use super::*;

/// #2134/#10985/#11057: tests for new-flow session-limit enforcement. These
/// drive the decision against real SessionTable counts, including default
/// source caps, overrides, and per-zone isolation.
#[cfg(test)]
mod new_flow_session_limit_tests {
    use super::*;
    use crate::screen::{ScreenProfile, ScreenState};
    use crate::session::{DEFAULT_MAX_SESSIONS_PER_SOURCE, SessionMetadata, SessionOrigin};
    use crate::test_zone_ids::{TEST_DMZ_ZONE_ID, TEST_LAN_ZONE_ID, TEST_TRUST_ZONE_ID};
    use std::net::{IpAddr, Ipv4Addr};

    fn forwarding_with_limit(zone: &str, src_limit: u32, dst_limit: u32) -> ForwardingState {
        let mut fw = ForwardingState::default();
        let mut profile = ScreenProfile::default();
        profile.session_limit_src = src_limit;
        profile.session_limit_dst = dst_limit;
        fw.screen_profiles.insert(zone.to_string(), profile);
        fw
    }

    fn counted_key(src: IpAddr, dst: IpAddr, src_port: u16) -> crate::session::SessionKey {
        crate::session::SessionKey {
            addr_family: 2,
            protocol: crate::ip_proto::PROTO_TCP,
            src_ip: src,
            dst_ip: dst,
            src_port,
            dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
        }
    }

    fn meta(ingress_zone: u32) -> SessionMetadata {
        SessionMetadata {
            ingress_zone,
            egress_zone: 2,
            ingress_zone_check: 0,
            egress_zone_check: 0,
            ingress_ifindex: 0,
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
        }
    }

    fn decision() -> crate::session::SessionDecision {
        crate::session::SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 12,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
                neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
                src_mac: None,
                tx_vlan_id: 0,
                source_ifindex: 0,
                route_mtu: 0,
                transport_route_mtu: 0,
            },
            nat: crate::nat::NatDecision::default(),
            install_table_domain: 0,
            install_table_check: 0,
        }
    }

    /// Install `n` distinct counted forward flows (distinct src ports) for
    /// the same (src, dst). `port_base` lets callers add MORE without
    /// re-installing already-present keys (which would net via the
    /// idempotent pre-clear).
    fn install_n(
        table: &mut SessionTable,
        ingress_zone: u32,
        src: IpAddr,
        dst: IpAddr,
        port_base: u16,
        n: u32,
    ) {
        for i in 0..n {
            assert!(table.install_with_protocol_with_origin(
                counted_key(src, dst, port_base + i as u16),
                decision(),
                meta(ingress_zone),
                SessionOrigin::ForwardFlow,
                1_000_000_000,
                crate::ip_proto::PROTO_TCP,
                0x10,
            ));
        }
    }

    #[test]
    fn under_limit_passes_at_and_over_limit_drops_src() {
        let fw = forwarding_with_limit("untrust", 3, 0);
        let mut table = SessionTable::new();
        table.set_session_limit_active(true);
        let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50));
        let dst = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));

        // 0 sessions: under limit -> pass (None).
        assert_eq!(
            new_flow_session_limit_drop(&fw, &table, "untrust", TEST_LAN_ZONE_ID, src, dst),
            None
        );
        // 2 sessions (under 3): still pass.
        install_n(&mut table, TEST_LAN_ZONE_ID, src, dst, 40000, 2);
        assert_eq!(table.session_limit_src_count(TEST_LAN_ZONE_ID, src), 2);
        assert_eq!(
            new_flow_session_limit_drop(&fw, &table, "untrust", TEST_LAN_ZONE_ID, src, dst),
            None
        );
        // 3 sessions (== limit): the next new flow MUST drop.
        install_n(&mut table, TEST_LAN_ZONE_ID, src, dst, 40002, 1); // distinct port -> count 3
        assert_eq!(table.session_limit_src_count(TEST_LAN_ZONE_ID, src), 3);
        assert_eq!(
            new_flow_session_limit_drop(&fw, &table, "untrust", TEST_LAN_ZONE_ID, src, dst),
            Some("session-limit-src"),
            "at/over the limit, a new flow must be dropped"
        );
    }

    #[test]
    fn over_limit_drops_dst() {
        let fw = forwarding_with_limit("untrust", 0, 2);
        let mut table = SessionTable::new();
        table.set_session_limit_active(true);
        let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 51));
        let dst = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));
        install_n(&mut table, TEST_LAN_ZONE_ID, src, dst, 40000, 2);
        assert_eq!(table.session_limit_dst_count(TEST_LAN_ZONE_ID, dst), 2);
        assert_eq!(
            new_flow_session_limit_drop(&fw, &table, "untrust", TEST_LAN_ZONE_ID, src, dst),
            Some("session-limit-dst")
        );
    }

    #[test]
    fn default_session_limit_source_quota_caps_one_source_without_blocking_others() {
        let fw = ForwardingState::default();
        let mut table = SessionTable::new();
        // Mirrors worker startup with an empty screen-profile snapshot.
        let no_profile_snapshot = ScreenState::new();
        table.set_session_limit_active(no_profile_snapshot.any_session_limit_dst_configured());
        let attacker = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 52));
        let other = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 53));
        let dst = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 3));

        install_n(
            &mut table,
            TEST_LAN_ZONE_ID,
            attacker,
            dst,
            40000,
            DEFAULT_MAX_SESSIONS_PER_SOURCE,
        );
        assert_eq!(
            table.session_limit_src_count(TEST_LAN_ZONE_ID, attacker),
            DEFAULT_MAX_SESSIONS_PER_SOURCE
        );
        assert_eq!(
            new_flow_session_limit_drop(
                &fw,
                &table,
                "unconfigured",
                TEST_LAN_ZONE_ID,
                attacker,
                dst
            ),
            Some("session-limit-src"),
            "default source quota applies without a screen profile"
        );
        let zero_limit_fw = forwarding_with_limit("unconfigured", 0, 0);
        assert_eq!(
            new_flow_session_limit_drop(
                &zero_limit_fw,
                &table,
                "unconfigured",
                TEST_LAN_ZONE_ID,
                attacker,
                dst
            ),
            Some("session-limit-src"),
            "zero source limit selects the default rather than disabling protection"
        );

        install_n(&mut table, TEST_DMZ_ZONE_ID, attacker, dst, 50000, 1);
        assert_eq!(table.session_limit_src_count(TEST_DMZ_ZONE_ID, attacker), 1);
        assert_eq!(
            new_flow_session_limit_drop(&fw, &table, "other-zone", TEST_DMZ_ZONE_ID, attacker, dst),
            None,
            "the default source quota is independently enforced per ingress zone"
        );
        assert_eq!(
            new_flow_session_limit_drop(&fw, &table, "unconfigured", TEST_LAN_ZONE_ID, other, dst),
            None,
            "one source reaching its quota must not block another source"
        );
    }

    #[test]
    fn read_only_check_never_creates_phantom_entry() {
        // #2128: checking an IP that never installed a session must not
        // populate the count maps.
        let fw = forwarding_with_limit("untrust", 5, 5);
        let table = SessionTable::new();
        let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 53));
        let dst = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4));
        for _ in 0..1000 {
            assert_eq!(
                new_flow_session_limit_drop(&fw, &table, "untrust", TEST_LAN_ZONE_ID, src, dst),
                None
            );
        }
        assert_eq!(table.session_limit_src_map_len(), 0);
        assert_eq!(table.session_limit_dst_map_len(), 0);
    }
    #[test]
    fn session_limit_counts_and_thresholds_are_isolated_per_zone_10985() {
        let fw = forwarding_with_limit("dmz", 2, 0);
        let mut table = SessionTable::new();
        let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 54));
        let dst = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5));

        // Source accounting is always active for the default quota; enabling
        // the optional destination counter must not change its zone scope.
        install_n(&mut table, TEST_TRUST_ZONE_ID, src, dst, 41000, 10);
        assert_eq!(table.session_limit_src_count(TEST_TRUST_ZONE_ID, src), 10);
        table.set_session_limit_active(true);
        assert_eq!(table.session_limit_src_count(TEST_TRUST_ZONE_ID, src), 10);
        assert_eq!(table.session_limit_src_count(TEST_DMZ_ZONE_ID, src), 0);
        assert_eq!(table.session_limit_dst_count(TEST_TRUST_ZONE_ID, dst), 10);
        assert_eq!(table.session_limit_dst_count(TEST_DMZ_ZONE_ID, dst), 0);
        assert_eq!(
            new_flow_session_limit_drop(&fw, &table, "dmz", TEST_DMZ_ZONE_ID, src, dst),
            None,
            "trust sessions do not consume dmz's session allowance"
        );

        // A dmz session consumes only dmz's own allowance; the next flow is
        // admitted while below the threshold, and the one at the threshold drops.
        install_n(&mut table, TEST_DMZ_ZONE_ID, src, dst, 42000, 1);
        assert_eq!(table.session_limit_src_count(TEST_DMZ_ZONE_ID, src), 1);
        assert_eq!(table.session_limit_src_count(TEST_TRUST_ZONE_ID, src), 10);
        assert_eq!(table.session_limit_dst_count(TEST_DMZ_ZONE_ID, dst), 1);
        assert_eq!(
            new_flow_session_limit_drop(&fw, &table, "dmz", TEST_DMZ_ZONE_ID, src, dst),
            None
        );
        install_n(&mut table, TEST_DMZ_ZONE_ID, src, dst, 42001, 1);
        assert_eq!(table.session_limit_src_count(TEST_DMZ_ZONE_ID, src), 2);
        assert_eq!(table.session_limit_dst_count(TEST_DMZ_ZONE_ID, dst), 2);
        assert_eq!(
            new_flow_session_limit_drop(&fw, &table, "dmz", TEST_DMZ_ZONE_ID, src, dst),
            Some("session-limit-src")
        );
    }
    #[test]
    fn transient_seeds_consume_per_source_session_quota_12179() {
        let fw = forwarding_with_limit("untrust", 10, 0);
        let now = 1_000_000_000u64;

        for origin in [
            SessionOrigin::MissingNeighborSeed,
            SessionOrigin::FabricPuntSeed,
        ] {
            let mut table = SessionTable::new();
            let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 121));
            let mut pending_decision = decision();
            pending_decision.resolution.neighbor_mac = None;
            if origin == SessionOrigin::FabricPuntSeed {
                pending_decision.resolution.disposition = ForwardingDisposition::FabricRedirect;
            }

            // Every distinct destination tuple resolves through the same
            // unresolved next hop. The first ten seeds fit; the eleventh
            // new-flow check must see those live entries and reject.
            for attempt in 0..=10u16 {
                let dst = IpAddr::V4(Ipv4Addr::new(
                    198,
                    51,
                    100,
                    u8::try_from(attempt + 1).expect("test destination octet"),
                ));
                let verdict =
                    new_flow_session_limit_drop(&fw, &table, "untrust", TEST_LAN_ZONE_ID, src, dst);
                if attempt == 10 {
                    assert_eq!(
                        verdict,
                        Some("session-limit-src"),
                        "{origin:?}: the eleventh pending seed must be rejected"
                    );
                    break;
                }
                assert_eq!(
                    verdict, None,
                    "{origin:?}: pending seed {attempt} should fit below the quota"
                );
                assert!(table.install_with_protocol_with_origin(
                    counted_key(src, dst, 40_000 + attempt),
                    pending_decision.clone(),
                    meta(TEST_LAN_ZONE_ID),
                    origin,
                    now,
                    crate::ip_proto::PROTO_TCP,
                    0x10,
                ));
                assert_eq!(
                    table.session_limit_src_count(TEST_LAN_ZONE_ID, src),
                    u32::from(attempt + 1),
                    "{origin:?}: each live seed must consume one source-quota slot"
                );
            }
            assert_eq!(table.len(), 10);
        }
    }
}

/// #4400/#10270/#10703: TCP SYN-selector behavior on the session-MISS install
/// path. The default and strict modes require SYN; explicit no-syn-check
/// admits non-closing mid-stream transit packets while bare RST/FIN still
/// drop. These tests drive the extracted predicate and guarded install against
/// a real `SessionTable` (the poll loop body is un-callable).
/// RED on revert: the default non-SYN miss and explicit opt-out assertions
/// observe the opposite session-creation outcomes if the policy is lost.
#[cfg(test)]
mod tcp_syn_check_tests {
    use super::*;
    use crate::ip_proto::{PROTO_TCP, PROTO_UDP};
    use crate::session::{SessionDecision, SessionKey, SessionMetadata, SessionOrigin};
    use crate::tcp_flags::{TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN};
    use std::net::{IpAddr, Ipv4Addr};

    fn tcp_key(src_port: u16) -> SessionKey {
        SessionKey {
            addr_family: 2,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
            src_port,
            dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
        }
    }

    fn fwd_meta() -> SessionMetadata {
        SessionMetadata {
            ingress_zone: 1,
            egress_zone: 2,
            ingress_zone_check: 0,
            egress_zone_check: 0,
            ingress_ifindex: 0,
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
        }
    }

    fn fwd_decision() -> SessionDecision {
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 12,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
                neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
                src_mac: None,
                tx_vlan_id: 0,
                source_ifindex: 0,
                route_mtu: 0,
                transport_route_mtu: 0,
            },
            nat: crate::nat::NatDecision::default(),
            install_table_domain: 0,
            install_table_check: 0,
        }
    }

    /// Model the transit session-MISS guard and install path with the default
    /// SYN-first policy.
    fn install_on_miss(table: &mut SessionTable, key: SessionKey, flags: u8) -> bool {
        install_on_miss_with_checks(table, key, flags, false, false)
    }

    fn install_on_miss_with_checks(
        table: &mut SessionTable,
        key: SessionKey,
        flags: u8,
        no_syn_check: bool,
        strict_syn_check: bool,
    ) -> bool {
        if strict_syn_check_drops_new_flow_with_payload(PROTO_TCP, flags, false, no_syn_check, strict_syn_check, 0) {
            return false;
        }
        table.install_with_protocol_with_origin(
            key,
            fwd_decision(),
            fwd_meta(),
            SessionOrigin::ForwardFlow,
            1_000_000_000,
            PROTO_TCP,
            flags,
        )
    }

    #[test]
    fn predicate_drops_every_non_syn_tcp_miss_by_default() {
        // With no opt-out configured, ACK/PSH/data and the original bare
        // RST/FIN subset remain fail-closed on a session miss.
        for flags in [
            TCP_ACK,
            TCP_ACK | TCP_PSH,
            0,
            TCP_FIN,
            TCP_RST,
            TCP_FIN | TCP_ACK,
            TCP_RST | TCP_ACK,
        ] {
            assert!(
                strict_syn_check_drops_new_flow_with_payload(PROTO_TCP, flags, false, false, false, 0),
                "non-SYN TCP flags 0x{flags:02x} must drop on a default-policy miss"
            );
        }
        // SYN-bearing packets remain eligible for a new session unless they
        // carry a closing flag; a SYN|ACK without FIN/RST supports asymmetric
        // routing, but closing SYNs must never seed an immediately-closing
        // session.
        assert!(!strict_syn_check_drops_new_flow_with_payload(
            PROTO_TCP, TCP_SYN, false, false, false, 0
        ));
        assert!(!strict_syn_check_drops_new_flow_with_payload(
            PROTO_TCP,
            TCP_SYN | TCP_ACK, false,
            false,
            false, 0
        ));
        for flags in [
            TCP_SYN | TCP_FIN,
            TCP_SYN | TCP_RST,
            TCP_SYN | TCP_ACK | TCP_FIN,
            TCP_SYN | TCP_ACK | TCP_RST,
        ] {
            assert!(
                strict_syn_check_drops_new_flow_with_payload(PROTO_TCP, flags, false, false, false, 0),
                "closing SYN flags 0x{flags:02x} must drop"
            );
        }
    }

    #[test]
    fn no_syn_check_admits_midstream_but_strict_and_closing_still_drop() {
        let mut table = SessionTable::new();
        for (port, flags) in [(40400, TCP_ACK), (40401, TCP_ACK | TCP_PSH)] {
            assert!(
                !strict_syn_check_drops_new_flow_with_payload(PROTO_TCP, flags, false, true, false, 0),
                "no-syn-check must admit non-closing TCP flags 0x{flags:02x}"
            );
            assert!(
                install_on_miss_with_checks(&mut table, tcp_key(port), flags, true, false),
                "an explicitly admitted mid-stream packet must seed a transit session"
            );
        }
        // The Junos opt-out does not weaken #4400's RST/FIN flood protection.
        for (port, flags) in [
            (40402, TCP_RST),
            (40403, TCP_FIN),
            (40404, TCP_RST | TCP_ACK),
            (40405, TCP_FIN | TCP_ACK),
        ] {
            assert!(strict_syn_check_drops_new_flow_with_payload(
                PROTO_TCP, flags, false, true, false, 0
            ));
            assert!(
                !install_on_miss_with_checks(&mut table, tcp_key(port), flags, true, false),
                "no-syn-check must not install closing flags 0x{flags:02x}"
            );
        }
        // Explicit strict mode has precedence if both knobs are configured.
        assert!(strict_syn_check_drops_new_flow_with_payload(
            PROTO_TCP,
            TCP_ACK | TCP_PSH, false,
            true,
            true, 0
        ));
        assert!(
            !install_on_miss_with_checks(&mut table, tcp_key(40406), TCP_ACK, true, true),
            "strict-syn-check must override no-syn-check at the install gate"
        );
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn tunnel_no_syn_check_admits_only_tunnel_midstream_15753() {
        // Tunnel ACK admitted only when is_tunnel && knob set.
        assert!(!strict_syn_check_drops_new_flow_tunnel_with_payload(PROTO_TCP, TCP_ACK, false, false, false, true, true, 0));
        assert!(strict_syn_check_drops_new_flow_tunnel_with_payload(PROTO_TCP, TCP_ACK, false, false, false, true, false, 0), "non-tunnel must still drop");
        assert!(strict_syn_check_drops_new_flow_tunnel_with_payload(PROTO_TCP, TCP_ACK, false, false, false, false, true, 0), "tunnel without knob drops");
        assert!(strict_syn_check_drops_new_flow_tunnel_with_payload(PROTO_TCP, TCP_ACK, false, false, true, true, true, 0), "strict overrides tunnel opt-out");
        assert!(strict_syn_check_drops_new_flow_tunnel_with_payload(PROTO_TCP, TCP_RST, false, false, false, true, true, 0), "closing tunnel still drops");
    }

    #[test]
    fn rst_seq_validation_in_window_vs_blind_15753() {
        use crate::session::SeqVerdict;
        let mut table = SessionTable::new();
        let key = tcp_key(40500);
        assert!(table.install_with_protocol_with_origin(key.clone(), fwd_decision(), fwd_meta(), SessionOrigin::ForwardFlow, 1_000_000_000, PROTO_TCP, TCP_SYN));
        // SYN seq=1000, window 4096 -> rcv_nxt=1001
        table.note_tcp_seq(&key, 1000, 0, 4096, 0, TCP_SYN, 0);
        // data seq 1001 len 100 -> nxt 1101
        table.note_tcp_seq(&key, 1001, 0, 4096, 100, TCP_ACK, 0);
        // #16040 fold: no companion ACK observed yet, so the RST
        // verdict is Unknown (admitted), not exact-vs-send-end.
        assert_eq!(table.tcp_closing_seq_verdict(&key, 1101, TCP_RST), SeqVerdict::Unknown, "no endpoint ACK observed yet (#16040 fold)");
        // Single-entry table: no companion ACK is observable here, so
        // RST stays Unknown; paired-table endpoint-exact coverage
        // lives in session::tcp_seq_15753_tests
        // (rst_requires_exact_seq_16040,
        // rst_exact_uses_endpoint_rcv_nxt_not_send_end_16040).
        assert_eq!(table.tcp_closing_seq_verdict(&key, 1050, TCP_RST), SeqVerdict::Unknown, "RST stays Unknown until endpoint ACK observed");
        assert_eq!(table.tcp_closing_seq_verdict(&key, 1050, TCP_FIN), SeqVerdict::Valid, "in-window FIN seq retained valid");
        assert_eq!(table.tcp_closing_seq_verdict(&key, 99999, TCP_FIN), SeqVerdict::Invalid);
    }

    #[test]
    fn bare_rst_fin_on_miss_installs_no_session() {
        let mut table = SessionTable::new();
        // RED on revert: without the guard each of these seeds an immediately-
        // closing session; with it, nothing is installed.
        assert!(!install_on_miss(&mut table, tcp_key(40000), TCP_RST));
        assert!(!install_on_miss(&mut table, tcp_key(40001), TCP_FIN));
        assert!(!install_on_miss(
            &mut table,
            tcp_key(40002),
            TCP_FIN | TCP_ACK
        ));
        assert!(!install_on_miss(
            &mut table,
            tcp_key(40003),
            TCP_RST | TCP_ACK
        ));
        assert_eq!(
            table.len(),
            0,
            "a bare RST/FIN session-miss must not seed a session"
        );
    }

    #[test]
    fn closing_syn_misses_are_dropped_13941() {
        let mut table = SessionTable::new();
        // unaffected, while closing SYN first packets cannot seed state.
        let syn = tcp_key(40100);
        assert!(install_on_miss(&mut table, syn.clone(), TCP_SYN));
        assert!(
            table
                .lookup(&syn, 1_001_000_000, TCP_SYN | TCP_ACK)
                .is_some()
        );
        for (port, flags) in [
            (40101, TCP_SYN | TCP_FIN),
            (40102, TCP_SYN | TCP_RST),
            (40103, TCP_SYN | TCP_ACK | TCP_FIN),
            (40104, TCP_SYN | TCP_ACK | TCP_RST),
        ] {
            assert!(
                !install_on_miss(&mut table, tcp_key(port), flags),
                "closing SYN miss flags 0x{flags:02x} must not install a session"
            );
        }
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn expired_and_fresh_non_syn_bursts_drop_10270() {
        let mut table = SessionTable::new();
        let expired = tcp_key(40300);
        let now = 1_000_000_000u64;
        // Seed an established tuple directly (the equivalent of a confirmed
        // existing session), then advance beyond the default 1800 s idle window (#15127).
        assert!(table.install_with_protocol_with_origin(
            expired.clone(),
            fwd_decision(),
            fwd_meta(),
            SessionOrigin::ForwardFlow,
            now,
            PROTO_TCP,
            TCP_ACK,
        ));
        let _ = table.expire_stale_entries(now + 1_801_000_000_000);
        assert!(
            table.probe_with_origin_at(&expired, now + 1_801_000_000_000).is_none(),
            "expired tuple must be a session miss before the ACK/PSH burst"
        );
        let fresh = tcp_key(40301);
        let mut expired_transit = 0usize;
        let mut fresh_transit = 0usize;
        // Match the wire gate's 1000-frame probe floor. A reverted predicate
        // installs/replaces the tuple on every first miss and makes these counts
        // nonzero; the fixed path drops all 2000 frames.
        for _ in 0..1000 {
            expired_transit += usize::from(install_on_miss(
                &mut table,
                expired.clone(),
                TCP_ACK | TCP_PSH,
            ));
            fresh_transit += usize::from(install_on_miss(
                &mut table,
                fresh.clone(),
                TCP_ACK | TCP_PSH,
            ));
        }
        assert_eq!(expired_transit, 0, "expired ACK/PSH burst must not transit");
        assert_eq!(fresh_transit, 0, "fresh ACK/PSH burst must not transit");
        assert!(
            table.probe_with_origin_at(&expired, now + 1_801_000_000_000).is_none()
        );
        assert!(table.probe_with_origin_at(&fresh, now + 1_801_000_000_000).is_none());
    }

    #[test]
    fn established_and_ha_synced_non_syn_hits_are_unaffected_10270() {
        let mut table = SessionTable::new();
        let now = 1_000_000_000u64;
        let established = tcp_key(40302);
        assert!(table.install_with_protocol_with_origin(
            established.clone(),
            fwd_decision(),
            fwd_meta(),
            SessionOrigin::ForwardFlow,
            now,
            PROTO_TCP,
            TCP_ACK,
        ));
        assert!(
            table
                .lookup(&established, now + 1_000_000, TCP_ACK | TCP_PSH)
                .is_some(),
            "a confirmed existing session remains a normal hit"
        );

        let synced = tcp_key(40303);
        table.upsert_synced(
            synced.clone(),
            fwd_decision(),
            fwd_meta(),
            now,
            PROTO_TCP,
            TCP_ACK,
            false,
        );
        assert!(
            table
                .lookup(&synced, now + 2_000_000, TCP_ACK | TCP_PSH)
                .is_some(),
            "an HA-synced session remains a normal hit"
        );
    }

    #[test]
    fn rst_for_existing_session_is_unaffected() {
        // The strict SYN gate applies only to session misses. Existing-session
        // FIN/RST packets retain the teardown path; #10887 separately gates
        // ACK-less non-SYN, non-closing anomalies before hit lookup.
        let mut table = SessionTable::new();
        let key = tcp_key(40200);
        assert!(install_on_miss(&mut table, key.clone(), TCP_SYN));
        assert_eq!(table.len(), 1);
        assert!(table.install_with_protocol_with_origin(
            key,
            fwd_decision(),
            fwd_meta(),
            SessionOrigin::ForwardFlow,
            2_000_000_000,
            PROTO_TCP,
            TCP_RST,
        ));
        assert_eq!(
            table.len(),
            1,
            "a RST on an existing session tears it down in place, never dropped as a miss"
        );
    }

    // #10729 X2-F6 RED cell 4: the SYN gate never drops AH — effective
    // proto 51 is non-TCP under every knob combination, so a v6+AH
    // non-SYN is not strict-dropped as a TCP miss (and AH seeds no TCP
    // session: flowless packets carry no install key).
    #[test]
    fn ah_protocol_never_drops_at_syn_gate_10729() {
        for flags in [TCP_SYN, TCP_ACK, TCP_ACK | TCP_PSH, TCP_FIN, 0] {
            for (no_syn, strict) in [(false, false), (true, false), (false, true), (true, true)] {
                assert!(
                    !strict_syn_check_drops_new_flow_with_payload(
                        crate::ip_proto::PROTO_AH,
                        flags, false,
                        no_syn,
                        strict, 0
                    ),
                    "proto AH flags 0x{flags:02x} (no_syn={no_syn}, strict={strict}) must never drop"
                );
            }
        }
    }
}

/// #16007: flags-UNKNOWN fails closed in every admission mode.
#[cfg(test)]
mod tiny_frag_flags_unknown_tests_16007 {
    use super::super::session_admission::{
        strict_syn_check_drops_new_flow_with_payload, strict_syn_check_drops_new_flow_tunnel_with_payload,
    };
    use crate::ip_proto::PROTO_TCP;
    use crate::tcp_flags::{TCP_ACK, TCP_SYN};

    #[test]
    fn unknown_flags_drop_in_all_modes_16007() {
        for (no_syn, strict) in [(false, false), (true, false), (false, true), (true, true)] {
            assert!(
                strict_syn_check_drops_new_flow_with_payload(PROTO_TCP, 0, true, no_syn, strict, 0),
                "unknown flags must drop (no_syn={no_syn} strict={strict})"
            );
            assert!(
                strict_syn_check_drops_new_flow_tunnel_with_payload(PROTO_TCP, 0, true, no_syn, strict, true, true, 0),
                "unknown flags must drop even with tunnel opt-out"
            );
        }
        // Even a stamped SYN is not proven when unknown is set.
        assert!(strict_syn_check_drops_new_flow_with_payload(PROTO_TCP, TCP_SYN, true, true, false, 0));
        // Controls: known flags keep prior semantics.
        assert!(!strict_syn_check_drops_new_flow_with_payload(PROTO_TCP, TCP_SYN, false, false, false, 0));
        assert!(!strict_syn_check_drops_new_flow_with_payload(PROTO_TCP, TCP_ACK, false, true, false, 0));
        assert!(strict_syn_check_drops_new_flow_with_payload(PROTO_TCP, TCP_ACK, false, false, false, 0));
    }
}

/// #16479: Junos strict-syn-check payload gates. (a) SYN+payload drops
/// at the MISS gate only under strict; (b) data-bearing segments drop
/// on a HIT while a SYN-first handshake is incomplete, and forward
/// after the completing ACK (positive control).
#[cfg(test)]
mod strict_syn_16479_tests {
    use super::super::session_admission::{
        strict_syn_check_drops_new_flow_with_payload,
        strict_syn_check_drops_pre_handshake_data,
    };
    use crate::ip_proto::PROTO_TCP;
    use crate::tcp_flags::{TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN};

    #[test]
    fn syn_with_payload_drops_only_under_strict_16479() {
        // SYN + 100 bytes payload: dropped only with strict on.
        assert!(strict_syn_check_drops_new_flow_with_payload(
            PROTO_TCP,
            TCP_SYN,
            false,
            false,
            true,
            100
        ));
        assert!(strict_syn_check_drops_new_flow_with_payload(
            PROTO_TCP,
            TCP_SYN | TCP_PSH,
            false,
            false,
            true,
            100
        ));
        // Positive controls: same frame without strict, and bare SYN
        // under strict, are admitted.
        assert!(!strict_syn_check_drops_new_flow_with_payload(
            PROTO_TCP,
            TCP_SYN,
            false,
            false,
            false,
            100
        ));
        assert!(!strict_syn_check_drops_new_flow_with_payload(
            PROTO_TCP,
            TCP_SYN,
            false,
            true,
            false,
            100
        ));
        assert!(!strict_syn_check_drops_new_flow_with_payload(
            PROTO_TCP,
            TCP_SYN,
            false,
            false,
            true,
            0
        ));
        // SYN-ACK with payload under strict also drops; closing SYN
        // drops regardless of payload (prior arm, unchanged).
        assert!(strict_syn_check_drops_new_flow_with_payload(
            PROTO_TCP,
            TCP_SYN | TCP_ACK,
            false,
            false,
            true,
            100
        ));
        assert!(strict_syn_check_drops_new_flow_with_payload(
            PROTO_TCP,
            TCP_SYN | TCP_FIN,
            false,
            false,
            false,
            0
        ));
    }

    #[test]
    fn pre_handshake_data_drops_and_completed_forwards_16479() {
        let data = TCP_ACK | TCP_PSH;
        // ACK+data BEFORE the SYN-ACK (OPENING: !established): drop.
        assert!(strict_syn_check_drops_pre_handshake_data(
            true, data, 100, false, false, false, false
        ));
        // ACK+data AFTER the SYN-ACK, before the final ACK (pending): drop.
        // This is also the completing ACK+data shape — pre-completion
        // state, so it drops exactly as Junos prescribes.
        assert!(strict_syn_check_drops_pre_handshake_data(
            true, data, 100, true, true, false, false
        ));
        // SYN-ACK-first pending: drop.
        assert!(strict_syn_check_drops_pre_handshake_data(
            true, data, 100, false, true, true, false
        ));
        // POSITIVE CONTROL: data AFTER the handshake ACK forwards.
        assert!(!strict_syn_check_drops_pre_handshake_data(
            true, data, 100, true, false, false, false
        ));
        // Knob off: the same pending data forwards (default unchanged).
        assert!(!strict_syn_check_drops_pre_handshake_data(
            false, data, 100, true, true, false, false
        ));
        // Payload-free segments never drop (SYN-ACK, completing ACK pass).
        assert!(!strict_syn_check_drops_pre_handshake_data(
            true,
            TCP_SYN | TCP_ACK,
            0,
            false,
            false,
            false,
            false
        ));
        assert!(!strict_syn_check_drops_pre_handshake_data(
            true, TCP_ACK, 0, true, true, false, false
        ));
        // SYN retransmit with payload on the hit path is handshake
        // control here (the MISS gate owns SYN+payload drops).
        assert!(!strict_syn_check_drops_pre_handshake_data(
            true, TCP_SYN, 100, false, false, false, false
        ));
        // Closing traffic keeps teardown handling even with payload.
        assert!(!strict_syn_check_drops_pre_handshake_data(
            true,
            TCP_FIN | TCP_ACK | TCP_PSH,
            100,
            true,
            true,
            false,
            false
        ));
        assert!(!strict_syn_check_drops_pre_handshake_data(
            true,
            TCP_RST | TCP_ACK,
            100,
            true,
            true,
            false,
            false
        ));
        assert!(!strict_syn_check_drops_pre_handshake_data(
            true, data, 100, true, true, false, true
        ));
    }
}

#[cfg(test)]
mod persistent_pressure_shed_17683_tests {
    use super::*;
    use crate::nat::PersistentNatPermit;
    use crate::session::{SessionDecision, SessionKey, SessionMetadata};
    use std::net::{IpAddr, Ipv4Addr};

    fn forwarding_with_idle_persistent_leases() -> (ForwardingState, crate::nat::NatDecision) {
        let mut forwarding = ForwardingState::default();
        forwarding.source_nat_rules =
            crate::nat::parse_source_nat_rules(&[crate::SourceNATRuleSnapshot {
                name: "persistent-snat".to_string(),
                from_zone: "lan".to_string(),
                to_zone: "wan".to_string(),
                source_addresses: vec!["0.0.0.0/0".to_string()],
                pool_name: "persistent-pool".to_string(),
                pool_addresses: vec!["203.0.113.10".to_string()],
                port_low: 40000,
                port_high: 40010,
                persistent_nat: true,
                persistent_nat_permit_any_remote_host: true,
                persistent_nat_permit: "any-remote-host".to_string(),
                persistent_nat_inactivity_timeout: 1,
                ..crate::SourceNATRuleSnapshot::default()
            }]);

        let mut mint_scoped = |scope: u32, now_ns: u64| {
            let mut counter = None;
            let decision = match crate::nat::match_source_nat_result_for_tuple(
                &crate::nat::InterfaceNatAllocators::default(),
                &forwarding.source_nat_rules,
                &crate::nat::NatScopeCtx {
                    routing_domain: scope,
                    ..crate::nat::NatScopeCtx::default()
                },
                "lan",
                "wan",
                "10.0.1.100".parse().unwrap(),
                "8.8.8.8".parse().unwrap(),
                Some(crate::ip_proto::PROTO_TCP),
                12345,
                53,
                None,
                None,
                now_ns,
                false,
                false,
                crate::nat::NatHolder::Untracked,
                &mut counter,
            ) {
                crate::nat::SourceNatLookup::Matched(decision) => decision,
                other => panic!("fixture: outbound mint must match, got {other:?}"),
            };
            let outbound_key = SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: crate::ip_proto::PROTO_TCP,
                src_ip: "10.0.1.100".parse().unwrap(),
                dst_ip: "8.8.8.8".parse().unwrap(),
                src_port: 12345,
                dst_port: 53,
                discriminator: Default::default(),
                routing_domain: scope,
            };
            crate::nat::release_source_nat_allocation(
                &crate::nat::InterfaceNatAllocators::default(),
                &forwarding.source_nat_rules,
                &outbound_key,
                decision,
                false,
                now_ns + 1,
            );
            decision
        };
        let tenant_a = mint_scoped(7, 1_000_000_000);
        mint_scoped(0, 1_000_000_000);
        (forwarding, tenant_a)
    }

    fn inbound_flows(forwarding: &ForwardingState, scope: u32) -> Option<u32> {
        forwarding.source_nat_rules[0]
            .pool_allocator
            .debug_persistent_lease_for_flow(
                &crate::nat::SourceNatFlowKey {
                    protocol: crate::ip_proto::PROTO_TCP,
                    src_ip: "10.0.1.100".parse().unwrap(),
                    dst_ip: "8.8.8.8".parse().unwrap(),
                    src_port: 12345,
                    dst_port: 53,
                    routing_scope: scope,
                },
                PersistentNatPermit::AnyRemoteHost,
            )
            .map(|lease| lease.inbound_flows)
    }

    fn session_metadata() -> SessionMetadata {
        SessionMetadata {
            ingress_zone: 1,
            egress_zone: 2,
            ingress_zone_check: 0,
            egress_zone_check: 0,
            ingress_ifindex: 0,
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
        }
    }

    #[test]
    fn queue_full_delete_leaves_peer_inbound_hold_for_drop_sweep_17683() {
        let (forwarding, tenant_a_nat) = forwarding_with_idle_persistent_leases();
        let allocator = &forwarding.source_nat_rules[0].pool_allocator;
        let lease_key_a = crate::nat::PersistentSourceKey {
            protocol: crate::ip_proto::PROTO_TCP,
            src_ip: "10.0.1.100".parse().unwrap(),
            src_port: 12345,
            routing_scope: 7,
            remote: None,
        };
        let hold_a = allocator
            .acquire_persistent_inbound_with_hold(lease_key_a, 1_500_000_000)
            .expect("fixture must acquire its exact scope-7 lease hold");
        let hold_b = crate::nat::PersistentSourceKey {
            routing_scope: 0,
            ..hold_a.key
        };
        assert!(allocator.acquire_persistent_inbound(hold_a.key, 1_500_000_000));
        assert!(allocator.acquire_persistent_inbound(hold_b, 1_500_000_000));

        // This is an inbound DNAT+SNAT session: the packet arrived for the
        // scope-7 public lease in arrival domain 0, and rewrite_dst identifies
        // the private host that owns that lease.
        let inbound_nat = crate::nat::NatDecision {
            rewrite_src: Some("198.51.100.1".parse().unwrap()),
            rewrite_src_port: Some(50_000),
            rewrite_dst: Some("10.0.1.100".parse().unwrap()),
            rewrite_dst_port: Some(12_345),
            ..crate::nat::NatDecision::default()
        };
        let key = SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: crate::ip_proto::PROTO_TCP,
            src_ip: "8.8.8.8".parse().unwrap(),
            dst_ip: tenant_a_nat.rewrite_src.expect("fixture has public address"),
            src_port: 53,
            dst_port: tenant_a_nat
                .rewrite_src_port
                .expect("fixture has public port"),
            discriminator: Default::default(),
            routing_domain: 0,
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 12,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
                neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
                src_mac: None,
                tx_vlan_id: 0,
                source_ifindex: 0,
                route_mtu: 0,
                transport_route_mtu: 0,
            },
            nat: inbound_nat,
            install_table_domain: 0,
            install_table_check: 0,
        };
        let mut worker_sessions = SessionTable::new();
        assert!(worker_sessions.upsert_synced_with_origin(
            crate::session::SessionInstall {
                key: key.clone(),
                decision,
                metadata: session_metadata(),
                source_nat_static: None,
                origin: crate::session::SessionOrigin::SyncImport,
                now_ns: 2_000_000_000,
                protocol: crate::ip_proto::PROTO_TCP,
                tcp_flags: crate::tcp_flags::TCP_ACK,
                session_id: 0,
                tcp_close_class: 0,
                tcp_handshake_state: 0,
                persistent_lease_hold: Some(hold_a),
                fwd_packets: 0,
                rev_packets: 0,
            },
            false,
        ));

        let queue = std::sync::Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new()));
        {
            let mut pending = queue.lock().unwrap();
            for _ in 0..crate::afxdp::worker_queue::MAX_PENDING_WORKER_COMMANDS {
                pending.push_back(crate::afxdp::WorkerCommand::DeleteSynced(key.clone()));
            }
        }
        let peers = vec![queue.clone()];
        let mut worker_commands_by_id = std::collections::BTreeMap::new();
        worker_commands_by_id.insert(42, queue.clone());

        let _outcome = crate::afxdp::session_glue::replicate_session_delete_repairing(
            &peers,
            &worker_commands_by_id,
            &forwarding,
            &key,
            inbound_nat,
            false,
            2_000_000_000,
        );
        assert_eq!(
            queue.lock().unwrap().len(),
            crate::afxdp::worker_queue::MAX_PENDING_WORKER_COMMANDS,
            "the queue-full fixture must refuse the delete"
        );
        assert_eq!(
            (inbound_flows(&forwarding, 7), inbound_flows(&forwarding, 0)),
            (Some(2), Some(1)),
            "queue-full repair must leave the worker's recorded scope-7 hold and the scope-0 control untouched"
        );

        // The epoch-driven production sweep removes the actual peer-synced
        // worker-table entry and releases that entry's recorded hold once.
        let shared_sessions = std::sync::Arc::new(std::sync::Mutex::new(FastMap::default()));
        let mut sweep = crate::afxdp::session_glue::DeleteDropSweep::default();
        sweep.arm();
        let mut evicted = Vec::new();
        assert_eq!(
            sweep.step_with_nat(
                &mut worker_sessions,
                &shared_sessions,
                SteeringMap::unshared_for_test(-1),
                &forwarding,
                2_000_000_001,
                42,
                &mut evicted,
            ),
            1,
            "delete-drop sweep must remove the stale peer entry"
        );
        assert_eq!(evicted, vec![key.clone()]);
        assert!(worker_sessions.probe_with_origin(&key).is_none());
        assert_eq!(
            (inbound_flows(&forwarding, 7), inbound_flows(&forwarding, 0)),
            (Some(1), Some(1)),
            "the actual worker sweep releases one scope-7 reference and leaves both other controls"
        );
    }

    #[test]
    fn pressure_shed_releases_recorded_cross_domain_hold_once_17683() {
        let (forwarding, tenant_a_nat) = forwarding_with_idle_persistent_leases();
        let allocator = &forwarding.source_nat_rules[0].pool_allocator;
        let lease_key_a = crate::nat::PersistentSourceKey {
            protocol: crate::ip_proto::PROTO_TCP,
            src_ip: "10.0.1.100".parse().unwrap(),
            src_port: 12345,
            routing_scope: 7,
            remote: None,
        };
        let hold_a = allocator
            .acquire_persistent_inbound_with_hold(lease_key_a, 1_500_000_000)
            .expect("fixture must acquire its exact scope-7 lease hold");
        let hold_b = crate::nat::PersistentSourceKey {
            routing_scope: 0,
            ..hold_a.key
        };

        // Two sessions share A's lease, while an overlapping tenant owns B's
        // same internal tuple in the arrival domain. Shedding one A session
        // must release exactly its recorded hold and leave both controls.
        assert!(allocator.acquire_persistent_inbound(hold_a.key, 1_500_000_000));
        assert!(allocator.acquire_persistent_inbound(hold_b, 1_500_000_000));
        assert_eq!(inbound_flows(&forwarding, 7), Some(2));
        assert_eq!(inbound_flows(&forwarding, 0), Some(1));

        let nat = crate::nat::NatDecision {
            rewrite_dst: Some("10.0.1.100".parse().unwrap()),
            rewrite_dst_port: Some(12345),
            ..crate::nat::NatDecision::default()
        };
        let key = SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: crate::ip_proto::PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            dst_ip: tenant_a_nat.rewrite_src.expect("fixture has public address"),
            src_port: 53,
            dst_port: tenant_a_nat
                .rewrite_src_port
                .expect("fixture has public port"),
            discriminator: Default::default(),
            routing_domain: 0,
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 12,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
                neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
                src_mac: None,
                tx_vlan_id: 0,
                source_ifindex: 0,
                route_mtu: 0,
                transport_route_mtu: 0,
            },
            nat,
            install_table_domain: 0,
            install_table_check: 0,
        };
        let now_ns = 2_000_000_000;
        let mut sessions = SessionTable::new();
        sessions.set_max_sessions_for_test(1);
        assert!(sessions.install_with_protocol(
            key.clone(),
            decision,
            session_metadata(),
            now_ns,
            crate::ip_proto::PROTO_TCP,
            crate::tcp_flags::TCP_SYN,
        ));
        sessions.set_persistent_lease_hold(&key, Some(hold_a));
        let (admitted, sheds) = sessions.can_admit_new_flow(
            1,
            crate::ip_proto::PROTO_TCP,
            crate::tcp_flags::TCP_SYN,
        );
        assert!(admitted);
        assert_eq!(sheds.len(), 1);
        let recorded_shed_hold = sheds
            .iter()
            .next()
            .and_then(|shed| shed.persistent_lease_hold);

        let dnat_fds = crate::afxdp::checksum::DnatTableFds::default();
        let shared_sessions = std::sync::Arc::new(std::sync::Mutex::new(FastMap::default()));
        let shared_nat_sessions = std::sync::Arc::new(std::sync::Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions =
            std::sync::Arc::new(std::sync::Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        let peer_worker_commands = Vec::new();
        let worker_commands_by_id = crate::afxdp::types::empty_worker_commands_by_id();
        assert!(teardown_pressure_shed_victims(
            &mut sessions,
            sheds,
            ShedTeardownCtx {
                forwarding: &forwarding,
                session_map: SteeringMap::unshared_for_test(-1),
                conntrack_v4_fd: -1,
                conntrack_v6_fd: -1,
                dnat_fds: &dnat_fds,
                worker_id: 0,
                peer_worker_commands: &peer_worker_commands,
                worker_commands_by_id,
                shared_sessions: &shared_sessions,
                shared_nat_sessions: &shared_nat_sessions,
                shared_forward_wire_sessions: &shared_forward_wire_sessions,
                shared_owner_rg_indexes: &shared_owner_rg_indexes,
                now_ns,
            },
            &mut |_| {},
        ));

        assert_eq!(
            (inbound_flows(&forwarding, 7), inbound_flows(&forwarding, 0)),
            (Some(1), Some(1)),
            "teardown releases exactly one scope-7 hold and leaves the overlapping arrival-domain tenant untouched"
        );
        assert_eq!(
            recorded_shed_hold,
            Some(hold_a),
            "pressure-shed intent retains the exact allocator and persistent key"
        );
        crate::nat::release_recorded_persistent_inbound(
            &forwarding.source_nat_rules,
            Some(hold_a),
            2_000_000_001,
        );
        assert_eq!(inbound_flows(&forwarding, 7), Some(0));
        assert_eq!(inbound_flows(&forwarding, 0), Some(1));
    }
}
