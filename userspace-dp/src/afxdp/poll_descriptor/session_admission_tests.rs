use super::*;

/// #2134: unit tests for the new-flow session-limit enforcement decision.
/// These drive `new_flow_session_limit_drop` directly against a real
/// `SessionTable` count, so they FAIL if the check is reverted to a
/// never-drop no-op (the #2134 bug) — the under/at/over-limit boundary
/// and the unconfigured-zone short-circuit are all pinned.
#[cfg(test)]
mod new_flow_session_limit_tests {
    use super::*;
    use crate::screen::ScreenProfile;
    use crate::session::{SessionMetadata, SessionOrigin};
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

    fn meta() -> SessionMetadata {
        SessionMetadata {
            ingress_zone: 1,
            egress_zone: 2,
            ingress_zone_check: 0,
            egress_zone_check: 0,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
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
        }
    }

    fn decision() -> crate::session::SessionDecision {
        crate::session::SessionDecision { resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
            src_mac: None,
            tx_vlan_id: 0,
        }, nat: crate::nat::NatDecision::default(), install_table_domain: 0, install_table_check: 0 }
    }

    /// Install `n` distinct counted forward flows (distinct src ports) for
    /// the same (src, dst). `port_base` lets callers add MORE without
    /// re-installing already-present keys (which would net via the
    /// idempotent pre-clear).
    fn install_n(table: &mut SessionTable, src: IpAddr, dst: IpAddr, port_base: u16, n: u32) {
        for i in 0..n {
            assert!(table.install_with_protocol_with_origin(
                counted_key(src, dst, port_base + i as u16),
                decision(),
                meta(),
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
            new_flow_session_limit_drop(&fw, &table, "untrust", src, dst),
            None
        );
        // 2 sessions (under 3): still pass.
        install_n(&mut table, src, dst, 40000, 2);
        assert_eq!(table.session_limit_src_count(src), 2);
        assert_eq!(
            new_flow_session_limit_drop(&fw, &table, "untrust", src, dst),
            None
        );
        // 3 sessions (== limit): the next new flow MUST drop.
        install_n(&mut table, src, dst, 40002, 1); // distinct port -> count 3
        assert_eq!(table.session_limit_src_count(src), 3);
        assert_eq!(
            new_flow_session_limit_drop(&fw, &table, "untrust", src, dst),
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
        install_n(&mut table, src, dst, 40000, 2);
        assert_eq!(table.session_limit_dst_count(dst), 2);
        assert_eq!(
            new_flow_session_limit_drop(&fw, &table, "untrust", src, dst),
            Some("session-limit-dst")
        );
    }

    #[test]
    fn unconfigured_zone_never_drops() {
        // Zone present but no limit configured.
        let fw = forwarding_with_limit("untrust", 0, 0);
        let mut table = SessionTable::new();
        table.set_session_limit_active(true);
        let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 52));
        let dst = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 3));
        install_n(&mut table, src, dst, 40000, 50);
        assert_eq!(
            new_flow_session_limit_drop(&fw, &table, "untrust", src, dst),
            None,
            "no limit configured -> never drop"
        );
        // Unknown zone name -> short-circuit None.
        assert_eq!(
            new_flow_session_limit_drop(&fw, &table, "nonexistent", src, dst),
            None
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
                new_flow_session_limit_drop(&fw, &table, "untrust", src, dst),
                None
            );
        }
        assert_eq!(table.session_limit_src_map_len(), 0);
        assert_eq!(table.session_limit_dst_map_len(), 0);
    }
}

/// #4400/#10270: strict-syn-check drop on the TCP session-MISS install path.
/// A TCP packet that misses the session table can only create a new transit
/// session when it carries SYN. Non-SYN ACK/PSH/data, including the original
/// bare RST/FIN subset, is either a late segment for an already-GC'd session
/// or a midstream tuple this firewall never observed. These drive the
/// extracted decision predicate and model the guarded install directly
/// against a real `SessionTable` (the poll loop body is un-callable).
/// RED on revert: without the guard a non-SYN miss installs a session, so the
/// expired/fresh burst tests observe transit/session creation.
#[cfg(test)]
mod strict_syn_check_tests {
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
        }
    }

    fn fwd_decision() -> SessionDecision {
        SessionDecision { resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
            src_mac: None,
            tx_vlan_id: 0,
        }, nat: crate::nat::NatDecision::default(), install_table_domain: 0, install_table_check: 0 }
    }

    /// Model the poll_descriptor session-MISS guard for a ForwardCandidate
    /// transit new flow: only SYN-bearing TCP packets are installed. Returns
    /// true iff a session was installed. Byte-for-byte the same predicate
    /// gate the production path applies before
    /// `install_with_protocol_with_origin`.
    fn install_on_miss(table: &mut SessionTable, key: SessionKey, flags: u8) -> bool {
        if strict_syn_check_drops_new_flow(PROTO_TCP, flags) {
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
    fn predicate_drops_every_non_syn_tcp_miss() {
        // The complete non-SYN family is fail-closed on a session miss,
        // including ACK/PSH bursts and the original bare RST/FIN subset.
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
                strict_syn_check_drops_new_flow(PROTO_TCP, flags),
                "non-SYN TCP flags 0x{flags:02x} must drop on a miss"
            );
        }
        // SYN-bearing packets remain eligible for a new session, including
        // asymmetric-path SYN-ACK and the existing tcp-syn-fin screen case.
        assert!(!strict_syn_check_drops_new_flow(PROTO_TCP, TCP_SYN));
        assert!(!strict_syn_check_drops_new_flow(PROTO_TCP, TCP_SYN | TCP_ACK));
        assert!(!strict_syn_check_drops_new_flow(PROTO_TCP, TCP_SYN | TCP_FIN));
        // Non-TCP traffic is never gated by this TCP-only predicate.
        assert!(!strict_syn_check_drops_new_flow(PROTO_UDP, TCP_RST));
        assert!(!strict_syn_check_drops_new_flow(PROTO_UDP, TCP_FIN));
    }

    #[test]
    fn bare_rst_fin_on_miss_installs_no_session() {
        let mut table = SessionTable::new();
        // RED on revert: without the guard each of these seeds an immediately-
        // closing session; with it, nothing is installed.
        assert!(!install_on_miss(&mut table, tcp_key(40000), TCP_RST));
        assert!(!install_on_miss(&mut table, tcp_key(40001), TCP_FIN));
        assert!(!install_on_miss(&mut table, tcp_key(40002), TCP_FIN | TCP_ACK));
        assert!(!install_on_miss(&mut table, tcp_key(40003), TCP_RST | TCP_ACK));
        assert_eq!(
            table.len(),
            0,
            "a bare RST/FIN session-miss must not seed a session"
        );
    }

    #[test]
    fn syn_only_first_packet_installs_on_miss() {
        let mut table = SessionTable::new();
        // A legitimate connection open (bare SYN) still installs.
        assert!(install_on_miss(&mut table, tcp_key(40100), TCP_SYN));
        // Asymmetric routing: a SYN-ACK on miss remains eligible.
        assert!(install_on_miss(&mut table, tcp_key(40101), TCP_SYN | TCP_ACK));
        // A bare ACK / ACK+PSH first packet is a session-less midstream
        // attempt and is dropped rather than opening a new transit session.
        assert!(!install_on_miss(
            &mut table,
            tcp_key(40102),
            TCP_ACK | TCP_PSH
        ));
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn expired_and_fresh_non_syn_bursts_drop_10270() {
        let mut table = SessionTable::new();
        let expired = tcp_key(40300);
        let now = 1_000_000_000u64;
        // Seed an established tuple directly (the equivalent of a confirmed
        // existing session), then advance beyond the default 300 s idle window.
        assert!(table.install_with_protocol_with_origin(
            expired.clone(),
            fwd_decision(),
            fwd_meta(),
            SessionOrigin::ForwardFlow,
            now,
            PROTO_TCP,
            TCP_ACK,
        ));
        let _ = table.expire_stale_entries(now + 301_000_000_000);
        assert!(
            table.probe_with_origin_at(&expired, now + 301_000_000_000).is_none(),
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
            table.probe_with_origin_at(&expired, now + 301_000_000_000).is_none()
        );
        assert!(table.probe_with_origin_at(&fresh, now + 301_000_000_000).is_none());
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
        // The guard gates ONLY the session-MISS install path. A RST for a flow
        // that already has a session is a session HIT (normal teardown) and
        // never consults the guard. Model the established in-place teardown
        // refresh by installing directly (as the hit path does), NOT through
        // `install_on_miss`.
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
}
