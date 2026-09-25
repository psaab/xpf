use super::*;

#[cfg(test)]
mod ipv6_ext_header_drop_tests {
    // #4743: the over-limit IPv6 ext-header fail-closed drop gate and its
    // counter. RED-on-revert: reverting the terminal `true` in
    // `ipv6_ext_chain_over_limit` (frame/inspect.rs) OR the increment in
    // `ipv6_ext_header_over_limit_drop` makes these fail.
    use super::*;

    /// eth(IPv6) + IPv6 base header (version 6, `next_header`) + `tail` bytes.
    fn v6_frame(next_header: u8, tail: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 14 + 40];
        f[12] = 0x86; // ethertype IPv6 (0x86DD)
        f[13] = 0xDD;
        f[14] = 0x60; // version 6 in the high nibble
        f[14 + 6] = next_header; // IPv6 next-header field
        f.extend_from_slice(tail);
        f
    }

    fn v6() -> u8 {
        libc::AF_INET6 as u8
    }

    #[test]
    fn over_limit_chain_is_detected() {
        // 8 Hop-by-Hop blocks (next=0, HdrExtLen=0 => 8 bytes each). After
        // MAX_IPV6_EXT_HEADERS iterations the walker is still on ext-header 0
        // => over-limit / uninspectable.
        let mut tail = Vec::new();
        for _ in 0..8 {
            tail.extend_from_slice(&[0u8; 8]);
        }
        let frame = v6_frame(0, &tail);
        assert!(crate::afxdp::frame::ipv6_ext_chain_over_limit(&frame, v6()));
    }

    #[test]
    fn normal_l4_chain_is_not_over_limit() {
        // next_header = TCP (6): a real L4 within the bound.
        let frame = v6_frame(6, &[0u8; 20]);
        assert!(!crate::afxdp::frame::ipv6_ext_chain_over_limit(&frame, v6()));
    }

    #[test]
    fn truncated_chain_is_not_over_limit() {
        // next_header = Hop-by-Hop (0) but the tail is too short for a full
        // ext-header block: an in-loop short read => truncation, NOT over-limit
        // (so it keeps its existing flowless handling, undisturbed).
        let frame = v6_frame(0, &[0u8; 1]);
        assert!(!crate::afxdp::frame::ipv6_ext_chain_over_limit(&frame, v6()));
    }

    #[test]
    fn fragment_then_l4_is_not_over_limit() {
        // Fragment header (44) whose next-header is TCP (6): terminates on a
        // real L4 within the bound, so a non-first fragment is NOT over-limit.
        let mut tail = vec![6u8, 0, 0, 0, 0, 0, 0, 0]; // frag: next=TCP
        tail.extend_from_slice(&[0u8; 20]);
        let frame = v6_frame(44, &tail);
        assert!(!crate::afxdp::frame::ipv6_ext_chain_over_limit(&frame, v6()));
    }

    #[test]
    fn ipv4_is_never_over_limit() {
        // IPv4 has no extension headers; the predicate must reject non-v6.
        let frame = v6_frame(0, &[0u8; 64]);
        assert!(!crate::afxdp::frame::ipv6_ext_chain_over_limit(
            &frame,
            libc::AF_INET as u8
        ));
    }

    #[test]
    fn over_limit_drop_helper_bumps_counter_and_signals_drop() {
        let mut tail = Vec::new();
        for _ in 0..8 {
            tail.extend_from_slice(&[0u8; 8]);
        }
        let frame = v6_frame(0, &tail);
        let mut counters = BatchCounters::default();
        let dropped = ipv6_ext_header_over_limit_drop(&frame, v6(), &mut counters);
        assert!(dropped, "an over-limit chain must be dropped");
        assert_eq!(
            counters.ipv6_ext_header_dropped, 1,
            "the drop must bump ipv6_ext_header_dropped"
        );
        assert!(counters.touched, "touched must be set so the batch flushes");
    }
    #[test]
    fn truncated_eighth_header_drops_and_counts_but_seventh_does_not() {
        // Seven complete headers put the next declaration at the bound. Both
        // a missing length byte and a declared-length overrun on header 8 are
        // OverLimit and count exactly once; truncation of header 7 stays
        // Truncated, with no drop or counter change.
        for last_header in [&[60u8][..], &[60u8, 5][..]] {
            let mut tail = Vec::new();
            for _ in 0..crate::afxdp::MAX_IPV6_EXT_HEADERS - 1 {
                tail.extend_from_slice(&[60, 0, 0, 0, 0, 0, 0, 0]);
            }
            tail.extend_from_slice(last_header);
            let frame = v6_frame(60, &tail);
            let mut counters = BatchCounters::default();

            assert!(
                ipv6_ext_header_over_limit_drop(&frame, v6(), &mut counters),
                "an 8th extension-header declaration must fail closed"
            );
            assert_eq!(counters.ipv6_ext_header_dropped, 1);
            assert!(counters.touched);
        }

        let mut tail = Vec::new();
        for _ in 0..crate::afxdp::MAX_IPV6_EXT_HEADERS - 2 {
            tail.extend_from_slice(&[60, 0, 0, 0, 0, 0, 0, 0]);
        }
        tail.push(60); // The 7th header has no length byte.
        let frame = v6_frame(60, &tail);
        let mut counters = BatchCounters::default();

        assert!(!ipv6_ext_header_over_limit_drop(
            &frame,
            v6(),
            &mut counters
        ));
        assert_eq!(counters.ipv6_ext_header_dropped, 0);
        assert!(!counters.touched);
    }


    #[test]
    fn normal_frame_helper_neither_drops_nor_counts() {
        let frame = v6_frame(6, &[0u8; 20]);
        let mut counters = BatchCounters::default();
        let dropped = ipv6_ext_header_over_limit_drop(&frame, v6(), &mut counters);
        assert!(!dropped, "a normally-parseable frame must not be dropped");
        assert_eq!(counters.ipv6_ext_header_dropped, 0);
        assert!(!counters.touched);
    }
}

/// #3292: the flowless (no-L4) LocalDelivery security gate + the #3600 review
/// Note 2 PBR-vs-local-delivery ordering. The poll loop body is un-callable, so
/// these drive the two extracted decision helpers directly:
/// `flowless_local_delivery_verdict` (host-inbound + lo0 + junos-host) and
/// `flowless_base_resolution` (local-delivery-first resolution ordering).
#[cfg(test)]
mod flowless_local_delivery_tests {
    use super::*;
    use crate::filter::TermMatchExtra;
    use crate::ip_proto::PROTO_TCP;
    use crate::session::SessionKey;
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    const GRE: u8 = 47;
    // Ingress zone id used by the host-inbound verdict tests.
    const ZONE: u16 = 7;
    // Ingress ifindex + firewall-local interface IP used by the ordering test.
    const INGRESS_IF: i32 = 6;

    fn flowless_meta(protocol: u8) -> UserspaceDpMeta {
        UserspaceDpMeta {
            protocol,
            addr_family: libc::AF_INET as u8,
            l3_offset: 14,
            l4_offset: 34,
            ingress_ifindex: INGRESS_IF as u32,
            ..UserspaceDpMeta::default()
        }
    }

    // A FLOWLESS host-bound flow: ports = 0 (a non-first fragment / no-L4
    // packet) destined to a firewall-local interface IP.
    fn flowless_flow(protocol: u8) -> SessionFlow {
        let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 99, 1));
        SessionFlow {
            src_ip: src,
            dst_ip: dst,
            forward_key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol,
                src_ip: src,
                dst_ip: dst,
                src_port: 0,
                dst_port: 0,
                            discriminator: Default::default(),
                            routing_domain: 0,
            },
        }
    }

    // The frame-extra a non-first fragment yields: L4 header ABSENT, fragment
    // TRUE (#2344).
    fn flowless_extra() -> TermMatchExtra<'static> {
        TermMatchExtra {
            is_fragment: true,
            l4_present: false,
            ..Default::default()
        }
    }

    fn fw_with_host_inbound(zone: u16, services: &[&str], protocols: &[&str]) -> ForwardingState {
        let mut fw = ForwardingState::default();
        let services: Vec<String> = services.iter().map(|s| s.to_string()).collect();
        let protocols: Vec<String> = protocols.iter().map(|s| s.to_string()).collect();
        fw.zone_host_inbound.insert(
            zone,
            crate::afxdp::forwarding::zone_host_inbound_from_tokens(&services, &protocols),
        );
        fw
    }

    fn verdict(
        fw: &ForwardingState,
        flow: &SessionFlow,
        meta: UserspaceDpMeta,
        from_zone_id: u16,
    ) -> FlowlessLocalVerdict {
        flowless_local_delivery_verdict(
            fw,
            None,
            flowless_extra(),
            flow,
            meta,
            meta.ingress_ifindex as i32,
            from_zone_id,
            Some(from_zone_id),
            64,
            1_000,
        )
    }

    // (a) #3292: a flowless TCP host-bound packet on an SSH-ONLY zone is host-
    // inbound DENIED (dst_port = 0 can never match the tcp/22 admit) → NOT
    // delivered. Reverting the flowless gate (deliver ungated) flips this RED.
    #[test]
    fn flowless_host_inbound_deny_not_delivered() {
        let fw = fw_with_host_inbound(ZONE, &["ssh"], &[]);
        assert_eq!(
            verdict(&fw, &flowless_flow(PROTO_TCP), flowless_meta(PROTO_TCP), ZONE),
            FlowlessLocalVerdict::HostInboundDeny,
        );
    }

    // #3610 fail-on-revert (flowless): a flowless host-bound packet denied by the
    // zone host-inbound gate must ALSO emit the tuple-rich host-inbound deny
    // event (the #3292 flowless LocalDelivery arm), not just return the verdict.
    // Removing the `emit_host_inbound_deny` call in the `None => HostInboundDeny`
    // branch drops the event → RED (empty channel).
    #[test]
    fn flowless_host_inbound_deny_emits_event() {
        let (handle, rx) = crate::event_stream::test_worker_handle(
            8,
            crate::event_stream::DataplaneEventRateLimitConfig {
                events_per_second: 0,
                burst: 0,
            },
        );
        let fw = fw_with_host_inbound(ZONE, &["ssh"], &[]);
        let flow = flowless_flow(PROTO_TCP);
        let v = flowless_local_delivery_verdict(
            &fw,
            Some(&handle),
            flowless_extra(),
            &flow,
            flowless_meta(PROTO_TCP),
            INGRESS_IF,
            ZONE,
            Some(ZONE),
            64,
            crate::afxdp::neighbor::monotonic_nanos(),
        );
        assert_eq!(v, FlowlessLocalVerdict::HostInboundDeny);

        let event = rx
            .try_recv()
            .expect("#3610: flowless host-inbound deny must emit a tuple event")
            .decode_dataplane_event()
            .expect("host-inbound deny payload");
        assert_eq!(
            event.kind,
            crate::event_stream::codec::DataplaneEventKind::PolicyDeny
        );
        // Distinct host-inbound reason (6), NOT the transit policy reason (5).
        assert_eq!(event.reason, 6);
        assert_eq!(event.action, 0, "host-inbound is a silent drop → DENY");
        assert_eq!(event.policy_id, 0);
        assert_eq!(event.ingress_zone_id, ZONE);
        assert_eq!(event.src_ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)));
        assert_eq!(event.dst_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 99, 1)));
        assert_eq!(handle.dataplane_event_stats().policy_deny.sent, 1);
    }

    // (b) NO over-gating: a flowless packet the zone DOES admit must still be
    // delivered. `host-inbound-traffic system-services any-service` admits every
    // host-bound packet regardless of L4 → Deliver. (#3226: `any-service`, not
    // `all`, is the packet-wide admit — a flowless packet carries no port, so
    // the named-service union `all` now expands to would not match it.)
    #[test]
    fn flowless_admit_all_delivered() {
        let fw = fw_with_host_inbound(ZONE, &["any-service"], &[]);
        assert_eq!(
            verdict(&fw, &flowless_flow(PROTO_TCP), flowless_meta(PROTO_TCP), ZONE),
            FlowlessLocalVerdict::Deliver,
        );
    }

    // (b) NO over-gating, realistic: a flowless GRE-to-self fragment on a zone
    // that admits `system-services gre` (IP protocol 47) is delivered — the bare
    // IP-protocol admit does not depend on a port, so l4_present = false does not
    // over-gate it.
    #[test]
    fn flowless_protocol_admit_delivered() {
        let fw = fw_with_host_inbound(ZONE, &["gre"], &[]);
        assert_eq!(
            verdict(&fw, &flowless_flow(GRE), flowless_meta(GRE), ZONE),
            FlowlessLocalVerdict::Deliver,
        );
    }

    // (a) lo0: an admit-all zone with a host-bound (lo0) `from protocol tcp then
    // discard` filter discards the flowless TCP packet → NOT delivered. The
    // protocol-only term matches regardless of L4 presence.
    #[test]
    fn flowless_lo0_discard_not_delivered() {
        let mut fw = fw_with_host_inbound(ZONE, &["any-service"], &[]);
        fw.filter_state = crate::filter::parse_filter_state(
            &[crate::FirewallFilterSnapshot {
                name: "protect-re".into(),
                family: "inet".into(),
                terms: vec![crate::FirewallTermSnapshot {
                    name: "drop-tcp".into(),
                    protocols: vec!["tcp".into()],
                    action: "discard".into(),
                    ..Default::default()
                }],
            }],
            &[],
            &[],
            "protect-re",
            "",
        )
        .expect("lo0 filter compiles");
        assert_eq!(
            verdict(&fw, &flowless_flow(PROTO_TCP), flowless_meta(PROTO_TCP), ZONE),
            FlowlessLocalVerdict::Filtered,
        );
    }

    // (a) junos-host: an admit-all zone with `from-zone trust to-zone junos-host
    // then deny` (application any) denies the flowless host-bound packet → NOT
    // delivered. `any` / address terms match regardless of L4.
    #[test]
    fn flowless_junos_host_deny_not_delivered() {
        use crate::test_zone_ids::TEST_TRUST_ZONE_ID;
        let mut fw = fw_with_host_inbound(TEST_TRUST_ZONE_ID, &["any-service"], &[]);
        let zone_name_to_id: rustc_hash::FxHashMap<String, u16> =
            [("trust".to_string(), TEST_TRUST_ZONE_ID)]
                .into_iter()
                .collect();
        fw.policy = crate::policy::parse_policy_state(
            "permit",
            &[crate::PolicyRuleSnapshot {
                name: "host-deny".into(),
                from_zone: "trust".into(),
                to_zone: crate::policy::JUNOS_HOST_ZONE_NAME.into(),
                source_addresses: vec!["any".into()],
                destination_addresses: vec!["any".into()],
                applications: vec!["any".into()],
                application_terms: Vec::new(),
                action: "deny".into(),
                ..Default::default()
            }],
            &zone_name_to_id,
        );
        assert_eq!(
            verdict(
                &fw,
                &flowless_flow(PROTO_TCP),
                flowless_meta(PROTO_TCP),
                TEST_TRUST_ZONE_ID,
            ),
            FlowlessLocalVerdict::Filtered,
        );
    }

    // (c) #3600 review Note 2: a host-bound flowless packet whose dst is the
    // INGRESS interface's own IP resolves LocalDelivery even when a PBR
    // `then routing-instance` term steers it into an override table with no
    // local route. `flowless_base_resolution` tries ingress-local resolution
    // BEFORE the override table; reverting to override-table-first turns the
    // first assertion RED (it would become NoRoute — the bug).
    #[test]
    fn flowless_local_delivery_beats_pbr_override() {
        let dst_v4 = Ipv4Addr::new(10, 0, 99, 1);
        let dst = IpAddr::V4(dst_v4);
        let mut fw = ForwardingState::default();
        fw.egress.insert(
            INGRESS_IF,
            EgressInterface {
                bind_ifindex: INGRESS_IF,
                vlan_id: 0,
                mtu: 1500,
                src_mac: [0; 6],
                zone_id: ZONE,
                redundancy_group: 0,
                primary_v4: Some(dst_v4),
                primary_v6: None,
            },
        );
        // local_v4 deliberately does NOT contain dst, so the override-table
        // lookup alone resolves NoRoute — isolating the ingress-local-first
        // ordering as the load-bearing fix.
        let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
        let ha_state: BTreeMap<i32, HAGroupRuntime> = BTreeMap::new();

        let resolved = flowless_base_resolution(
            &fw,
            &dynamic_neighbors,
            &ha_state,
            0,
            INGRESS_IF,
            0,
            PROTO_TCP,
            dst,
            Some("vrf-x"),
        );
        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::LocalDelivery,
            "ingress-local resolution must win over the PBR override table",
        );

        // The override-table lookup alone does NOT deliver this host-bound
        // packet — the bug the ordering fixes.
        let override_only = lookup_forwarding_resolution_in_table_with_dynamic(
            &fw,
            &dynamic_neighbors,
            dst,
            Some("vrf-x"),
        );
        assert_ne!(
            override_only.disposition,
            ForwardingDisposition::LocalDelivery,
            "override-table-first (the #3600 Note 2 bug) would not deliver",
        );
    }
    /// #10677 helper-side failure witness: a shim tail stamped with the
    /// #7494 no-L4 protocol reaches interface-NAT LocalDelivery if diverted
    /// here, but cannot pass the zone's real GRE host-inbound rule. This is
    /// why the shim must keep the tail with its kernel-bound GRE head rather
    /// than relaxing the helper's protocol gate.
    #[test]
    fn interface_nat_gre_tail_is_refused_by_helper_host_inbound_10677() {
        let dst = Ipv4Addr::new(10, 0, 99, 1);
        let mut fw = fw_with_host_inbound(ZONE, &["gre"], &[]);
        fw.interface_nat_v4.insert(dst, INGRESS_IF);
        let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
        let ha_state: BTreeMap<i32, HAGroupRuntime> = BTreeMap::new();

        let resolved = flowless_base_resolution(
            &fw,
            &dynamic_neighbors,
            &ha_state,
            0,
            INGRESS_IF,
            0,
            255,
            IpAddr::V4(dst),
            None,
        );
        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::LocalDelivery,
            "the helper recognizes the interface-NAT target, but not the tail's protocol",
        );
        assert_eq!(
            verdict(&fw, &flowless_flow(255), flowless_meta(255), ZONE),
            FlowlessLocalVerdict::HostInboundDeny,
            "a 255-stamped GRE tail cannot match system-services gre",
        );
        assert_eq!(
            verdict(&fw, &flowless_flow(GRE), flowless_meta(GRE), ZONE),
            FlowlessLocalVerdict::Deliver,
            "the real GRE head protocol remains admitted",
        );
    }
}
