// Tests for nat.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep nat.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "nat_tests.rs"]` from nat.rs.

use super::*;

#[test]
fn interface_source_nat_matches_v4_rule() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let decision = match_source_nat(
        &rules,
        "lan",
        "wan",
        "10.0.61.102".parse().expect("src"),
        "172.16.80.200".parse().expect("dst"),
        Some("172.16.80.8".parse().expect("egress")),
        None,
    );
    assert_eq!(
        decision,
        Some(NatDecision {
            rewrite_src: Some("172.16.80.8".parse().expect("snat")),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    );
}

#[test]
fn interface_source_nat_matches_v6_rule() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat6".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["::/0".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let decision = match_source_nat(
        &rules,
        "lan",
        "wan",
        "2001:559:8585:ef00::100".parse().expect("src"),
        "2001:559:8585:80::200".parse().expect("dst"),
        None,
        Some("2001:559:8585:80::8".parse().expect("egress")),
    );
    assert_eq!(
        decision,
        Some(NatDecision {
            rewrite_src: Some("2001:559:8585:80::8".parse().expect("snat")),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    );
}

#[test]
fn off_rule_short_circuits_translation() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "no-nat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["10.0.61.0/24".to_string()],
        off: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    assert_eq!(
        match_source_nat(
            &rules,
            "lan",
            "wan",
            "10.0.61.102".parse().expect("src"),
            "172.16.80.200".parse().expect("dst"),
            Some("172.16.80.8".parse().expect("egress")),
            None,
        ),
        Some(NatDecision::default())
    );
}

#[test]
fn reverse_decision_turns_snat_into_reply_dnat() {
    let decision = NatDecision {
        rewrite_src: Some("172.16.80.8".parse().expect("snat")),
        rewrite_dst: None,
        ..NatDecision::default()
    };
    assert_eq!(
        decision.reverse(
            "10.0.61.102".parse().expect("orig src"),
            "172.16.80.200".parse().expect("orig dst"),
            12345,
            443,
        ),
        NatDecision {
            rewrite_src: None,
            rewrite_dst: Some("10.0.61.102".parse().expect("orig src")),
            ..NatDecision::default()
        }
    );
}

#[test]
fn static_nat_dnat_matches_external_ip_v4() {
    let table = StaticNatTable::from_snapshots(&[StaticNATRuleSnapshot {
        name: "static-1".to_string(),
        from_zone: "untrust".to_string(),
        external_ip: "203.0.113.10".to_string(),
        internal_ip: "192.168.1.10".to_string(),
    }]);
    let decision = table.match_dnat("203.0.113.10".parse().expect("ext"), "untrust");
    assert_eq!(
        decision,
        Some(NatDecision {
            rewrite_src: None,
            rewrite_dst: Some("192.168.1.10".parse().expect("int")),
            ..NatDecision::default()
        })
    );
}

#[test]
fn static_nat_snat_matches_internal_ip_v4() {
    let table = StaticNatTable::from_snapshots(&[StaticNATRuleSnapshot {
        name: "static-1".to_string(),
        from_zone: "trust".to_string(),
        external_ip: "203.0.113.10".to_string(),
        internal_ip: "192.168.1.10".to_string(),
    }]);
    let decision = table.match_snat("192.168.1.10".parse().expect("int"), "trust");
    assert_eq!(
        decision,
        Some(NatDecision {
            rewrite_src: Some("203.0.113.10".parse().expect("ext")),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    );
}

#[test]
fn static_nat_dnat_matches_external_ip_v6() {
    let table = StaticNatTable::from_snapshots(&[StaticNATRuleSnapshot {
        name: "static-v6".to_string(),
        from_zone: "untrust".to_string(),
        external_ip: "2001:db8::1".to_string(),
        internal_ip: "fd00::1".to_string(),
    }]);
    let decision = table.match_dnat("2001:db8::1".parse().expect("ext"), "untrust");
    assert_eq!(
        decision,
        Some(NatDecision {
            rewrite_src: None,
            rewrite_dst: Some("fd00::1".parse().expect("int")),
            ..NatDecision::default()
        })
    );
}

#[test]
fn static_nat_snat_matches_internal_ip_v6() {
    let table = StaticNatTable::from_snapshots(&[StaticNATRuleSnapshot {
        name: "static-v6".to_string(),
        from_zone: "trust".to_string(),
        external_ip: "2001:db8::1".to_string(),
        internal_ip: "fd00::1".to_string(),
    }]);
    let decision = table.match_snat("fd00::1".parse().expect("int"), "trust");
    assert_eq!(
        decision,
        Some(NatDecision {
            rewrite_src: Some("2001:db8::1".parse().expect("ext")),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    );
}

#[test]
fn static_nat_zone_mismatch_returns_none_for_dnat() {
    let table = StaticNatTable::from_snapshots(&[StaticNATRuleSnapshot {
        name: "static-1".to_string(),
        from_zone: "untrust".to_string(),
        external_ip: "203.0.113.10".to_string(),
        internal_ip: "192.168.1.10".to_string(),
    }]);
    // DNAT from wrong zone should fail
    assert!(table
        .match_dnat("203.0.113.10".parse().expect("ext"), "trust")
        .is_none());
    // SNAT does not check from_zone -- internal IP match is sufficient.
    // Traffic from internal host gets SNAT regardless of ingress zone.
    assert!(table
        .match_snat("192.168.1.10".parse().expect("int"), "dmz")
        .is_some());
}

#[test]
fn static_nat_empty_zone_matches_any() {
    let table = StaticNatTable::from_snapshots(&[StaticNATRuleSnapshot {
        name: "static-any".to_string(),
        from_zone: String::new(),
        external_ip: "203.0.113.10".to_string(),
        internal_ip: "192.168.1.10".to_string(),
    }]);
    assert!(table
        .match_dnat("203.0.113.10".parse().expect("ext"), "untrust")
        .is_some());
    assert!(table
        .match_dnat("203.0.113.10".parse().expect("ext"), "trust")
        .is_some());
    assert!(table
        .match_snat("192.168.1.10".parse().expect("int"), "trust")
        .is_some());
}

#[test]
fn static_nat_bidirectional_reverse() {
    let table = StaticNatTable::from_snapshots(&[StaticNATRuleSnapshot {
        name: "static-1".to_string(),
        from_zone: "untrust".to_string(),
        external_ip: "203.0.113.10".to_string(),
        internal_ip: "192.168.1.10".to_string(),
    }]);
    // Inbound DNAT: external -> internal
    let dnat = table
        .match_dnat("203.0.113.10".parse().expect("ext"), "untrust")
        .expect("dnat");
    assert_eq!(
        dnat,
        NatDecision {
            rewrite_src: None,
            rewrite_dst: Some("192.168.1.10".parse().expect("int")),
            ..NatDecision::default()
        }
    );
    // The reverse of DNAT should produce SNAT: on reply packets from
    // the internal host, rewrite src back to the external IP.
    // reverse().rewrite_src = self.rewrite_dst.map(|_| original_dst) = Some(external)
    // reverse().rewrite_dst = self.rewrite_src.map(|_| original_src) = None
    let original_src: IpAddr = "198.51.100.1".parse().expect("peer");
    let original_dst: IpAddr = "203.0.113.10".parse().expect("ext");
    let reverse = dnat.reverse(original_src, original_dst, 54321, 80);
    assert_eq!(
        reverse,
        NatDecision {
            rewrite_src: Some(original_dst),
            rewrite_dst: None,
            ..NatDecision::default()
        }
    );
}

#[test]
fn static_nat_no_match_returns_none() {
    let table = StaticNatTable::from_snapshots(&[StaticNATRuleSnapshot {
        name: "static-1".to_string(),
        from_zone: "untrust".to_string(),
        external_ip: "203.0.113.10".to_string(),
        internal_ip: "192.168.1.10".to_string(),
    }]);
    assert!(table
        .match_dnat("203.0.113.99".parse().expect("unknown"), "untrust")
        .is_none());
    assert!(table
        .match_snat("192.168.1.99".parse().expect("unknown"), "trust")
        .is_none());
}

#[test]
fn static_nat_invalid_ip_skipped() {
    let table = StaticNatTable::from_snapshots(&[
        StaticNATRuleSnapshot {
            name: "bad".to_string(),
            from_zone: String::new(),
            external_ip: "not-an-ip".to_string(),
            internal_ip: "192.168.1.10".to_string(),
        },
        StaticNATRuleSnapshot {
            name: "good".to_string(),
            from_zone: String::new(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
        },
    ]);
    // The bad entry should be skipped, the good one should work
    assert!(table
        .match_dnat("203.0.113.10".parse().expect("ext"), "any")
        .is_some());
}

#[test]
fn static_nat_external_ips_iterator() {
    let table = StaticNatTable::from_snapshots(&[
        StaticNATRuleSnapshot {
            name: "s1".to_string(),
            from_zone: String::new(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
        },
        StaticNATRuleSnapshot {
            name: "s2".to_string(),
            from_zone: String::new(),
            external_ip: "203.0.113.20".to_string(),
            internal_ip: "192.168.1.20".to_string(),
        },
    ]);
    let mut ips: Vec<IpAddr> = table.external_ips().copied().collect();
    ips.sort_by(|a, b| a.to_string().cmp(&b.to_string()));
    assert_eq!(ips.len(), 2);
    assert!(ips.contains(&"203.0.113.10".parse::<IpAddr>().unwrap()));
    assert!(ips.contains(&"203.0.113.20".parse::<IpAddr>().unwrap()));
}

// --- DNAT table tests ---

#[test]
fn dnat_basic_lookup_tcp() {
    let table = DnatTable::from_snapshots(&[DestinationNATRuleSnapshot {
        name: "web".to_string(),
        destination_address: "203.0.113.10".to_string(),
        destination_port: 80,
        protocol: "tcp".to_string(),
        pool_address: "192.168.1.10".to_string(),
        pool_port: 8080,
        ..DestinationNATRuleSnapshot::default()
    }]);
    let decision = table.lookup(PROTO_TCP, "203.0.113.10".parse().unwrap(), 80, "");
    assert_eq!(
        decision,
        Some(NatDecision {
            rewrite_dst: Some("192.168.1.10".parse().unwrap()),
            rewrite_dst_port: Some(8080),
            ..NatDecision::default()
        })
    );
}

#[test]
fn dnat_wildcard_port_fallback() {
    // port=0 entry matches any destination port
    let table = DnatTable::from_snapshots(&[DestinationNATRuleSnapshot {
        name: "any-port".to_string(),
        destination_address: "203.0.113.10".to_string(),
        destination_port: 0,
        protocol: "tcp".to_string(),
        pool_address: "192.168.1.10".to_string(),
        pool_port: 0,
        ..DestinationNATRuleSnapshot::default()
    }]);
    // Any port should match via wildcard
    let decision = table.lookup(PROTO_TCP, "203.0.113.10".parse().unwrap(), 12345, "");
    assert!(decision.is_some());
    let d = decision.unwrap();
    assert_eq!(d.rewrite_dst, Some("192.168.1.10".parse().unwrap()));
    // port=0 wildcard: no port rewrite
    assert_eq!(d.rewrite_dst_port, None);
}

#[test]
fn dnat_protocol_specificity() {
    // TCP entry should not match UDP lookups
    let table = DnatTable::from_snapshots(&[DestinationNATRuleSnapshot {
        name: "tcp-only".to_string(),
        destination_address: "203.0.113.10".to_string(),
        destination_port: 80,
        protocol: "tcp".to_string(),
        pool_address: "192.168.1.10".to_string(),
        pool_port: 8080,
        ..DestinationNATRuleSnapshot::default()
    }]);
    assert!(table
        .lookup(PROTO_TCP, "203.0.113.10".parse().unwrap(), 80, "")
        .is_some());
    assert!(table
        .lookup(PROTO_UDP, "203.0.113.10".parse().unwrap(), 80, "")
        .is_none());
}

#[test]
fn dnat_ipv6_lookup() {
    let table = DnatTable::from_snapshots(&[DestinationNATRuleSnapshot {
        name: "web-v6".to_string(),
        destination_address: "2001:db8::1".to_string(),
        destination_port: 443,
        protocol: "tcp".to_string(),
        pool_address: "fd00::1".to_string(),
        pool_port: 8443,
        ..DestinationNATRuleSnapshot::default()
    }]);
    let decision = table.lookup(PROTO_TCP, "2001:db8::1".parse().unwrap(), 443, "");
    assert_eq!(
        decision,
        Some(NatDecision {
            rewrite_dst: Some("fd00::1".parse().unwrap()),
            rewrite_dst_port: Some(8443),
            ..NatDecision::default()
        })
    );
}

#[test]
fn dnat_multiple_entries() {
    let table = DnatTable::from_snapshots(&[
        DestinationNATRuleSnapshot {
            name: "http".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 80,
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.10".to_string(),
            pool_port: 8080,
            ..DestinationNATRuleSnapshot::default()
        },
        DestinationNATRuleSnapshot {
            name: "https".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 443,
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.10".to_string(),
            pool_port: 8443,
            ..DestinationNATRuleSnapshot::default()
        },
    ]);
    let http = table.lookup(PROTO_TCP, "203.0.113.10".parse().unwrap(), 80, "");
    assert_eq!(http.unwrap().rewrite_dst_port, Some(8080));
    let https = table.lookup(PROTO_TCP, "203.0.113.10".parse().unwrap(), 443, "");
    assert_eq!(https.unwrap().rewrite_dst_port, Some(8443));
}

#[test]
fn dnat_no_match_returns_none() {
    let table = DnatTable::from_snapshots(&[DestinationNATRuleSnapshot {
        name: "web".to_string(),
        destination_address: "203.0.113.10".to_string(),
        destination_port: 80,
        protocol: "tcp".to_string(),
        pool_address: "192.168.1.10".to_string(),
        pool_port: 8080,
        ..DestinationNATRuleSnapshot::default()
    }]);
    // Different IP
    assert!(table
        .lookup(PROTO_TCP, "203.0.113.99".parse().unwrap(), 80, "")
        .is_none());
    // Different port (no wildcard entry)
    assert!(table
        .lookup(PROTO_TCP, "203.0.113.10".parse().unwrap(), 443, "")
        .is_none());
}

#[test]
fn dnat_port_aware_reverse() {
    // DNAT: rewrite dst to internal, rewrite dst_port from 80 to 8080
    let decision = NatDecision {
        rewrite_src: None,
        rewrite_dst: Some("192.168.1.10".parse().unwrap()),
        rewrite_src_port: None,
        rewrite_dst_port: Some(8080),
        nat64: false,
        nptv6: false,
    };
    // Reverse should turn rewrite_dst -> rewrite_src and port mapping too
    let reversed = decision.reverse(
        "198.51.100.1".parse().unwrap(), // original src
        "203.0.113.10".parse().unwrap(), // original dst
        54321,                           // original src_port
        80,                              // original dst_port
    );
    assert_eq!(reversed.rewrite_src, Some("203.0.113.10".parse().unwrap()));
    assert_eq!(reversed.rewrite_dst, None);
    assert_eq!(reversed.rewrite_src_port, Some(80));
    assert_eq!(reversed.rewrite_dst_port, None);
}

#[test]
fn dnat_snat_merge_preserves_both() {
    let dnat = NatDecision {
        rewrite_dst: Some("192.168.1.10".parse().unwrap()),
        rewrite_dst_port: Some(8080),
        ..NatDecision::default()
    };
    let snat = NatDecision {
        rewrite_src: Some("10.0.0.1".parse().unwrap()),
        ..NatDecision::default()
    };
    let merged = dnat.merge(snat);
    assert_eq!(merged.rewrite_dst, Some("192.168.1.10".parse().unwrap()));
    assert_eq!(merged.rewrite_dst_port, Some(8080));
    assert_eq!(merged.rewrite_src, Some("10.0.0.1".parse().unwrap()));
    assert_eq!(merged.rewrite_src_port, None);
}

#[test]
fn default_nat_decision_unchanged() {
    let d = NatDecision::default();
    assert_eq!(d.rewrite_src, None);
    assert_eq!(d.rewrite_dst, None);
    assert_eq!(d.rewrite_src_port, None);
    assert_eq!(d.rewrite_dst_port, None);
    assert!(!d.nat64);
}

#[test]
fn dnat_empty_protocol_expands_to_both() {
    let table = DnatTable::from_snapshots(&[DestinationNATRuleSnapshot {
        name: "both".to_string(),
        destination_address: "203.0.113.10".to_string(),
        destination_port: 0,
        protocol: String::new(),
        pool_address: "192.168.1.10".to_string(),
        pool_port: 0,
        ..DestinationNATRuleSnapshot::default()
    }]);
    // Both TCP and UDP should match
    assert!(table
        .lookup(PROTO_TCP, "203.0.113.10".parse().unwrap(), 53, "")
        .is_some());
    assert!(table
        .lookup(PROTO_UDP, "203.0.113.10".parse().unwrap(), 53, "")
        .is_some());
}

#[test]
fn dnat_same_port_no_port_rewrite() {
    // When pool_port == destination_port, no port rewrite needed
    let table = DnatTable::from_snapshots(&[DestinationNATRuleSnapshot {
        name: "same-port".to_string(),
        destination_address: "203.0.113.10".to_string(),
        destination_port: 80,
        protocol: "tcp".to_string(),
        pool_address: "192.168.1.10".to_string(),
        pool_port: 80,
        ..DestinationNATRuleSnapshot::default()
    }]);
    let decision = table
        .lookup(PROTO_TCP, "203.0.113.10".parse().unwrap(), 80, "")
        .unwrap();
    assert_eq!(decision.rewrite_dst, Some("192.168.1.10".parse().unwrap()));
    // Same port: no rewrite needed
    assert_eq!(decision.rewrite_dst_port, None);
}

#[test]
fn dnat_destination_ips_iterator() {
    let table = DnatTable::from_snapshots(&[
        DestinationNATRuleSnapshot {
            name: "web".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 80,
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.10".to_string(),
            pool_port: 8080,
            ..DestinationNATRuleSnapshot::default()
        },
        DestinationNATRuleSnapshot {
            name: "ssh".to_string(),
            destination_address: "203.0.113.20".to_string(),
            destination_port: 22,
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.20".to_string(),
            pool_port: 22,
            ..DestinationNATRuleSnapshot::default()
        },
    ]);
    let mut ips: Vec<IpAddr> = table.destination_ips().collect();
    ips.sort_by(|a, b| a.to_string().cmp(&b.to_string()));
    assert_eq!(ips.len(), 2);
    assert!(ips.contains(&"203.0.113.10".parse::<IpAddr>().unwrap()));
    assert!(ips.contains(&"203.0.113.20".parse::<IpAddr>().unwrap()));
}

#[test]
fn dnat_exact_port_beats_wildcard() {
    let table = DnatTable::from_snapshots(&[
        DestinationNATRuleSnapshot {
            name: "wildcard".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 0,
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.100".to_string(),
            pool_port: 0,
            ..DestinationNATRuleSnapshot::default()
        },
        DestinationNATRuleSnapshot {
            name: "exact".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 80,
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.10".to_string(),
            pool_port: 8080,
            ..DestinationNATRuleSnapshot::default()
        },
    ]);
    // Exact match should win over wildcard
    let decision = table
        .lookup(PROTO_TCP, "203.0.113.10".parse().unwrap(), 80, "")
        .unwrap();
    assert_eq!(decision.rewrite_dst, Some("192.168.1.10".parse().unwrap()));
    assert_eq!(decision.rewrite_dst_port, Some(8080));
    // Non-matching port should fall through to wildcard
    let decision = table
        .lookup(PROTO_TCP, "203.0.113.10".parse().unwrap(), 443, "")
        .unwrap();
    assert_eq!(decision.rewrite_dst, Some("192.168.1.100".parse().unwrap()));
    assert_eq!(decision.rewrite_dst_port, None);
}

#[test]
fn dnat_prefers_exact_from_zone_over_any_zone() {
    let table = DnatTable::from_snapshots(&[
        DestinationNATRuleSnapshot {
            name: "any-zone".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 443,
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.200".to_string(),
            pool_port: 9443,
            ..DestinationNATRuleSnapshot::default()
        },
        DestinationNATRuleSnapshot {
            name: "wan-only".to_string(),
            from_zone: "wan".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 443,
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.10".to_string(),
            pool_port: 8443,
            ..DestinationNATRuleSnapshot::default()
        },
    ]);
    let decision = table
        .lookup(PROTO_TCP, "203.0.113.10".parse().unwrap(), 443, "wan")
        .unwrap();
    assert_eq!(decision.rewrite_dst, Some("192.168.1.10".parse().unwrap()));
    assert_eq!(decision.rewrite_dst_port, Some(8443));
}

#[test]
fn dnat_zone_mismatch_falls_back_to_any_zone_rule() {
    let table = DnatTable::from_snapshots(&[
        DestinationNATRuleSnapshot {
            name: "wan-only".to_string(),
            from_zone: "wan".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 443,
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.10".to_string(),
            pool_port: 8443,
            ..DestinationNATRuleSnapshot::default()
        },
        DestinationNATRuleSnapshot {
            name: "any-zone".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 443,
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.200".to_string(),
            pool_port: 9443,
            ..DestinationNATRuleSnapshot::default()
        },
    ]);
    let decision = table
        .lookup(PROTO_TCP, "203.0.113.10".parse().unwrap(), 443, "dmz")
        .unwrap();
    assert_eq!(decision.rewrite_dst, Some("192.168.1.200".parse().unwrap()));
    assert_eq!(decision.rewrite_dst_port, Some(9443));
}

#[test]
fn dnat_zone_mismatch_without_wildcard_returns_none() {
    let table = DnatTable::from_snapshots(&[DestinationNATRuleSnapshot {
        name: "wan-only".to_string(),
        from_zone: "wan".to_string(),
        destination_address: "203.0.113.10".to_string(),
        destination_port: 443,
        protocol: "tcp".to_string(),
        pool_address: "192.168.1.10".to_string(),
        pool_port: 8443,
        ..DestinationNATRuleSnapshot::default()
    }]);
    assert!(table
        .lookup(PROTO_TCP, "203.0.113.10".parse().unwrap(), 443, "dmz")
        .is_none());
}

#[test]
fn dnat_duplicate_same_zone_last_rule_wins() {
    let table = DnatTable::from_snapshots(&[
        DestinationNATRuleSnapshot {
            name: "first".to_string(),
            from_zone: "wan".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 443,
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.101".to_string(),
            pool_port: 8443,
            ..DestinationNATRuleSnapshot::default()
        },
        DestinationNATRuleSnapshot {
            name: "second".to_string(),
            from_zone: "wan".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 443,
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.102".to_string(),
            pool_port: 9443,
            ..DestinationNATRuleSnapshot::default()
        },
    ]);
    let decision = table
        .lookup(PROTO_TCP, "203.0.113.10".parse().unwrap(), 443, "wan")
        .unwrap();
    assert_eq!(decision.rewrite_dst, Some("192.168.1.102".parse().unwrap()));
    assert_eq!(decision.rewrite_dst_port, Some(9443));
}

#[test]
fn dnat_duplicate_any_zone_last_rule_wins() {
    let table = DnatTable::from_snapshots(&[
        DestinationNATRuleSnapshot {
            name: "first".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 443,
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.101".to_string(),
            pool_port: 8443,
            ..DestinationNATRuleSnapshot::default()
        },
        DestinationNATRuleSnapshot {
            name: "second".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 443,
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.102".to_string(),
            pool_port: 9443,
            ..DestinationNATRuleSnapshot::default()
        },
    ]);
    let decision = table
        .lookup(PROTO_TCP, "203.0.113.10".parse().unwrap(), 443, "wan")
        .unwrap();
    assert_eq!(decision.rewrite_dst, Some("192.168.1.102".parse().unwrap()));
    assert_eq!(decision.rewrite_dst_port, Some(9443));
}

// --- Pool-mode SNAT tests ---

#[test]
fn pool_snat_single_address_rewrites_src_and_port() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "pool-snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "my-pool".to_string(),
        pool_addresses: vec!["203.0.113.1/32".to_string()],
        port_low: 1024,
        port_high: 65535,
        ..SourceNATRuleSnapshot::default()
    }]);
    let decision = match_source_nat(
        &rules,
        "lan",
        "wan",
        "10.0.1.100".parse().expect("src"),
        "8.8.8.8".parse().expect("dst"),
        None,
        None,
    );
    let d = decision.expect("should match pool rule");
    assert_eq!(d.rewrite_src, Some("203.0.113.1".parse().unwrap()));
    assert!(d.rewrite_src_port.is_some());
    let port = d.rewrite_src_port.unwrap();
    assert!(port >= 1024, "port {} out of range", port);
    assert_eq!(d.rewrite_dst, None);
    assert_eq!(d.rewrite_dst_port, None);
}

#[test]
fn pool_snat_multiple_addresses_round_robin() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "pool-multi".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "multi-pool".to_string(),
        pool_addresses: vec![
            "203.0.113.1".to_string(),
            "203.0.113.2".to_string(),
            "203.0.113.3".to_string(),
        ],
        port_low: 1024,
        port_high: 65535,
        ..SourceNATRuleSnapshot::default()
    }]);
    let mut seen_addrs = std::collections::HashSet::new();
    for _ in 0..6 {
        let d = match_source_nat(
            &rules,
            "lan",
            "wan",
            "10.0.1.100".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            None,
            None,
        )
        .expect("should match");
        if let Some(IpAddr::V4(addr)) = d.rewrite_src {
            seen_addrs.insert(addr);
        }
    }
    // After 6 allocations across 3 addresses, all should have been used.
    assert_eq!(
        seen_addrs.len(),
        3,
        "expected round-robin across all 3 addresses, got {:?}",
        seen_addrs
    );
}

#[test]
fn pool_snat_wrong_family_pool_does_not_shadow_later_rule() {
    let rules = parse_source_nat_rules(&[
        SourceNATRuleSnapshot {
            name: "wrong-family".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "v6-only".to_string(),
            pool_addresses: vec!["2001:db8::10".to_string()],
            port_low: 1024,
            port_high: 65535,
            ..SourceNATRuleSnapshot::default()
        },
        SourceNATRuleSnapshot {
            name: "usable-v4".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "v4-pool".to_string(),
            pool_addresses: vec!["203.0.113.20".to_string()],
            port_low: 40000,
            port_high: 40000,
            ..SourceNATRuleSnapshot::default()
        },
    ]);

    let d = match_source_nat(
        &rules,
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        None,
        None,
    )
    .expect("later compatible rule should match");
    assert_eq!(d.rewrite_src, Some("203.0.113.20".parse().unwrap()));
    assert_eq!(d.rewrite_src_port, Some(40000));
}

#[test]
fn pool_snat_wrong_family_pool_returns_none_when_no_later_rule_matches() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "wrong-family".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "v6-only".to_string(),
        pool_addresses: vec!["2001:db8::10".to_string()],
        port_low: 1024,
        port_high: 65535,
        ..SourceNATRuleSnapshot::default()
    }]);

    let d = match_source_nat(
        &rules,
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        None,
        None,
    );
    assert_eq!(d, None);
}

#[test]
fn pool_snat_address_persistent_sticks_source_to_pool_address() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "pool-sticky".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "sticky-pool".to_string(),
        pool_addresses: vec![
            "203.0.113.1".to_string(),
            "203.0.113.2".to_string(),
            "203.0.113.3".to_string(),
        ],
        port_low: 40000,
        port_high: 40010,
        address_persistent: true,
        ..SourceNATRuleSnapshot::default()
    }]);

    let src = "10.0.1.101".parse().unwrap();
    let expected_idx = sticky_pool_index(src, 3);
    assert_eq!(expected_idx, 1);

    for want_port in 40000..40004 {
        let d = match_source_nat(
            &rules,
            "lan",
            "wan",
            src,
            "8.8.8.8".parse().unwrap(),
            None,
            None,
        )
        .expect("should match");
        assert_eq!(d.rewrite_src, Some("203.0.113.2".parse().unwrap()));
        assert_eq!(d.rewrite_src_port, Some(want_port));
    }
}

#[test]
fn pool_snat_address_persistent_sticks_each_source_independently() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "pool-sticky-many".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "sticky-pool".to_string(),
        pool_addresses: vec![
            "203.0.113.1".to_string(),
            "203.0.113.2".to_string(),
            "203.0.113.3".to_string(),
            "203.0.113.4".to_string(),
            "203.0.113.5".to_string(),
        ],
        port_low: 40000,
        port_high: 40100,
        address_persistent: true,
        ..SourceNATRuleSnapshot::default()
    }]);

    let sources: [IpAddr; 8] = [
        "10.0.1.100".parse().unwrap(),
        "10.0.1.101".parse().unwrap(),
        "10.0.1.102".parse().unwrap(),
        "10.0.1.103".parse().unwrap(),
        "10.0.1.104".parse().unwrap(),
        "10.0.1.105".parse().unwrap(),
        "10.0.1.106".parse().unwrap(),
        "10.0.1.107".parse().unwrap(),
    ];
    let mut pool_addresses_used = std::collections::HashSet::new();

    for src in sources {
        let mut addresses_for_src = std::collections::HashSet::new();
        for dst_host in 1..=20 {
            let dst = IpAddr::V4(Ipv4Addr::new(8, 8, 8, dst_host));
            let d = match_source_nat(&rules, "lan", "wan", src, dst, None, None)
                .expect("sticky source should match");
            addresses_for_src.insert(d.rewrite_src.expect("pool address"));
        }
        assert_eq!(
            addresses_for_src.len(),
            1,
            "source {src} mapped to multiple pool addresses: {addresses_for_src:?}"
        );
        pool_addresses_used.extend(addresses_for_src);
    }

    assert!(
        pool_addresses_used.len() >= 4,
        "sticky hash collapsed source spread: {pool_addresses_used:?}"
    );
}

#[test]
fn pool_snat_address_persistent_spreads_distinct_sources_across_pool() {
    let pool_len = 64usize;
    let mut seen = vec![false; pool_len];

    for host in 0..1000u32 {
        let src = IpAddr::V4(Ipv4Addr::new(
            10,
            ((host >> 16) & 0xff) as u8,
            ((host >> 8) & 0xff) as u8,
            (host & 0xff) as u8,
        ));
        seen[sticky_pool_index(src, pool_len)] = true;
    }

    let used = seen.iter().filter(|used| **used).count();
    assert!(
        used >= pool_len * 80 / 100,
        "sticky hash used {used}/{pool_len} pool slots"
    );
}

#[test]
fn pool_snat_address_persistent_userspace_v1_contract_fixtures() {
    assert_eq!(sticky_pool_index("10.0.1.100".parse().unwrap(), 4), 3);
    assert_eq!(sticky_pool_index("10.0.1.101".parse().unwrap(), 4), 0);
    assert_eq!(sticky_pool_index("192.0.2.1".parse().unwrap(), 5), 4);
    assert_eq!(sticky_pool_index("198.51.100.25".parse().unwrap(), 5), 0);
    assert_eq!(sticky_pool_index("2001:db8::1".parse().unwrap(), 257), 197);
    assert_eq!(sticky_pool_index("2001:db8::2".parse().unwrap(), 257), 125);
}

#[test]
fn pool_snat_address_persistent_differs_from_legacy_backend_algorithms() {
    let v4: Ipv4Addr = "10.0.1.100".parse().unwrap();
    assert_eq!(sticky_pool_index(IpAddr::V4(v4), 4), 3);
    assert_eq!(legacy_backend_v4_index(v4, 4), 2);

    let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    assert_eq!(sticky_pool_index(IpAddr::V6(v6), 257), 197);
    assert_eq!(legacy_backend_v6_index(v6, 257), 116);
}

fn legacy_backend_v4_index(src_ip: Ipv4Addr, pool_len: usize) -> usize {
    if pool_len <= 1 {
        return 0;
    }
    (u32::from_le_bytes(src_ip.octets()) as usize) % pool_len
}

fn legacy_backend_v6_index(src_ip: Ipv6Addr, pool_len: usize) -> usize {
    if pool_len <= 1 {
        return 0;
    }
    let mut hash = 0u32;
    for chunk in src_ip.octets().chunks_exact(4) {
        let mut word = [0u8; 4];
        word.copy_from_slice(chunk);
        hash ^= u32::from_le_bytes(word);
    }
    (hash as usize) % pool_len
}

#[test]
fn pool_snat_address_persistent_hashes_full_ipv6_address() {
    let a: IpAddr = "2001:db8::1".parse().unwrap();
    let b: IpAddr = "2001:db8::2".parse().unwrap();

    assert_eq!(sticky_pool_index(a, 257), 197);
    assert_eq!(sticky_pool_index(b, 257), 125);
}

#[test]
fn pool_snat_port_range_wrapping() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "small-range".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "small".to_string(),
        pool_addresses: vec!["203.0.113.1".to_string()],
        port_low: 10000,
        port_high: 10002,
        ..SourceNATRuleSnapshot::default()
    }]);
    let mut ports = Vec::new();
    for _ in 0..6 {
        let d = match_source_nat(
            &rules,
            "lan",
            "wan",
            "10.0.1.100".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            None,
            None,
        )
        .expect("should match");
        ports.push(d.rewrite_src_port.unwrap());
    }
    // With range [10000, 10002] (3 ports), allocations should wrap.
    assert_eq!(ports[0], 10000);
    assert_eq!(ports[1], 10001);
    assert_eq!(ports[2], 10002);
    assert_eq!(ports[3], 10000);
    assert_eq!(ports[4], 10001);
    assert_eq!(ports[5], 10002);
}

#[test]
fn pool_snat_combined_with_dnat() {
    // Pre-routing DNAT decision
    let dnat = NatDecision {
        rewrite_dst: Some("192.168.1.10".parse().unwrap()),
        rewrite_dst_port: Some(8080),
        ..NatDecision::default()
    };
    // Post-policy pool SNAT decision
    let snat = NatDecision {
        rewrite_src: Some("203.0.113.1".parse().unwrap()),
        rewrite_src_port: Some(40000),
        ..NatDecision::default()
    };
    let merged = dnat.merge(snat);
    assert_eq!(merged.rewrite_dst, Some("192.168.1.10".parse().unwrap()));
    assert_eq!(merged.rewrite_dst_port, Some(8080));
    assert_eq!(merged.rewrite_src, Some("203.0.113.1".parse().unwrap()));
    assert_eq!(merged.rewrite_src_port, Some(40000));
}

#[test]
fn pool_snat_reverse_session_key() {
    let decision = NatDecision {
        rewrite_src: Some("203.0.113.1".parse().unwrap()),
        rewrite_src_port: Some(40000),
        ..NatDecision::default()
    };
    let reversed = decision.reverse(
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        12345,
        443,
    );
    assert_eq!(reversed.rewrite_src, None);
    assert_eq!(reversed.rewrite_dst, Some("10.0.1.100".parse().unwrap()));
    assert_eq!(reversed.rewrite_src_port, None);
    assert_eq!(reversed.rewrite_dst_port, Some(12345));
}

#[test]
fn pool_snat_v6_single_address() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "pool-v6".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["::/0".to_string()],
        pool_name: "v6-pool".to_string(),
        pool_addresses: vec!["2001:db8::1".to_string()],
        port_low: 2000,
        port_high: 3000,
        ..SourceNATRuleSnapshot::default()
    }]);
    let decision = match_source_nat(
        &rules,
        "lan",
        "wan",
        "fd00::100".parse().expect("src"),
        "2001:db8:1::1".parse().expect("dst"),
        None,
        None,
    );
    let d = decision.expect("should match pool v6 rule");
    assert_eq!(d.rewrite_src, Some("2001:db8::1".parse().unwrap()));
    assert!(d.rewrite_src_port.is_some());
    let port = d.rewrite_src_port.unwrap();
    assert!(port >= 2000 && port <= 3000, "port {} out of range", port);
}

#[test]
fn pool_snat_default_port_range() {
    // When port_low and port_high are 0, defaults to 1024..65535
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "default-range".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "default".to_string(),
        pool_addresses: vec!["203.0.113.1".to_string()],
        port_low: 0,
        port_high: 0,
        ..SourceNATRuleSnapshot::default()
    }]);
    let d = match_source_nat(
        &rules,
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        None,
        None,
    )
    .expect("should match");
    let port = d.rewrite_src_port.unwrap();
    assert!(port >= 1024, "port {} out of default range", port);
}

#[test]
fn pool_snat_zone_mismatch_returns_none() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "pool-zone".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "p".to_string(),
        pool_addresses: vec!["203.0.113.1".to_string()],
        port_low: 1024,
        port_high: 65535,
        ..SourceNATRuleSnapshot::default()
    }]);
    assert!(match_source_nat(
        &rules,
        "dmz", // wrong from_zone
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        None,
        None,
    )
    .is_none());
}

#[test]
fn port_allocator_basic() {
    let alloc = PortAllocator::new(2, 5000, 5002);
    // Address selection round-robin
    let src = "10.0.1.100".parse().unwrap();
    assert_eq!(alloc.address_index(src, 0, 2, false), 0);
    assert_eq!(alloc.address_index(src, 0, 2, false), 1);
    assert_eq!(alloc.address_index(src, 0, 2, false), 0);
    // Port allocation for address 0
    assert_eq!(alloc.next_port(0), 5000);
    assert_eq!(alloc.next_port(0), 5001);
    assert_eq!(alloc.next_port(0), 5002);
    assert_eq!(alloc.next_port(0), 5000); // wraps

    let mixed = PortAllocator::new(4, 5000, 5002);
    let src_v4 = "10.0.1.100".parse().unwrap();
    let src_v6 = "2001:db8::100".parse().unwrap();
    assert_eq!(mixed.address_index(src_v4, 0, 2, false), 0);
    assert_eq!(mixed.address_index(src_v6, 2, 2, false), 2);
    assert_eq!(mixed.address_index(src_v4, 0, 2, false), 1);
    assert_eq!(mixed.address_index(src_v6, 2, 2, false), 3);
}
