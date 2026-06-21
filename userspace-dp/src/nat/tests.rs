// Tests for the nat/ module. Moved into nat/tests.rs as part of the
// #1542 split. White-box tests reach into allocator internals via the
// `debug_live()` accessor and the `pub(super)` items promoted in
// allocator.rs / destination.rs.

use super::allocator::{
    sticky_pool_index, PersistentLease, PersistentSourceKey, ALLOCATION_GC_BUDGET, NS_PER_SEC,
};
use super::destination::{PROTO_TCP, PROTO_UDP};
use super::*;
use crate::{DestinationNATRuleSnapshot, SourceNATRuleSnapshot, StaticNATRuleSnapshot};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
    assert!(
        table
            .match_dnat("203.0.113.10".parse().expect("ext"), "trust")
            .is_none()
    );
    // SNAT does not check from_zone -- internal IP match is sufficient.
    // Traffic from internal host gets SNAT regardless of ingress zone.
    assert!(
        table
            .match_snat("192.168.1.10".parse().expect("int"), "dmz")
            .is_some()
    );
}

#[test]
fn static_nat_empty_zone_matches_any() {
    let table = StaticNatTable::from_snapshots(&[StaticNATRuleSnapshot {
        name: "static-any".to_string(),
        from_zone: String::new(),
        external_ip: "203.0.113.10".to_string(),
        internal_ip: "192.168.1.10".to_string(),
    }]);
    assert!(
        table
            .match_dnat("203.0.113.10".parse().expect("ext"), "untrust")
            .is_some()
    );
    assert!(
        table
            .match_dnat("203.0.113.10".parse().expect("ext"), "trust")
            .is_some()
    );
    assert!(
        table
            .match_snat("192.168.1.10".parse().expect("int"), "trust")
            .is_some()
    );
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
    assert!(
        table
            .match_dnat("203.0.113.99".parse().expect("unknown"), "untrust")
            .is_none()
    );
    assert!(
        table
            .match_snat("192.168.1.99".parse().expect("unknown"), "trust")
            .is_none()
    );
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
    assert!(
        table
            .match_dnat("203.0.113.10".parse().expect("ext"), "any")
            .is_some()
    );
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

#[test]
fn static_nat_canonical_cidr_mask_v4_installs_entry() {
    // #2122: Junos emits static-NAT match/then in canonical prefix form
    // ("203.0.113.5/32" / "10.0.0.5/32") and the Go compiler copies the mask
    // verbatim into the snapshot. IpAddr::from_str rejects CIDR, so pre-fix
    // every rule hit the Err/skip arm and was silently dropped — no
    // translation occurred and the external IP was never registered as a
    // local address. The parse must strip the /32 mask. This test FAILS on
    // the unfixed code (table is empty, every assertion is None).
    let table = StaticNatTable::from_snapshots(&[StaticNATRuleSnapshot {
        name: "static-cidr".to_string(),
        from_zone: "untrust".to_string(),
        external_ip: "203.0.113.5/32".to_string(),
        internal_ip: "10.0.0.5/32".to_string(),
    }]);
    // Inbound DNAT on the bare external IP -> bare internal IP.
    assert_eq!(
        table.match_dnat("203.0.113.5".parse().expect("ext"), "untrust"),
        Some(NatDecision {
            rewrite_src: None,
            rewrite_dst: Some("10.0.0.5".parse().expect("int")),
            ..NatDecision::default()
        })
    );
    // Outbound SNAT on the bare internal IP -> bare external IP.
    assert_eq!(
        table.match_snat("10.0.0.5".parse().expect("int"), "trust"),
        Some(NatDecision {
            rewrite_src: Some("203.0.113.5".parse().expect("ext")),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    );
    // The external IP must be registered (bare, no mask) for local delivery
    // recognition (forwarding_build iterates external_ips()).
    let ips: Vec<IpAddr> = table.external_ips().copied().collect();
    assert_eq!(ips, vec!["203.0.113.5".parse::<IpAddr>().unwrap()]);
}

#[test]
fn static_nat_canonical_cidr_mask_v6_installs_entry() {
    // IPv6 canonical host form carries /128; same root cause as the v4 case.
    let table = StaticNatTable::from_snapshots(&[StaticNATRuleSnapshot {
        name: "static-cidr-v6".to_string(),
        from_zone: "untrust".to_string(),
        external_ip: "2001:db8::1/128".to_string(),
        internal_ip: "fd00::1/128".to_string(),
    }]);
    assert_eq!(
        table.match_dnat("2001:db8::1".parse().expect("ext"), "untrust"),
        Some(NatDecision {
            rewrite_src: None,
            rewrite_dst: Some("fd00::1".parse().expect("int")),
            ..NatDecision::default()
        })
    );
    assert_eq!(
        table.match_snat("fd00::1".parse().expect("int"), "trust"),
        Some(NatDecision {
            rewrite_src: Some("2001:db8::1".parse().expect("ext")),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    );
    let ips: Vec<IpAddr> = table.external_ips().copied().collect();
    assert_eq!(ips, vec!["2001:db8::1".parse::<IpAddr>().unwrap()]);
}

#[test]
fn static_nat_cidr_and_bare_coexist() {
    // A masked rule and a bare-IP rule must both install — stripping the mask
    // on one must not regress the other.
    let table = StaticNatTable::from_snapshots(&[
        StaticNATRuleSnapshot {
            name: "masked".to_string(),
            from_zone: String::new(),
            external_ip: "203.0.113.5/32".to_string(),
            internal_ip: "10.0.0.5".to_string(),
        },
        StaticNATRuleSnapshot {
            name: "bare".to_string(),
            from_zone: String::new(),
            external_ip: "203.0.113.6".to_string(),
            internal_ip: "10.0.0.6/32".to_string(),
        },
    ]);
    assert!(
        table
            .match_dnat("203.0.113.5".parse().expect("ext"), "any")
            .is_some()
    );
    assert!(
        table
            .match_dnat("203.0.113.6".parse().expect("ext"), "any")
            .is_some()
    );
    assert!(
        table
            .match_snat("10.0.0.5".parse().expect("int"), "any")
            .is_some()
    );
    assert!(
        table
            .match_snat("10.0.0.6".parse().expect("int"), "any")
            .is_some()
    );
}

#[test]
fn static_nat_non_host_mask_rejected() {
    // A non-host mask (or garbage suffix) is NOT a canonical host form and
    // must be rejected (skipped), not silently coerced to a host route — it
    // would otherwise translate the wrong scope. Pre-#2122 ALL of these were
    // rejected too (the bare parser errored on any mask), so this is not a
    // regression; it keeps the hardened parse strict about misconfiguration.
    for bad in [
        "203.0.113.5/24",     // non-host v4 prefix
        "203.0.113.5/notanum", // non-numeric mask
        "203.0.113.5/",       // empty mask
        "203.0.113.5//32",    // double slash
        "203.0.113.5/128",    // v6 host length applied to a v4 address
        "2001:db8::1/64",     // non-host v6 prefix
        "2001:db8::1/32",     // v4 host length applied to a v6 address
    ] {
        let table = StaticNatTable::from_snapshots(&[StaticNATRuleSnapshot {
            name: "bad-mask".to_string(),
            from_zone: String::new(),
            external_ip: bad.to_string(),
            internal_ip: "10.0.0.5".to_string(),
        }]);
        assert_eq!(
            table.external_ips().count(),
            0,
            "non-host/garbage mask {bad:?} must be rejected, not installed"
        );
    }
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
    assert!(
        table
            .lookup(PROTO_TCP, "203.0.113.10".parse().unwrap(), 80, "")
            .is_some()
    );
    assert!(
        table
            .lookup(PROTO_UDP, "203.0.113.10".parse().unwrap(), 80, "")
            .is_none()
    );
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
    assert!(
        table
            .lookup(PROTO_TCP, "203.0.113.99".parse().unwrap(), 80, "")
            .is_none()
    );
    // Different port (no wildcard entry)
    assert!(
        table
            .lookup(PROTO_TCP, "203.0.113.10".parse().unwrap(), 443, "")
            .is_none()
    );
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
    assert!(
        table
            .lookup(PROTO_TCP, "203.0.113.10".parse().unwrap(), 53, "")
            .is_some()
    );
    assert!(
        table
            .lookup(PROTO_UDP, "203.0.113.10".parse().unwrap(), 53, "")
            .is_some()
    );
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
    assert!(
        table
            .lookup(PROTO_TCP, "203.0.113.10".parse().unwrap(), 443, "dmz")
            .is_none()
    );
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

// --- #1827 PR-3: per-uplink SNAT pool selection by to-zone ---
//
// Multi-WAN per-uplink pools need NO new matcher: the to-zone fed to
// match_source_nat is derived from the RESOLVED egress interface of
// each new flow (zone_pair_ids_for_flow_with_override in
// poll_descriptor), so when ip-monitoring flips the preferred route
// (or an FBF term steers into an uplink's routing-instance), the
// to-zone follows the new egress interface and the other rule-set's
// pool is chosen. These tests pin the matcher half of that contract:
// two rules identical except to_zone select their own pools.

fn per_uplink_pool_rules() -> Vec<SourceNatRule> {
    parse_source_nat_rules(&[
        SourceNATRuleSnapshot {
            name: "snat-isp-a".to_string(),
            from_zone: "trust".to_string(),
            to_zone: "untrust-a".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "isp-a-pool".to_string(),
            pool_addresses: vec!["203.0.113.10/32".to_string()],
            port_low: 1024,
            port_high: 65535,
            ..SourceNATRuleSnapshot::default()
        },
        SourceNATRuleSnapshot {
            name: "snat-isp-b".to_string(),
            from_zone: "trust".to_string(),
            to_zone: "untrust-b".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "isp-b-pool".to_string(),
            pool_addresses: vec!["198.51.100.10/32".to_string()],
            port_low: 1024,
            port_high: 65535,
            ..SourceNATRuleSnapshot::default()
        },
    ])
}

#[test]
fn per_uplink_pool_selected_by_to_zone() {
    let rules = per_uplink_pool_rules();
    // Same flow, resolved egress in uplink A's zone -> pool A.
    let d = match_source_nat(
        &rules,
        "trust",
        "untrust-a",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        None,
        None,
    )
    .expect("uplink A rule should match");
    assert_eq!(d.rewrite_src, Some("203.0.113.10".parse().unwrap()));

    // Identical flow after a route flip: resolved egress now sits in
    // uplink B's zone -> pool B, with no rule-set change.
    let d = match_source_nat(
        &rules,
        "trust",
        "untrust-b",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        None,
        None,
    )
    .expect("uplink B rule should match");
    assert_eq!(d.rewrite_src, Some("198.51.100.10".parse().unwrap()));
}

#[test]
fn per_uplink_pool_no_match_outside_uplink_zones() {
    let rules = per_uplink_pool_rules();
    // Egress resolving into a zone neither rule-set names must not
    // borrow either uplink's pool.
    assert_eq!(
        match_source_nat(
            &rules,
            "trust",
            "dmz",
            "10.0.1.100".parse().unwrap(),
            "10.0.30.101".parse().unwrap(),
            None,
            None,
        ),
        None
    );
}

fn persistent_pool_rules(timeout_secs: i64, port_low: u16, port_high: u16) -> Vec<SourceNatRule> {
    persistent_pool_rules_with_options(
        timeout_secs,
        port_low,
        port_high,
        vec!["203.0.113.10"],
        false,
    )
}

fn persistent_pool_rules_with_options(
    timeout_secs: i64,
    port_low: u16,
    port_high: u16,
    pool_addresses: Vec<&str>,
    address_persistent: bool,
) -> Vec<SourceNatRule> {
    parse_source_nat_rules(&[persistent_pool_snapshot(
        timeout_secs,
        port_low,
        port_high,
        pool_addresses,
        address_persistent,
    )])
}

fn persistent_pool_snapshot(
    timeout_secs: i64,
    port_low: u16,
    port_high: u16,
    pool_addresses: Vec<&str>,
    address_persistent: bool,
) -> SourceNATRuleSnapshot {
    SourceNATRuleSnapshot {
        name: "persistent-snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "persistent-pool".to_string(),
        pool_addresses: pool_addresses
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>(),
        port_low,
        port_high,
        address_persistent,
        persistent_nat: true,
        persistent_nat_permit_any_remote_host: true,
        persistent_nat_inactivity_timeout: timeout_secs,
        ..SourceNATRuleSnapshot::default()
    }
}

fn tuple_snat_lookup(
    rules: &[SourceNatRule],
    src_port: u16,
    dst_ip: &str,
    dst_port: u16,
    now_ns: u64,
) -> SourceNatLookup {
    tuple_snat_lookup_from_src(rules, "10.0.1.100", src_port, dst_ip, dst_port, now_ns)
}

fn tuple_snat_lookup_from_src(
    rules: &[SourceNatRule],
    src_ip: &str,
    src_port: u16,
    dst_ip: &str,
    dst_port: u16,
    now_ns: u64,
) -> SourceNatLookup {
    match_source_nat_result_for_tuple(
        rules,
        "lan",
        "wan",
        src_ip.parse().unwrap(),
        dst_ip.parse().unwrap(),
        6,
        src_port,
        dst_port,
        None,
        None,
        now_ns,
        false,
    )
}

fn expect_snat_decision(lookup: SourceNatLookup) -> NatDecision {
    match lookup {
        SourceNatLookup::Matched(decision) => decision,
        other => panic!("expected matched SNAT decision, got {other:?}"),
    }
}

fn session_key(src_port: u16, dst_ip: &str, dst_port: u16) -> crate::session::SessionKey {
    session_key_from_src("10.0.1.100", src_port, dst_ip, dst_port)
}

fn lease_key(src_port: u16) -> PersistentSourceKey {
    PersistentSourceKey {
        protocol: 6,
        src_ip: "10.0.1.100".parse().unwrap(),
        src_port,
    }
}

fn session_key_from_src(
    src_ip: &str,
    src_port: u16,
    dst_ip: &str,
    dst_port: u16,
) -> crate::session::SessionKey {
    crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: src_ip.parse().unwrap(),
        dst_ip: dst_ip.parse().unwrap(),
        src_port,
        dst_port,
    }
}

fn assert_persistent_expiry_indexes_consistent(rule: &SourceNatRule) {
    let live = rule
        .pool_allocator
        .debug_live();
    let mut expected_global = BTreeSet::new();
    let mut expected_by_addr = vec![BTreeSet::new(); live.lease_expirations_by_addr.len()];

    for (key, lease) in &live.persistent_by_source {
        let entry = (lease.expires_at_ns, *key);
        assert!(
            lease.addr_index < expected_by_addr.len(),
            "persistent lease addr index {} out of range {}",
            lease.addr_index,
            expected_by_addr.len()
        );
        assert_eq!(
            live.addr_index_by_translated
                .get(&lease.translated)
                .copied(),
            Some(lease.addr_index),
            "persistent lease addr index mismatch"
        );
        assert_eq!(
            pool_ip_for_addr_index(rule, lease.addr_index),
            Some(lease.translated.ip),
            "persistent lease translated address mismatch"
        );
        if lease.active_flows == 0 {
            expected_global.insert(entry);
            expected_by_addr[lease.addr_index].insert(entry);
        }
    }

    assert_eq!(
        live.lease_expirations, expected_global,
        "global persistent expiry index mismatch"
    );
    assert_eq!(
        live.lease_expirations_by_addr, expected_by_addr,
        "per-address persistent expiry index mismatch"
    );
}

fn pool_ip_for_addr_index(rule: &SourceNatRule, addr_index: usize) -> Option<IpAddr> {
    if addr_index < rule.pool_addresses_v4.len() {
        return Some(IpAddr::V4(rule.pool_addresses_v4[addr_index]));
    }
    let v6_index = addr_index.checked_sub(rule.pool_addresses_v4.len())?;
    rule.pool_addresses_v6
        .get(v6_index)
        .copied()
        .map(IpAddr::V6)
}

#[test]
fn pool_snat_persistent_reuses_same_source_tuple() {
    let rules = persistent_pool_rules(300, 40000, 40010);
    let first = expect_snat_decision(tuple_snat_lookup(&rules, 12345, "8.8.8.8", 53, 1));
    let second = expect_snat_decision(tuple_snat_lookup(&rules, 12345, "1.1.1.1", 443, 2));

    assert_eq!(first.rewrite_src, second.rewrite_src);
    assert_eq!(first.rewrite_src_port, second.rewrite_src_port);

    let status = source_nat_pool_statuses(&rules);
    assert_eq!(status[0].allocations_total, 1);
    assert_eq!(status[0].reuses_total, 1);
    assert_eq!(status[0].persistent_leases, 1);
    assert_eq!(status[0].live_flows, 2);
    assert_persistent_expiry_indexes_consistent(&rules[0]);
}

#[test]
fn pool_snat_persistent_reassigns_after_timeout() {
    let rules = persistent_pool_rules(2, 40000, 40001);
    let first = expect_snat_decision(tuple_snat_lookup(
        &rules,
        12345,
        "8.8.8.8",
        53,
        1_000_000_000,
    ));
    release_source_nat_allocation(
        &rules,
        &session_key(12345, "8.8.8.8", 53),
        first,
        false,
        2_000_000_000,
    );

    let reused = expect_snat_decision(tuple_snat_lookup(
        &rules,
        12345,
        "1.1.1.1",
        443,
        3_000_000_000,
    ));
    assert_eq!(first.rewrite_src_port, reused.rewrite_src_port);
    release_source_nat_allocation(
        &rules,
        &session_key(12345, "1.1.1.1", 443),
        reused,
        false,
        3_500_000_000,
    );

    let reassigned = expect_snat_decision(tuple_snat_lookup(
        &rules,
        12345,
        "9.9.9.9",
        853,
        6_000_000_000,
    ));
    assert_eq!(reassigned.rewrite_src, first.rewrite_src);
    assert_ne!(reassigned.rewrite_src_port, first.rewrite_src_port);
    assert_persistent_expiry_indexes_consistent(&rules[0]);
}

#[test]
fn pool_snat_persistent_compatible_refresh_preserves_lease_state() {
    let snapshot = persistent_pool_snapshot(300, 40000, 40001, vec!["203.0.113.10"], false);
    let rules = parse_source_nat_rules(&[snapshot.clone()]);
    let first = expect_snat_decision(tuple_snat_lookup(&rules, 12345, "8.8.8.8", 53, 1));
    release_source_nat_allocation(&rules, &session_key(12345, "8.8.8.8", 53), first, false, 2);

    let before = source_nat_pool_statuses(&rules);
    assert_eq!(before[0].live_flows, 0);
    assert_eq!(before[0].used_ports, 1);
    assert_eq!(before[0].persistent_leases, 1);
    assert_eq!(before[0].allocations_total, 1);
    assert_eq!(before[0].reuses_total, 0);

    let refreshed = parse_source_nat_rules_with_previous(&[snapshot], Some(&rules));
    let after_refresh = source_nat_pool_statuses(&refreshed);
    assert_eq!(after_refresh[0].live_flows, 0);
    assert_eq!(after_refresh[0].used_ports, 1);
    assert_eq!(after_refresh[0].persistent_leases, 1);
    assert_eq!(after_refresh[0].allocations_total, 1);
    assert_eq!(after_refresh[0].reuses_total, 0);

    let reused = expect_snat_decision(tuple_snat_lookup(&refreshed, 12345, "1.1.1.1", 443, 3));
    assert_eq!(reused.rewrite_src, first.rewrite_src);
    assert_eq!(reused.rewrite_src_port, first.rewrite_src_port);

    let after_reuse = source_nat_pool_statuses(&refreshed);
    assert_eq!(after_reuse[0].live_flows, 1);
    assert_eq!(after_reuse[0].used_ports, 1);
    assert_eq!(after_reuse[0].persistent_leases, 1);
    assert_eq!(after_reuse[0].allocations_total, 1);
    assert_eq!(after_reuse[0].reuses_total, 1);
    assert_persistent_expiry_indexes_consistent(&refreshed[0]);
}

#[test]
fn pool_snat_persistent_helper_restart_resets_lease_state() {
    let snapshot = persistent_pool_snapshot(300, 40000, 40001, vec!["203.0.113.10"], false);
    let rules = parse_source_nat_rules(&[snapshot.clone()]);
    let first = expect_snat_decision(tuple_snat_lookup(&rules, 12345, "8.8.8.8", 53, 1));
    release_source_nat_allocation(&rules, &session_key(12345, "8.8.8.8", 53), first, false, 2);

    let before = source_nat_pool_statuses(&rules);
    assert_eq!(before[0].live_flows, 0);
    assert_eq!(before[0].used_ports, 1);
    assert_eq!(before[0].persistent_leases, 1);
    assert_eq!(before[0].allocations_total, 1);

    // A helper restart has no previous in-process allocator to reuse. The
    // lease table and allocator counters reset even when the snapshot is
    // byte-identical.
    let restarted = parse_source_nat_rules(&[snapshot]);
    let reset = source_nat_pool_statuses(&restarted);
    assert_eq!(reset[0].live_flows, 0);
    assert_eq!(reset[0].used_ports, 0);
    assert_eq!(reset[0].persistent_leases, 0);
    assert_eq!(reset[0].allocations_total, 0);
    assert_eq!(reset[0].reuses_total, 0);
    assert_eq!(reset[0].exhaustion_total, 0);

    let fresh = expect_snat_decision(tuple_snat_lookup(&restarted, 12345, "1.1.1.1", 443, 3));
    assert_eq!(fresh.rewrite_src, Some("203.0.113.10".parse().unwrap()));
    assert!(fresh.rewrite_src_port.is_some());

    let after_fresh = source_nat_pool_statuses(&restarted);
    assert_eq!(after_fresh[0].live_flows, 1);
    assert_eq!(after_fresh[0].used_ports, 1);
    assert_eq!(after_fresh[0].persistent_leases, 1);
    assert_eq!(after_fresh[0].allocations_total, 1);
    assert_eq!(after_fresh[0].reuses_total, 0);
    assert_persistent_expiry_indexes_consistent(&restarted[0]);
}

#[test]
fn pool_snat_allocator_exhausted_counter_increments() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "tiny-snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "tiny-pool".to_string(),
        pool_addresses: vec!["203.0.113.10".to_string()],
        port_low: 40000,
        port_high: 40000,
        ..SourceNATRuleSnapshot::default()
    }]);

    let first = tuple_snat_lookup(&rules, 10000, "8.8.8.8", 53, 1);
    assert!(matches!(first, SourceNatLookup::Matched(_)));
    let second = tuple_snat_lookup(&rules, 10001, "1.1.1.1", 53, 2);
    assert_eq!(
        second,
        SourceNatLookup::Unavailable(SourceNatFailure {
            rule_name: "tiny-snat".to_string(),
            pool_name: "tiny-pool".to_string(),
            reason: SourceNatFailureReason::AllocatorExhausted,
        })
    );

    let status = source_nat_pool_statuses(&rules);
    assert_eq!(status[0].used_ports, 1);
    assert_eq!(status[0].live_flows, 1);
    assert_eq!(status[0].exhaustion_total, 1);
}

#[test]
fn pool_snat_shared_pool_exhaustion_crosses_rules() {
    let rules = parse_source_nat_rules(&[
        SourceNATRuleSnapshot {
            name: "rule-a".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["10.0.1.0/24".to_string()],
            pool_name: "shared-pool".to_string(),
            pool_addresses: vec!["203.0.113.10".to_string()],
            port_low: 40000,
            port_high: 40000,
            ..SourceNATRuleSnapshot::default()
        },
        SourceNATRuleSnapshot {
            name: "rule-b".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["10.0.2.0/24".to_string()],
            pool_name: "shared-pool".to_string(),
            pool_addresses: vec!["203.0.113.10".to_string()],
            port_low: 40000,
            port_high: 40000,
            ..SourceNATRuleSnapshot::default()
        },
    ]);

    let first = match_source_nat_result_for_tuple(
        &rules,
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        6,
        10000,
        53,
        None,
        None,
        1,
        false,
    );
    assert!(matches!(first, SourceNatLookup::Matched(_)));

    let second = match_source_nat_result_for_tuple(
        &rules,
        "lan",
        "wan",
        "10.0.2.100".parse().unwrap(),
        "1.1.1.1".parse().unwrap(),
        6,
        10001,
        53,
        None,
        None,
        2,
        false,
    );
    assert_eq!(
        second,
        SourceNatLookup::Unavailable(SourceNatFailure {
            rule_name: "rule-b".to_string(),
            pool_name: "shared-pool".to_string(),
            reason: SourceNatFailureReason::AllocatorExhausted,
        })
    );

    let status = source_nat_pool_statuses(&rules);
    assert_eq!(status[0].used_ports, 1);
    assert_eq!(status[1].used_ports, 1);
    assert_eq!(status[0].exhaustion_total, 1);
    assert_eq!(status[1].exhaustion_total, 1);
}

#[test]
fn pool_snat_shared_pool_exhaustion_crosses_persistence_modes() {
    let rules = parse_source_nat_rules(&[
        SourceNATRuleSnapshot {
            name: "persistent-rule".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["10.0.1.0/24".to_string()],
            pool_name: "shared-pool".to_string(),
            pool_addresses: vec!["203.0.113.10".to_string()],
            port_low: 40000,
            port_high: 40000,
            persistent_nat: true,
            persistent_nat_permit_any_remote_host: true,
            ..SourceNATRuleSnapshot::default()
        },
        SourceNATRuleSnapshot {
            name: "plain-rule".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["10.0.2.0/24".to_string()],
            pool_name: "shared-pool".to_string(),
            pool_addresses: vec!["203.0.113.10".to_string()],
            port_low: 40000,
            port_high: 40000,
            ..SourceNATRuleSnapshot::default()
        },
    ]);

    let first = match_source_nat_result_for_tuple(
        &rules,
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        6,
        10000,
        53,
        None,
        None,
        1,
        false,
    );
    assert!(matches!(first, SourceNatLookup::Matched(_)));

    let second = match_source_nat_result_for_tuple(
        &rules,
        "lan",
        "wan",
        "10.0.2.100".parse().unwrap(),
        "1.1.1.1".parse().unwrap(),
        6,
        10001,
        53,
        None,
        None,
        2,
        false,
    );
    assert_eq!(
        second,
        SourceNatLookup::Unavailable(SourceNatFailure {
            rule_name: "plain-rule".to_string(),
            pool_name: "shared-pool".to_string(),
            reason: SourceNatFailureReason::AllocatorExhausted,
        })
    );
}

#[test]
fn pool_snat_release_after_failed_session_install_frees_tuple() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "tiny-snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "tiny-pool".to_string(),
        pool_addresses: vec!["203.0.113.10".to_string()],
        port_low: 40000,
        port_high: 40000,
        ..SourceNATRuleSnapshot::default()
    }]);

    let first = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "8.8.8.8", 53, 1));
    release_source_nat_allocation(&rules, &session_key(10000, "8.8.8.8", 53), first, false, 2);

    let second = expect_snat_decision(tuple_snat_lookup(&rules, 10001, "1.1.1.1", 53, 3));
    assert_eq!(second.rewrite_src, first.rewrite_src);
    assert_eq!(second.rewrite_src_port, first.rewrite_src_port);
}

#[test]
fn pool_snat_persistent_rollback_removes_fresh_lease() {
    let rules = persistent_pool_rules(300, 40000, 40000);
    let first = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "8.8.8.8", 53, 1));

    rollback_source_nat_allocation(&rules, &session_key(10000, "8.8.8.8", 53), first, false, 2);

    let status = source_nat_pool_statuses(&rules);
    assert_eq!(status[0].live_flows, 0);
    assert_eq!(status[0].used_ports, 0);
    assert_eq!(status[0].persistent_leases, 0);
    assert_persistent_expiry_indexes_consistent(&rules[0]);

    let second = expect_snat_decision(tuple_snat_lookup(&rules, 10001, "1.1.1.1", 53, 3));
    assert_eq!(second.rewrite_src, first.rewrite_src);
    assert_eq!(second.rewrite_src_port, first.rewrite_src_port);
}

#[test]
fn pool_snat_persistent_rollback_keeps_lease_reused_by_another_flow() {
    let rules = persistent_pool_rules(300, 40000, 40001);
    let first = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "8.8.8.8", 53, 1));
    let second = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "1.1.1.1", 53, 2));
    assert_eq!(second.rewrite_src, first.rewrite_src);
    assert_eq!(second.rewrite_src_port, first.rewrite_src_port);

    rollback_source_nat_allocation(&rules, &session_key(10000, "8.8.8.8", 53), first, false, 3);

    let status = source_nat_pool_statuses(&rules);
    assert_eq!(status[0].live_flows, 1);
    assert_eq!(status[0].used_ports, 1);
    assert_eq!(status[0].persistent_leases, 1);
    {
        let live = rules[0]
            .pool_allocator
            .debug_live();
        let lease = live.persistent_by_source.values().next().unwrap();
        assert_eq!(lease.active_flows, 1);
        assert!(live.lease_expirations.is_empty());
        assert!(live.lease_expirations_by_addr[0].is_empty());
    }

    let third = expect_snat_decision(tuple_snat_lookup(&rules, 10001, "9.9.9.9", 53, 4));
    assert_ne!(third.rewrite_src_port, first.rewrite_src_port);
}

#[test]
fn pool_snat_persistent_rollback_preserves_lease_after_reuser_release() {
    let rules = persistent_pool_rules(300, 40000, 40001);
    let first = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "8.8.8.8", 53, 1));
    let second = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "1.1.1.1", 53, 2));
    assert_eq!(second.rewrite_src, first.rewrite_src);
    assert_eq!(second.rewrite_src_port, first.rewrite_src_port);

    release_source_nat_allocation(&rules, &session_key(10000, "1.1.1.1", 53), second, false, 3);
    rollback_source_nat_allocation(&rules, &session_key(10000, "8.8.8.8", 53), first, false, 4);

    let status = source_nat_pool_statuses(&rules);
    assert_eq!(status[0].live_flows, 0);
    assert_eq!(status[0].used_ports, 1);
    assert_eq!(status[0].persistent_leases, 1);
    {
        let live = rules[0]
            .pool_allocator
            .debug_live();
        let lease = live.persistent_by_source.values().next().unwrap();
        assert_eq!(lease.active_flows, 0);
        assert_eq!(lease.completed_flows, 1);
        assert_eq!(live.lease_expirations.len(), 1);
        assert_eq!(live.lease_expirations_by_addr[0].len(), 1);
    }

    let third = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "9.9.9.9", 53, 5));
    assert_eq!(third.rewrite_src, first.rewrite_src);
    assert_eq!(third.rewrite_src_port, first.rewrite_src_port);
}

#[test]
fn pool_snat_persistent_double_rollback_removes_unused_lease() {
    let rules = persistent_pool_rules(300, 40000, 40001);
    let first = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "8.8.8.8", 53, 1));
    let second = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "1.1.1.1", 53, 2));
    assert_eq!(second.rewrite_src, first.rewrite_src);
    assert_eq!(second.rewrite_src_port, first.rewrite_src_port);

    rollback_source_nat_allocation(&rules, &session_key(10000, "8.8.8.8", 53), first, false, 3);
    rollback_source_nat_allocation(&rules, &session_key(10000, "1.1.1.1", 53), second, false, 4);

    let status = source_nat_pool_statuses(&rules);
    assert_eq!(status[0].live_flows, 0);
    assert_eq!(status[0].used_ports, 0);
    assert_eq!(status[0].persistent_leases, 0);
    {
        let live = rules[0]
            .pool_allocator
            .debug_live();
        assert!(live.persistent_by_source.is_empty());
        assert!(live.lease_expirations.is_empty());
        assert!(live.lease_expirations_by_addr[0].is_empty());
        assert_eq!(live.recycled_ports_by_addr[0], vec![40000]);
    }
}

#[test]
fn pool_snat_persistent_reactivation_uses_fresh_expiry_after_success() {
    let rules = persistent_pool_rules(300, 40000, 40001);
    let timeout_ns = 300 * NS_PER_SEC;
    let original = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "8.8.8.8", 53, 1));
    release_source_nat_allocation(
        &rules,
        &session_key(10000, "8.8.8.8", 53),
        original,
        false,
        2,
    );

    let old_expiry = 2 + timeout_ns;
    {
        let live = rules[0]
            .pool_allocator
            .debug_live();
        let lease = live.persistent_by_source.values().next().unwrap();
        assert_eq!(lease.expires_at_ns, old_expiry);
        assert!(live
            .lease_expirations
            .contains(&(old_expiry, lease_key(10000))));
    }

    let first = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "1.1.1.1", 53, 3));
    let second = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "9.9.9.9", 53, 4));
    assert_eq!(second.rewrite_src, first.rewrite_src);
    assert_eq!(second.rewrite_src_port, first.rewrite_src_port);

    release_source_nat_allocation(
        &rules,
        &session_key(10000, "9.9.9.9", 53),
        second,
        false,
        5,
    );
    rollback_source_nat_allocation(
        &rules,
        &session_key(10000, "1.1.1.1", 53),
        first,
        false,
        6,
    );

    let fresh_expiry = 6 + timeout_ns;
    let status = source_nat_pool_statuses(&rules);
    assert_eq!(status[0].live_flows, 0);
    assert_eq!(status[0].used_ports, 1);
    assert_eq!(status[0].persistent_leases, 1);
    {
        let live = rules[0]
            .pool_allocator
            .debug_live();
        let lease = live.persistent_by_source.values().next().unwrap();
        assert_eq!(lease.active_flows, 0);
        assert_eq!(lease.completed_flows, 2);
        assert_eq!(lease.expires_at_ns, fresh_expiry);
        assert_eq!(live.lease_expirations.len(), 1);
        assert!(live
            .lease_expirations
            .contains(&(fresh_expiry, lease_key(10000))));
        assert!(!live
            .lease_expirations
            .contains(&(old_expiry, lease_key(10000))));
    }
}

#[test]
fn pool_snat_persistent_reactivation_completion_survives_saturated_counter() {
    let rules = persistent_pool_rules(300, 40000, 40001);
    let timeout_ns = 300 * NS_PER_SEC;
    let original = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "8.8.8.8", 53, 1));
    release_source_nat_allocation(
        &rules,
        &session_key(10000, "8.8.8.8", 53),
        original,
        false,
        2,
    );

    let old_expiry = 2 + timeout_ns;
    {
        let mut live = rules[0]
            .pool_allocator
            .debug_live();
        let lease = live.persistent_by_source.values_mut().next().unwrap();
        lease.completed_flows = u64::MAX;
        assert_eq!(lease.expires_at_ns, old_expiry);
    }

    let first = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "1.1.1.1", 53, 3));
    let second = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "9.9.9.9", 53, 4));
    assert_eq!(second.rewrite_src, first.rewrite_src);
    assert_eq!(second.rewrite_src_port, first.rewrite_src_port);

    release_source_nat_allocation(
        &rules,
        &session_key(10000, "9.9.9.9", 53),
        second,
        false,
        5,
    );
    rollback_source_nat_allocation(
        &rules,
        &session_key(10000, "1.1.1.1", 53),
        first,
        false,
        6,
    );

    let fresh_expiry = 6 + timeout_ns;
    {
        let live = rules[0]
            .pool_allocator
            .debug_live();
        let lease = live.persistent_by_source.values().next().unwrap();
        assert_eq!(lease.active_flows, 0);
        assert_eq!(lease.completed_flows, u64::MAX);
        assert_eq!(lease.expires_at_ns, fresh_expiry);
        assert!(live
            .lease_expirations
            .contains(&(fresh_expiry, lease_key(10000))));
        assert!(!live
            .lease_expirations
            .contains(&(old_expiry, lease_key(10000))));
    }
}

#[test]
fn pool_snat_persistent_reactivation_double_rollback_restores_old_expiry() {
    let rules = persistent_pool_rules(300, 40000, 40001);
    let timeout_ns = 300 * NS_PER_SEC;
    let original = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "8.8.8.8", 53, 1));
    release_source_nat_allocation(
        &rules,
        &session_key(10000, "8.8.8.8", 53),
        original,
        false,
        2,
    );

    let old_expiry = 2 + timeout_ns;
    let first = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "1.1.1.1", 53, 3));
    let second = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "9.9.9.9", 53, 4));
    assert_eq!(second.rewrite_src, first.rewrite_src);
    assert_eq!(second.rewrite_src_port, first.rewrite_src_port);

    rollback_source_nat_allocation(
        &rules,
        &session_key(10000, "1.1.1.1", 53),
        first,
        false,
        5,
    );
    rollback_source_nat_allocation(
        &rules,
        &session_key(10000, "9.9.9.9", 53),
        second,
        false,
        6,
    );

    let status = source_nat_pool_statuses(&rules);
    assert_eq!(status[0].live_flows, 0);
    assert_eq!(status[0].used_ports, 1);
    assert_eq!(status[0].persistent_leases, 1);
    {
        let live = rules[0]
            .pool_allocator
            .debug_live();
        let lease = live.persistent_by_source.values().next().unwrap();
        assert_eq!(lease.active_flows, 0);
        assert_eq!(lease.completed_flows, 1);
        assert_eq!(lease.expires_at_ns, old_expiry);
        assert_eq!(live.lease_expirations.len(), 1);
        assert!(live
            .lease_expirations
            .contains(&(old_expiry, lease_key(10000))));
    }
}

#[test]
fn pool_snat_release_uses_rewritten_dnat_destination_key() {
    let rules = persistent_pool_rules(300, 40000, 40000);
    let translated_dst: IpAddr = "10.0.0.5".parse().unwrap();
    let first = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "10.0.0.5", 443, 1));
    let mut nat = first;
    nat.rewrite_dst = Some(translated_dst);

    release_source_nat_allocation(
        &rules,
        &session_key(10000, "198.51.100.5", 443),
        nat,
        false,
        2,
    );

    let status = source_nat_pool_statuses(&rules);
    assert_eq!(status[0].live_flows, 0);
    assert_eq!(status[0].used_ports, 1);
    assert_eq!(status[0].persistent_leases, 1);
    assert_persistent_expiry_indexes_consistent(&rules[0]);
}

#[test]
fn pool_snat_persistent_expiry_index_is_bounded_by_leases() {
    let rules = persistent_pool_rules(300, 40000, 40000);
    for i in 0..10 {
        let now_ns = 1_000_000_000 + i * 10_000_000;
        let decision =
            expect_snat_decision(tuple_snat_lookup(&rules, 10000, "8.8.8.8", 53, now_ns));
        release_source_nat_allocation(
            &rules,
            &session_key(10000, "8.8.8.8", 53),
            decision,
            false,
            now_ns + 1,
        );
    }

    let live = rules[0]
        .pool_allocator
        .debug_live();
    assert_eq!(live.persistent_by_source.len(), 1);
    assert_eq!(live.lease_expirations.len(), 1);
    assert_eq!(live.lease_expirations_by_addr[0].len(), 1);
    drop(live);
    assert_persistent_expiry_indexes_consistent(&rules[0]);
}

#[test]
#[should_panic(expected = "global persistent expiry index mismatch")]
fn pool_snat_expiry_invariant_rejects_stale_global_entry() {
    let rules = persistent_pool_rules(300, 40000, 40000);
    let decision =
        expect_snat_decision(tuple_snat_lookup(&rules, 10000, "8.8.8.8", 53, 1_000));
    release_source_nat_allocation(
        &rules,
        &session_key(10000, "8.8.8.8", 53),
        decision,
        false,
        2_000,
    );
    {
        let mut live = rules[0]
            .pool_allocator
            .debug_live();
        let (key, lease) = live
            .persistent_by_source
            .iter()
            .next()
            .map(|(key, lease)| (*key, *lease))
            .unwrap();
        live.lease_expirations
            .insert((lease.expires_at_ns + 1, key));
    }

    assert_persistent_expiry_indexes_consistent(&rules[0]);
}

#[test]
#[should_panic(expected = "per-address persistent expiry index mismatch")]
fn pool_snat_expiry_invariant_rejects_stale_per_address_entry() {
    let rules = persistent_pool_rules(300, 40000, 40000);
    let decision =
        expect_snat_decision(tuple_snat_lookup(&rules, 10000, "8.8.8.8", 53, 1_000));
    release_source_nat_allocation(
        &rules,
        &session_key(10000, "8.8.8.8", 53),
        decision,
        false,
        2_000,
    );
    {
        let mut live = rules[0]
            .pool_allocator
            .debug_live();
        let (key, lease) = live
            .persistent_by_source
            .iter()
            .next()
            .map(|(key, lease)| (*key, *lease))
            .unwrap();
        live.lease_expirations_by_addr[lease.addr_index]
            .insert((lease.expires_at_ns + 1, key));
    }

    assert_persistent_expiry_indexes_consistent(&rules[0]);
}

#[test]
#[should_panic(expected = "persistent lease addr index mismatch")]
fn pool_snat_expiry_invariant_rejects_wrong_addr_index() {
    let rules = persistent_pool_rules_with_options(
        300,
        40000,
        40000,
        vec!["203.0.113.10", "203.0.113.11"],
        false,
    );
    let decision =
        expect_snat_decision(tuple_snat_lookup(&rules, 10000, "8.8.8.8", 53, 1_000));
    release_source_nat_allocation(
        &rules,
        &session_key(10000, "8.8.8.8", 53),
        decision,
        false,
        2_000,
    );
    {
        let mut live = rules[0]
            .pool_allocator
            .debug_live();
        let (key, lease) = live
            .persistent_by_source
            .iter()
            .next()
            .map(|(key, lease)| (*key, *lease))
            .unwrap();
        let wrong_addr_index = if lease.addr_index == 0 { 1 } else { 0 };
        let entry = (lease.expires_at_ns, key);
        live.lease_expirations_by_addr[lease.addr_index].remove(&entry);
        live.lease_expirations_by_addr[wrong_addr_index].insert(entry);
        live.persistent_by_source.insert(
            key,
            PersistentLease {
                addr_index: wrong_addr_index,
                ..lease
            },
        );
    }

    assert_persistent_expiry_indexes_consistent(&rules[0]);
}

#[test]
fn pool_snat_persistent_release_replaces_stale_expiry_tuple() {
    let rules = persistent_pool_rules(300, 40000, 40000);
    let decision =
        expect_snat_decision(tuple_snat_lookup(&rules, 10000, "8.8.8.8", 53, 1_000));
    let stale_expires_at_ns = {
        let mut live = rules[0]
            .pool_allocator
            .debug_live();
        let (key, lease) = live
            .persistent_by_source
            .iter()
            .next()
            .map(|(key, lease)| (*key, *lease))
            .unwrap();
        assert_eq!(lease.active_flows, 1);
        live.lease_expirations.insert((lease.expires_at_ns, key));
        live.lease_expirations_by_addr[lease.addr_index].insert((lease.expires_at_ns, key));
        lease.expires_at_ns
    };

    release_source_nat_allocation(
        &rules,
        &session_key(10000, "8.8.8.8", 53),
        decision,
        false,
        2_000,
    );

    let live = rules[0]
        .pool_allocator
        .debug_live();
    let (key, lease) = live
        .persistent_by_source
        .iter()
        .next()
        .map(|(key, lease)| (*key, *lease))
        .unwrap();
    assert_ne!(lease.expires_at_ns, stale_expires_at_ns);
    assert_eq!(live.lease_expirations.len(), 1);
    assert!(live.lease_expirations.contains(&(lease.expires_at_ns, key)));
    assert!(!live.lease_expirations.contains(&(stale_expires_at_ns, key)));
    assert_eq!(live.lease_expirations_by_addr[lease.addr_index].len(), 1);
    assert!(
        live.lease_expirations_by_addr[lease.addr_index].contains(&(lease.expires_at_ns, key))
    );
    assert!(
        !live.lease_expirations_by_addr[lease.addr_index].contains(&(stale_expires_at_ns, key))
    );
}

#[test]
fn pool_snat_allocation_gc_is_bounded_when_not_under_pressure() {
    let rules = persistent_pool_rules(1, 40000, 40099);
    let expired_lease_count = ALLOCATION_GC_BUDGET + 12;
    for i in 0..expired_lease_count {
        let src_port = 10000 + i as u16;
        let now_ns = 1_000_000_000 + i as u64;
        let decision =
            expect_snat_decision(tuple_snat_lookup(&rules, src_port, "8.8.8.8", 53, now_ns));
        release_source_nat_allocation(
            &rules,
            &session_key(src_port, "8.8.8.8", 53),
            decision,
            false,
            now_ns + 1,
        );
    }

    let before = source_nat_pool_statuses(&rules);
    assert_eq!(before[0].persistent_leases, expired_lease_count as u64);

    let decision = expect_snat_decision(tuple_snat_lookup(
        &rules,
        20000,
        "1.1.1.1",
        53,
        5_000_000_000,
    ));
    assert_eq!(
        decision.rewrite_src_port,
        Some(40000 + expired_lease_count as u16)
    );

    let after = source_nat_pool_statuses(&rules);
    assert_eq!(
        after[0].persistent_leases,
        (expired_lease_count - ALLOCATION_GC_BUDGET + 1) as u64
    );
    let live = rules[0]
        .pool_allocator
        .debug_live();
    assert_eq!(
        live.lease_expirations.len(),
        expired_lease_count - ALLOCATION_GC_BUDGET
    );
    assert_eq!(
        live.lease_expirations_by_addr[0].len(),
        expired_lease_count - ALLOCATION_GC_BUDGET
    );
    drop(live);
    assert_persistent_expiry_indexes_consistent(&rules[0]);
}

#[test]
fn pool_snat_pressure_gc_reclaims_expired_lease_for_selected_address() {
    let rules = persistent_pool_rules_with_options(
        1,
        40000,
        40007,
        vec!["203.0.113.10", "203.0.113.11"],
        true,
    );
    let src_addr_0 = source_for_sticky_pool_index(0, 2);
    let src_addr_1 = source_for_sticky_pool_index(1, 2);

    for i in 0..ALLOCATION_GC_BUDGET {
        let src_port = 10000 + i as u16;
        let now_ns = 1_000_000_000 + i as u64;
        let decision = expect_snat_decision(tuple_snat_lookup_from_src(
            &rules,
            &src_addr_0,
            src_port,
            "8.8.8.8",
            53,
            now_ns,
        ));
        release_source_nat_allocation(
            &rules,
            &session_key_from_src(&src_addr_0, src_port, "8.8.8.8", 53),
            decision,
            false,
            now_ns + 1,
        );
    }
    for i in 0..ALLOCATION_GC_BUDGET {
        let src_port = 11000 + i as u16;
        let now_ns = 1_100_000_000 + i as u64;
        let decision = expect_snat_decision(tuple_snat_lookup_from_src(
            &rules,
            &src_addr_1,
            src_port,
            "8.8.4.4",
            53,
            now_ns,
        ));
        release_source_nat_allocation(
            &rules,
            &session_key_from_src(&src_addr_1, src_port, "8.8.4.4", 53),
            decision,
            false,
            now_ns + 1,
        );
    }

    {
        let live = rules[0]
            .pool_allocator
            .debug_live();
        assert_eq!(
            live.lease_expirations_by_addr[0].len(),
            ALLOCATION_GC_BUDGET
        );
        assert_eq!(
            live.lease_expirations_by_addr[1].len(),
            ALLOCATION_GC_BUDGET
        );
    }
    assert_persistent_expiry_indexes_consistent(&rules[0]);

    let decision = expect_snat_decision(tuple_snat_lookup_from_src(
        &rules,
        &src_addr_1,
        12000,
        "1.1.1.1",
        53,
        5_000_000_000,
    ));

    assert_eq!(decision.rewrite_src, Some("203.0.113.11".parse().unwrap()));
    assert!(matches!(decision.rewrite_src_port, Some(40000..=40007)));
    let live = rules[0]
        .pool_allocator
        .debug_live();
    assert_eq!(live.lease_expirations_by_addr[0].len(), 0);
    assert!(live.lease_expirations_by_addr[1].len() < ALLOCATION_GC_BUDGET);
    drop(live);
    assert_persistent_expiry_indexes_consistent(&rules[0]);
}

fn source_for_sticky_pool_index(want: usize, pool_len: usize) -> String {
    for octet in 1..=254 {
        let candidate = format!("10.0.1.{octet}");
        let ip = candidate.parse().unwrap();
        if sticky_pool_index(ip, pool_len) == want {
            return candidate;
        }
    }
    panic!("no source address found for sticky index {want}");
}

#[test]
fn pool_snat_wrong_family_pool_fails_closed_before_later_rule() {
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

    let lookup = match_source_nat_result(
        &rules,
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        None,
        None,
    );
    assert_eq!(
        lookup,
        SourceNatLookup::Unavailable(SourceNatFailure {
            rule_name: "wrong-family".to_string(),
            pool_name: "v6-only".to_string(),
            reason: SourceNatFailureReason::WrongAddressFamily,
        })
    );
}

#[test]
fn pool_snat_wrong_family_pool_fails_closed_when_no_later_rule_matches() {
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

    let lookup = match_source_nat_result(
        &rules,
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        None,
        None,
    );
    assert_eq!(
        lookup,
        SourceNatLookup::Unavailable(SourceNatFailure {
            rule_name: "wrong-family".to_string(),
            pool_name: "v6-only".to_string(),
            reason: SourceNatFailureReason::WrongAddressFamily,
        })
    );
}

#[test]
fn pool_snat_missing_pool_snapshot_fails_closed() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "missing".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "missing-pool".to_string(),
        pool_unusable: true,
        pool_unusable_reason: "missing_pool".to_string(),
        ..SourceNATRuleSnapshot::default()
    }]);

    let lookup = match_source_nat_result(
        &rules,
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        None,
        None,
    );
    assert_eq!(
        lookup,
        SourceNatLookup::Unavailable(SourceNatFailure {
            rule_name: "missing".to_string(),
            pool_name: "missing-pool".to_string(),
            reason: SourceNatFailureReason::MissingPool,
        })
    );
}

#[test]
fn pool_snat_empty_pool_fails_closed_instead_of_no_match() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "empty".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "empty-pool".to_string(),
        ..SourceNATRuleSnapshot::default()
    }]);

    let lookup = match_source_nat_result(
        &rules,
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        None,
        None,
    );
    assert_eq!(
        lookup,
        SourceNatLookup::Unavailable(SourceNatFailure {
            rule_name: "empty".to_string(),
            pool_name: "empty-pool".to_string(),
            reason: SourceNatFailureReason::EmptyPool,
        })
    );
}

#[test]
fn pool_snat_invalid_port_range_fails_closed() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "bad-ports".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "bad-port-pool".to_string(),
        pool_addresses: vec!["203.0.113.1".to_string()],
        port_low: 40000,
        port_high: 39999,
        ..SourceNATRuleSnapshot::default()
    }]);

    let lookup = match_source_nat_result(
        &rules,
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        None,
        None,
    );
    assert_eq!(
        lookup,
        SourceNatLookup::Unavailable(SourceNatFailure {
            rule_name: "bad-ports".to_string(),
            pool_name: "bad-port-pool".to_string(),
            reason: SourceNatFailureReason::InvalidPortRange,
        })
    );
}

#[test]
fn pool_snat_invalid_pool_address_fails_closed() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "bad-address".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "bad-address-pool".to_string(),
        pool_addresses: vec!["not-an-ip".to_string()],
        port_low: 1024,
        port_high: 65535,
        ..SourceNATRuleSnapshot::default()
    }]);

    let lookup = match_source_nat_result(
        &rules,
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        None,
        None,
    );
    assert_eq!(
        lookup,
        SourceNatLookup::Unavailable(SourceNatFailure {
            rule_name: "bad-address".to_string(),
            pool_name: "bad-address-pool".to_string(),
            reason: SourceNatFailureReason::InvalidPool,
        })
    );
}

#[test]
fn pool_snat_partially_invalid_pool_address_fails_closed() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "mixed-addresses".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "mixed-address-pool".to_string(),
        pool_addresses: vec!["203.0.113.1".to_string(), "not-an-ip".to_string()],
        port_low: 1024,
        port_high: 65535,
        ..SourceNATRuleSnapshot::default()
    }]);

    let lookup = match_source_nat_result(
        &rules,
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        None,
        None,
    );
    assert_eq!(
        lookup,
        SourceNatLookup::Unavailable(SourceNatFailure {
            rule_name: "mixed-addresses".to_string(),
            pool_name: "mixed-address-pool".to_string(),
            reason: SourceNatFailureReason::InvalidPool,
        })
    );
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
fn pool_snat_address_persistent_userspace_v1_selects_pool_addresses() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "userspace-v1-selection".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string(), "::/0".to_string()],
        pool_name: "userspace-v1-pool".to_string(),
        pool_addresses: vec![
            "203.0.113.10".to_string(),
            "203.0.113.11".to_string(),
            "203.0.113.12".to_string(),
            "203.0.113.13".to_string(),
            "2001:db8:ffff::10".to_string(),
            "2001:db8:ffff::11".to_string(),
            "2001:db8:ffff::12".to_string(),
            "2001:db8:ffff::13".to_string(),
        ],
        port_low: 40000,
        port_high: 40010,
        address_persistent: true,
        ..SourceNATRuleSnapshot::default()
    }]);

    let cases = [
        ("10.0.1.100", "8.8.8.8", 50000, "203.0.113.13"),
        ("10.0.1.101", "8.8.4.4", 50001, "203.0.113.10"),
        (
            "2001:db8::1",
            "2001:4860:4860::8888",
            50002,
            "2001:db8:ffff::12",
        ),
        (
            "fd00::1234",
            "2001:4860:4860::8844",
            50003,
            "2001:db8:ffff::11",
        ),
    ];

    for (src, dst, src_port, want_src) in cases {
        let decision = expect_snat_decision(match_source_nat_result_for_tuple(
            &rules,
            "lan",
            "wan",
            src.parse().unwrap(),
            dst.parse().unwrap(),
            6,
            src_port,
            443,
            None,
            None,
            0,
            false,
        ));

        assert_eq!(decision.rewrite_src, Some(want_src.parse().unwrap()));
        assert_eq!(decision.rewrite_src_port, Some(40000));
    }
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
    assert!(
        match_source_nat(
            &rules,
            "dmz", // wrong from_zone
            "wan",
            "10.0.1.100".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            None,
            None,
        )
        .is_none()
    );
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
    assert_eq!(alloc.try_next_port(0), Ok(5000));
    assert_eq!(alloc.try_next_port(0), Ok(5001));
    assert_eq!(alloc.try_next_port(0), Ok(5002));
    assert_eq!(alloc.try_next_port(0), Ok(5000)); // wraps

    let mixed = PortAllocator::new(4, 5000, 5002);
    let src_v4 = "10.0.1.100".parse().unwrap();
    let src_v6 = "2001:db8::100".parse().unwrap();
    assert_eq!(mixed.address_index(src_v4, 0, 2, false), 0);
    assert_eq!(mixed.address_index(src_v6, 2, 2, false), 2);
    assert_eq!(mixed.address_index(src_v4, 0, 2, false), 1);
    assert_eq!(mixed.address_index(src_v6, 2, 2, false), 3);
}

#[test]
fn pool_snat_non_first_fragment_refused_no_allocation() {
    // #1852: a non-first fragment that would match a pool-mode SNAT rule
    // must be refused (Unavailable::NonFirstFragment) so no pool port is
    // allocated and no port is written into payload. The matching
    // first-fragment case (non_first_fragment=false) still allocates.
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

    // Non-first fragment: refused without allocating.
    let frag = match_source_nat_result_for_tuple(
        &rules,
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        6,
        10000,
        53,
        None,
        None,
        1,
        true,
    );
    match frag {
        SourceNatLookup::Unavailable(failure) => {
            assert_eq!(failure.exception_reason(), "source_nat_non_first_fragment");
        }
        other => panic!("expected NonFirstFragment refusal, got {other:?}"),
    }

    // First/atomic fragment (non_first_fragment=false): still allocates.
    let first = match_source_nat_result_for_tuple(
        &rules,
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        6,
        10000,
        53,
        None,
        None,
        1,
        false,
    );
    assert!(
        matches!(first, SourceNatLookup::Matched(d) if d.rewrite_src_port.is_some()),
        "first fragment must still allocate a pool mapping"
    );
}
