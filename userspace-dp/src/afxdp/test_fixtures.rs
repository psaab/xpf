use super::*;
use crate::test_zone_ids::*;
use crate::{
    FabricSnapshot, FirewallFilterSnapshot, FirewallTermSnapshot, InterfaceAddressSnapshot,
    InterfaceSnapshot, NeighborSnapshot, PolicyRuleSnapshot, RouteSnapshot, SourceNATRuleSnapshot,
    StaticNATRuleSnapshot, TunnelEndpointSnapshot, ZoneSnapshot,
};

pub(super) fn forwarding_snapshot(include_neighbor: bool) -> ConfigSnapshot {
    ConfigSnapshot {
        zones: vec![ZoneSnapshot {
            name: "wan".to_string(),
            id: TEST_WAN_ZONE_ID,
        }],
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/0.50".to_string(),
            zone: "wan".to_string(),
            linux_name: "ge-0-0-0.50".to_string(),
            ifindex: 12,
            hardware_addr: "02:bf:72:00:50:08".to_string(),
            addresses: vec![
                InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "172.16.50.8/24".to_string(),
                    scope: 0,
                },
                InterfaceAddressSnapshot {
                    family: "inet6".to_string(),
                    address: "2001:559:8585:50::8/64".to_string(),
                    scope: 0,
                },
            ],
            ..Default::default()
        }],
        routes: vec![
            RouteSnapshot {
                table: "inet.0".to_string(),
                family: "inet".to_string(),
                destination: "0.0.0.0/0".to_string(),
                next_hops: vec!["172.16.50.1@ge-0/0/0.50".to_string()],
                discard: false,
                next_table: String::new(),
            },
            RouteSnapshot {
                table: "inet6.0".to_string(),
                family: "inet6".to_string(),
                destination: "::/0".to_string(),
                next_hops: vec!["2001:559:8585:50::1@ge-0/0/0.50".to_string()],
                discard: false,
                next_table: String::new(),
            },
        ],
        neighbors: if include_neighbor {
            vec![
                NeighborSnapshot {
                    interface: "ge-0-0-0.50".to_string(),
                    ifindex: 12,
                    family: "inet".to_string(),
                    ip: "172.16.50.1".to_string(),
                    mac: "00:11:22:33:44:55".to_string(),
                    state: "reachable".to_string(),
                    router: true,
                    link_local: false,
                },
                NeighborSnapshot {
                    interface: "ge-0-0-0.50".to_string(),
                    ifindex: 12,
                    family: "inet6".to_string(),
                    ip: "2001:559:8585:50::1".to_string(),
                    mac: "00:11:22:33:44:55".to_string(),
                    state: "reachable".to_string(),
                    router: true,
                    link_local: false,
                },
            ]
        } else {
            vec![]
        },
        source_nat_rules: vec![SourceNATRuleSnapshot {
            name: "snat".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string(), "::/0".to_string()],
            interface_mode: true,
            ..Default::default()
        }],
        ..Default::default()
    }
}

pub(super) fn native_gre_snapshot(include_neighbor: bool) -> ConfigSnapshot {
    ConfigSnapshot {
        zones: vec![
            ZoneSnapshot {
                name: "wan".to_string(),
                id: TEST_WAN_ZONE_ID,
            },
            ZoneSnapshot {
                name: "sfmix".to_string(),
                id: TEST_SFMIX_ZONE_ID,
            },
        ],
        interfaces: vec![
            InterfaceSnapshot {
                name: "reth0.80".to_string(),
                zone: "wan".to_string(),
                linux_name: "ge-0-0-2.80".to_string(),
                ifindex: 12,
                parent_ifindex: 6,
                vlan_id: 80,
                mtu: 1500,
                redundancy_group: 1,
                hardware_addr: "02:bf:72:00:50:08".to_string(),
                addresses: vec![InterfaceAddressSnapshot {
                    family: "inet6".to_string(),
                    address: "2001:559:8585:80::8/64".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "gr-0/0/0.0".to_string(),
                zone: "sfmix".to_string(),
                linux_name: "gr-0-0-0".to_string(),
                ifindex: 362,
                mtu: 1476,
                redundancy_group: 1,
                tunnel: true,
                addresses: vec![InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "10.255.192.42/30".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
        ],
        tunnel_endpoints: vec![TunnelEndpointSnapshot {
            id: 1,
            interface: "gr-0/0/0.0".to_string(),
            linux_name: "gr-0-0-0".to_string(),
            ifindex: 362,
            zone: "sfmix".to_string(),
            redundancy_group: 1,
            mtu: 1476,
            mode: "gre".to_string(),
            outer_family: "inet6".to_string(),
            source: "2001:559:8585:80::8".to_string(),
            destination: "2602:ffd3:0:2::7".to_string(),
            key: 0,
            ttl: 64,
            transport_table: "inet6.0".to_string(),
        }],
        routes: vec![
            RouteSnapshot {
                table: "inet6.0".to_string(),
                family: "inet6".to_string(),
                destination: "2602:ffd3:0:2::/64".to_string(),
                next_hops: vec!["2001:559:8585:80::1@reth0.80".to_string()],
                discard: false,
                next_table: String::new(),
            },
            RouteSnapshot {
                table: "sfmix.inet.0".to_string(),
                family: "inet".to_string(),
                destination: "0.0.0.0/0".to_string(),
                next_hops: vec!["10.255.192.41".to_string()],
                discard: false,
                next_table: String::new(),
            },
        ],
        neighbors: if include_neighbor {
            vec![NeighborSnapshot {
                interface: "ge-0-0-2.80".to_string(),
                ifindex: 12,
                family: "inet6".to_string(),
                ip: "2001:559:8585:80::1".to_string(),
                mac: "00:11:22:33:44:55".to_string(),
                state: "reachable".to_string(),
                router: true,
                link_local: false,
            }]
        } else {
            vec![]
        },
        ..Default::default()
    }
}

pub(super) fn native_gre_pbr_snapshot(include_neighbor: bool) -> ConfigSnapshot {
    let mut snapshot = native_gre_snapshot(include_neighbor);
    snapshot.zones.insert(
        0,
        ZoneSnapshot {
            name: "lan".to_string(),
            id: TEST_LAN_ZONE_ID,
        },
    );
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "reth1.0".to_string(),
        zone: "lan".to_string(),
        linux_name: "ge-0-0-1".to_string(),
        ifindex: 5,
        filter_input_v4: "sfmix-pbr".to_string(),
        addresses: vec![InterfaceAddressSnapshot {
            family: "inet".to_string(),
            address: "10.0.61.1/24".to_string(),
            scope: 0,
        }],
        ..Default::default()
    });
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: "sfmix-pbr".to_string(),
        family: "inet".to_string(),
        terms: vec![
            FirewallTermSnapshot {
                name: "sfmix-route".to_string(),
                destination_addresses: vec!["10.255.192.40/30".to_string()],
                routing_instance: "sfmix".to_string(),
                ..Default::default()
            },
            FirewallTermSnapshot {
                name: "default".to_string(),
                action: "accept".to_string(),
                ..Default::default()
            },
        ],
    }];
    snapshot
}

pub(super) fn forwarding_snapshot_with_next_table(include_neighbor: bool) -> ConfigSnapshot {
    ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/0.50".to_string(),
            zone: "wan".to_string(),
            linux_name: "ge-0-0-0.50".to_string(),
            ifindex: 12,
            hardware_addr: "02:bf:72:00:50:08".to_string(),
            addresses: vec![
                InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "172.16.50.8/24".to_string(),
                    scope: 0,
                },
                InterfaceAddressSnapshot {
                    family: "inet6".to_string(),
                    address: "2001:559:8585:50::8/64".to_string(),
                    scope: 0,
                },
            ],
            ..Default::default()
        }],
        routes: vec![
            RouteSnapshot {
                table: "inet.0".to_string(),
                family: "inet".to_string(),
                destination: "8.8.8.0/24".to_string(),
                next_hops: vec![],
                discard: false,
                next_table: "blue.inet.0".to_string(),
            },
            RouteSnapshot {
                table: "blue.inet.0".to_string(),
                family: "inet".to_string(),
                destination: "8.8.8.0/24".to_string(),
                next_hops: vec!["172.16.50.1@ge-0/0/0.50".to_string()],
                discard: false,
                next_table: String::new(),
            },
            RouteSnapshot {
                table: "inet6.0".to_string(),
                family: "inet6".to_string(),
                destination: "2606:4700:4700::/48".to_string(),
                next_hops: vec![],
                discard: false,
                next_table: "blue.inet6.0".to_string(),
            },
            RouteSnapshot {
                table: "blue.inet6.0".to_string(),
                family: "inet6".to_string(),
                destination: "2606:4700:4700::/48".to_string(),
                next_hops: vec!["2001:559:8585:50::1@ge-0/0/0.50".to_string()],
                discard: false,
                next_table: String::new(),
            },
        ],
        neighbors: if include_neighbor {
            vec![
                NeighborSnapshot {
                    interface: "ge-0-0-0.50".to_string(),
                    ifindex: 12,
                    family: "inet".to_string(),
                    ip: "172.16.50.1".to_string(),
                    mac: "00:11:22:33:44:55".to_string(),
                    state: "reachable".to_string(),
                    router: true,
                    link_local: false,
                },
                NeighborSnapshot {
                    interface: "ge-0-0-0.50".to_string(),
                    ifindex: 12,
                    family: "inet6".to_string(),
                    ip: "2001:559:8585:50::1".to_string(),
                    mac: "00:11:22:33:44:55".to_string(),
                    state: "reachable".to_string(),
                    router: true,
                    link_local: false,
                },
            ]
        } else {
            vec![]
        },
        ..Default::default()
    }
}

pub(super) fn forwarding_snapshot_with_next_table_loop() -> ConfigSnapshot {
    ConfigSnapshot {
        routes: vec![RouteSnapshot {
            table: "inet.0".to_string(),
            family: "inet".to_string(),
            destination: "0.0.0.0/0".to_string(),
            next_hops: vec![],
            discard: false,
            next_table: "inet.0".to_string(),
        }],
        ..Default::default()
    }
}

pub(super) fn nat_snapshot() -> ConfigSnapshot {
    ConfigSnapshot {
        zones: vec![
            ZoneSnapshot {
                name: "lan".to_string(),
                id: TEST_LAN_ZONE_ID,
            },
            ZoneSnapshot {
                name: "wan".to_string(),
                id: TEST_WAN_ZONE_ID,
            },
        ],
        interfaces: vec![
            InterfaceSnapshot {
                name: "reth1.0".to_string(),
                zone: "lan".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                ifindex: 24,
                redundancy_group: 2,
                hardware_addr: "02:bf:72:01:00:01".to_string(),
                addresses: vec![
                    InterfaceAddressSnapshot {
                        family: "inet".to_string(),
                        address: "10.0.61.1/24".to_string(),
                        scope: 0,
                    },
                    InterfaceAddressSnapshot {
                        family: "inet6".to_string(),
                        address: "2001:559:8585:ef00::1/64".to_string(),
                        scope: 0,
                    },
                ],
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "reth0.80".to_string(),
                zone: "wan".to_string(),
                linux_name: "ge-0-0-0.80".to_string(),
                ifindex: 12,
                parent_ifindex: 11,
                redundancy_group: 1,
                vlan_id: 80,
                hardware_addr: "02:bf:72:00:80:08".to_string(),
                addresses: vec![
                    InterfaceAddressSnapshot {
                        family: "inet".to_string(),
                        address: "172.16.80.8/24".to_string(),
                        scope: 0,
                    },
                    InterfaceAddressSnapshot {
                        family: "inet6".to_string(),
                        address: "2001:559:8585:80::8/64".to_string(),
                        scope: 0,
                    },
                ],
                ..Default::default()
            },
        ],
        routes: vec![
            RouteSnapshot {
                table: "inet.0".to_string(),
                family: "inet".to_string(),
                destination: "0.0.0.0/0".to_string(),
                next_hops: vec!["172.16.80.1@reth0.80".to_string()],
                discard: false,
                next_table: String::new(),
            },
            RouteSnapshot {
                table: "inet6.0".to_string(),
                family: "inet6".to_string(),
                destination: "::/0".to_string(),
                next_hops: vec!["2001:559:8585:80::1@reth0.80".to_string()],
                discard: false,
                next_table: String::new(),
            },
        ],
        source_nat_rules: vec![
            SourceNATRuleSnapshot {
                name: "snat".to_string(),
                from_zone: "lan".to_string(),
                to_zone: "wan".to_string(),
                source_addresses: vec!["0.0.0.0/0".to_string()],
                interface_mode: true,
                ..Default::default()
            },
            SourceNATRuleSnapshot {
                name: "snat6".to_string(),
                from_zone: "lan".to_string(),
                to_zone: "wan".to_string(),
                source_addresses: vec!["::/0".to_string()],
                interface_mode: true,
                ..Default::default()
            },
        ],
        default_policy: "deny".to_string(),
        policies: vec![PolicyRuleSnapshot {
            name: "allow-all".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["any".to_string()],
            applications: vec!["any".to_string()],
            application_terms: Vec::new(),
            action: "permit".to_string(),
            ..Default::default()
        }],
        neighbors: vec![
            NeighborSnapshot {
                interface: "ge-0-0-0.80".to_string(),
                ifindex: 12,
                family: "inet".to_string(),
                ip: "172.16.80.1".to_string(),
                mac: "00:11:22:33:44:55".to_string(),
                state: "reachable".to_string(),
                router: true,
                link_local: false,
            },
            NeighborSnapshot {
                interface: "ge-0-0-0.80".to_string(),
                ifindex: 12,
                family: "inet6".to_string(),
                ip: "2001:559:8585:80::1".to_string(),
                mac: "00:11:22:33:44:55".to_string(),
                state: "reachable".to_string(),
                router: true,
                link_local: false,
            },
        ],
        ..Default::default()
    }
}

pub(super) fn nat_snapshot_with_fabric() -> ConfigSnapshot {
    let mut snapshot = nat_snapshot();
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "ge-0/0/0".to_string(),
        linux_name: "ge-0-0-0".to_string(),
        ifindex: 21,
        hardware_addr: "02:bf:72:ff:00:01".to_string(),
        ..Default::default()
    });
    snapshot.fabrics = vec![FabricSnapshot {
        name: "fab0".to_string(),
        parent_interface: "ge-0/0/0".to_string(),
        parent_linux_name: "ge-0-0-0".to_string(),
        parent_ifindex: 21,
        overlay_linux_name: "fab0".to_string(),
        overlay_ifindex: 101,
        rx_queues: 2,
        peer_address: "10.99.13.2".to_string(),
        local_mac: "02:bf:72:ff:00:01".to_string(),
        peer_mac: "00:aa:bb:cc:dd:ee".to_string(),
    }];
    snapshot.neighbors.push(NeighborSnapshot {
        interface: "fab0".to_string(),
        ifindex: 101,
        family: "inet".to_string(),
        ip: "10.99.13.2".to_string(),
        mac: "00:aa:bb:cc:dd:ee".to_string(),
        state: "reachable".to_string(),
        router: false,
        link_local: false,
    });
    snapshot
}

pub(super) fn policy_deny_snapshot() -> ConfigSnapshot {
    ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "reth1.0".to_string(),
                zone: "lan".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                ifindex: 24,
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "reth0.80".to_string(),
                zone: "wan".to_string(),
                linux_name: "ge-0-0-0.80".to_string(),
                ifindex: 12,
                parent_ifindex: 11,
                vlan_id: 80,
                hardware_addr: "02:bf:72:00:80:08".to_string(),
                addresses: vec![InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "172.16.80.8/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
        ],
        default_policy: "deny".to_string(),
        policies: vec![PolicyRuleSnapshot {
            name: "allow-other".to_string(),
            from_zone: "dmz".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["any".to_string()],
            applications: vec!["any".to_string()],
            application_terms: Vec::new(),
            action: "permit".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    }
}

pub(super) fn valid_meta() -> UserspaceDpMeta {
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        flow_src_port: 0x1234,
        flow_src_addr: [172, 16, 80, 200, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        flow_dst_addr: [172, 16, 80, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        config_generation: 11,
        fib_generation: 7,
        ..UserspaceDpMeta::default()
    }
}

pub(super) fn vlan_icmp_reply_frame() -> Vec<u8> {
    let mut frame = vec![
        0x02, 0xbf, 0x72, 0x16, 0x02, 0x00, 0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5, 0x81, 0x00, 0x00,
        0x50, 0x08, 0x00, 0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00,
        0xac, 0x10, 0x50, 0xc8, 0xac, 0x10, 0x50, 0x08, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00,
        0x01,
    ];
    frame.resize(98, 0);
    frame
}

pub(super) fn static_nat_snapshot() -> ConfigSnapshot {
    ConfigSnapshot {
        zones: vec![
            ZoneSnapshot {
                name: "trust".to_string(),
                id: TEST_TRUST_ZONE_ID,
            },
            ZoneSnapshot {
                name: "untrust".to_string(),
                id: TEST_UNTRUST_ZONE_ID,
            },
        ],
        interfaces: vec![
            InterfaceSnapshot {
                name: "ge-0/0/0".to_string(),
                zone: "trust".to_string(),
                linux_name: "ge-0-0-0".to_string(),
                ifindex: 5,
                hardware_addr: "02:bf:72:01:00:00".to_string(),
                addresses: vec![InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "192.168.1.1/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "ge-0/0/1".to_string(),
                zone: "untrust".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                ifindex: 6,
                hardware_addr: "02:bf:72:01:00:01".to_string(),
                addresses: vec![InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "203.0.113.1/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
        ],
        routes: vec![RouteSnapshot {
            table: "inet.0".to_string(),
            family: "inet".to_string(),
            destination: "0.0.0.0/0".to_string(),
            next_hops: vec!["203.0.113.254@ge-0/0/1".to_string()],
            discard: false,
            next_table: String::new(),
        }],
        static_nat_rules: vec![StaticNATRuleSnapshot {
            name: "web-server".to_string(),
            from_zone: "untrust".to_string(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
        }],
        default_policy: "deny".to_string(),
        policies: vec![
            PolicyRuleSnapshot {
                name: "allow-inbound".to_string(),
                from_zone: "untrust".to_string(),
                to_zone: "trust".to_string(),
                source_addresses: vec!["any".to_string()],
                destination_addresses: vec!["any".to_string()],
                applications: vec!["any".to_string()],
                action: "permit".to_string(),
                ..Default::default()
            },
            PolicyRuleSnapshot {
                name: "allow-outbound".to_string(),
                from_zone: "trust".to_string(),
                to_zone: "untrust".to_string(),
                source_addresses: vec!["any".to_string()],
                destination_addresses: vec!["any".to_string()],
                applications: vec!["any".to_string()],
                action: "permit".to_string(),
                ..Default::default()
            },
        ],
        neighbors: vec![
            NeighborSnapshot {
                interface: "ge-0-0-0".to_string(),
                ifindex: 5,
                family: "inet".to_string(),
                ip: "192.168.1.10".to_string(),
                mac: "aa:bb:cc:dd:ee:10".to_string(),
                state: "reachable".to_string(),
                ..Default::default()
            },
            NeighborSnapshot {
                interface: "ge-0-0-1".to_string(),
                ifindex: 6,
                family: "inet".to_string(),
                ip: "203.0.113.254".to_string(),
                mac: "aa:bb:cc:dd:ee:fe".to_string(),
                state: "reachable".to_string(),
                ..Default::default()
            },
        ],
        ..Default::default()
    }
}
