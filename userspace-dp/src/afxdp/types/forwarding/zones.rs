// Zone host-inbound admission types split from forwarding.rs
// (#16209): ZoneHostInbound and the multicast-group catalog helper.
// Pure code motion behind `forwarding/mod.rs`'s `use forwarding::*`
// glob; zero layout or access-site change.
// Visibility bill: no widening.

use super::super::*;

/// #3070/#3405: a zone's compiled host-inbound-traffic admission set. Built from
/// the raw Junos `system-services` / `protocols` tokens on the wire
/// (`ZoneSnapshot`) at config-apply time (`zone_host_inbound_from_snapshot`),
/// then read on the per-packet local-delivery admit path. At the map level an
/// absent `ZoneHostInbound` still means admit-all (the pre-#3070 behaviour) for
/// that zone id — but that no longer describes a configured no-stanza zone.
/// Post-#3405 the Go control plane sends HostInboundConfigured=true for EVERY
/// configured zone (security.go:70, zones.go:448), so a zone with NO
/// `host-inbound-traffic` stanza produces a PRESENT entry with an EMPTY token
/// set (`admits()` -> false for every service/protocol => default-DENY, Junos
/// parity). The absent-entry admit-all branch therefore now applies only to a
/// zone not present in the snapshot at all (legacy / truly-unconfigured).
/// Lifeline interfaces (fxp0/em0/fab*) never reach this classifier (#3682).
/// SSOT for the token semantics: docs/host-inbound-service-matrix.md.
///
/// Service tokens are classified to L4 signatures: TCP/UDP services contribute
/// destination ports; ICMP-bearing services (ping, router-discovery) contribute
/// the specific ICMP/ICMPv6 *types* they imply (#3201/#3240 — not the whole
/// protocol); the raw `protocols` routing tokens contribute an IP-protocol
/// number. `all_services` (Junos `any-service` ONLY — `system-services { all }`
/// is NOT a full admit since #3226, it expands to the named service union)
/// short-circuits to a full admit. `protocols { all }` is NOT a
/// blanket admit (#3199): it expands at classify time to the routing-protocol
/// signatures (ospf/bgp/rip/.../router-discovery), so it admits routing
/// protocols but never a system service (SSH/HTTPS/SNMP/...) that was not
/// separately permitted. An UNRECOGNISED token contributes nothing
/// (fail-closed: it does not broaden the admit set), so a host-bound packet
/// matching no listed service/protocol is denied.
#[derive(Clone, Debug, Default)]
pub(in crate::afxdp) struct ZoneHostInbound {
    /// `system-services { any-service }` — admit every host-bound packet
    /// regardless of service. Junos defines `any-service` as "all system
    /// services on an entire port range including the system services that are
    /// not defined", the explicit escape hatch for traffic the named set does
    /// not cover; xpf reads it as a superset (every IP protocol, not just the
    /// TCP/UDP port range), which is the fail-safe direction for a token whose
    /// purpose is to over-admit.
    ///
    /// #3226: `system-services { all }` NO LONGER sets this. Junos scopes `all`
    /// to "traffic from the defined system services available on the Routing
    /// Engine", so it now EXPANDS at classify time to the named-service
    /// signatures (`system_service_all_expansion`, host_inbound.rs) exactly as
    /// `protocols { all }` expands to the routing-protocol set (#3199).
    /// Previously `all` short-circuited here, so an `all` zone admitted every
    /// IP protocol — GRE/ESP/AH/OSPF/PIM/VRRP and arbitrary future protocol
    /// numbers — to its local addresses with no default deny.
    pub(in crate::afxdp) all_services: bool,
    /// Admitted TCP destination ports (ssh=22, https=443, bgp=179, ...).
    pub(in crate::afxdp) tcp_ports: FastSet<u16>,
    /// Admitted DUAL-FAMILY UDP destination ports (dns=53, ike=500/4500, ...).
    /// Family-specific UDP services live in `udp_ports_v4` / `udp_ports_v6`.
    pub(in crate::afxdp) udp_ports: FastSet<u16>,
    /// #3225: IPv4-ONLY admitted UDP ports (dhcp/bootp=67/68, rip=520). Consulted
    /// by `admits` only when the packet is IPv4, so a `system-services dhcp` zone
    /// does not open udp/67-68 on the IPv6 path.
    pub(in crate::afxdp) udp_ports_v4: FastSet<u16>,
    /// #3225: IPv6-ONLY admitted UDP ports (dhcpv6=546/547, ripng=521). Consulted
    /// by `admits` only when the packet is IPv6.
    pub(in crate::afxdp) udp_ports_v6: FastSet<u16>,
    /// #3201/#3240: admitted ICMPv4 *types* (not the whole protocol). A service
    /// contributes only the ICMP subtypes it implies — `ping` → echo-request
    /// (8); `router-discovery` → router-advertisement/solicitation (9, 10) —
    /// mirroring the kernel nft chain (`pkg/daemon/daemon_nft.go`
    /// `hostInboundServiceMatches` / `hostInboundProtocolMatches`), so the
    /// AF_XDP fast-path admit set equals the nft chain's per-service type set.
    /// ICMP *error* / PMTUD subtypes are admitted globally and unconditionally
    /// by `is_icmp_host_inbound_global_accept` (#3171), so they are NOT carried
    /// per-zone here.
    pub(in crate::afxdp) icmp_types_v4: FastSet<u8>,
    /// #3201/#3240: admitted ICMPv6 *types* — `ping` → echo-request (128).
    /// `router-discovery` adds nothing on v6 (RS/RA ride the globally-accepted
    /// ND set in `is_icmp_host_inbound_global_accept`, matching the nft chain
    /// which returns nil for v6 router-discovery).
    pub(in crate::afxdp) icmp_types_v6: FastSet<u8>,
    /// Admitted DUAL-FAMILY bare IP protocol numbers (gre=47, esp=50, ah=51,
    /// vrrp=112, pim=103, ...). Checked for non-TCP/UDP/ICMP packets.
    /// Family-specific protocols live in `ip_protocols_v4` / `ip_protocols_v6`.
    pub(in crate::afxdp) ip_protocols: FastSet<u8>,
    /// #3225: IPv4-ONLY admitted IP protocol numbers (ospf=OSPFv2=89, igmp=2).
    /// Consulted by `admits` only when the packet is IPv4.
    pub(in crate::afxdp) ip_protocols_v4: FastSet<u8>,
    /// #3225: IPv6-ONLY admitted IP protocol numbers (ospf3=OSPFv3=89). Consulted
    /// by `admits` only when the packet is IPv6, so a `protocols ospf` (v2) zone
    /// does not open proto 89 on IPv6 and vice versa.
    pub(in crate::afxdp) ip_protocols_v6: FastSet<u8>,
    /// #11571: per-token MULTICAST routing-protocol flags for exact
    /// catalog-group gating (`host_inbound_multicast_gate`,
    /// forwarding/host_inbound.rs). The port/proto/type sets above are
    /// transport-only: `igmp` and `dvmrp` both admit proto 2 on v4, and
    /// `ospf`/`ospf3` both ride proto 89, so the sets alone cannot tell
    /// which well-known GROUP each token owns (igmp -> 224.0.0.1/22,
    /// dvmrp -> 224.0.0.4, ospf -> v4 groups only, ospf3 -> v6 groups
    /// only). These flags preserve the token identity through classify so
    /// a catalog-group packet is admitted only on the exact
    /// group+family+transport+token tuple. Set alongside the transport
    /// sets in `classify_protocol` (including via the `protocols all`
    /// expansion, which recurses through it); consulted ONLY for dsts in
    /// the catalog — every other dst keeps the legacy transport-only
    /// `admits()` behavior byte-identically.
    pub(in crate::afxdp) mcast_ospf: bool,
    pub(in crate::afxdp) mcast_ospf3: bool,
    pub(in crate::afxdp) mcast_rip: bool,
    pub(in crate::afxdp) mcast_ripng: bool,
    pub(in crate::afxdp) mcast_pim: bool,
    pub(in crate::afxdp) mcast_igmp: bool,
    pub(in crate::afxdp) mcast_dvmrp: bool,
    pub(in crate::afxdp) mcast_vrrp: bool,
    pub(in crate::afxdp) mcast_router_discovery: bool,
    /// #15671: `protocols ndp except` authored — ND default withdrawn.
    pub(in crate::afxdp) ndp_excluded: bool,
    /// #15931: explicit `protocols ndp` (or `protocols all`, which
    /// expands to it) — ND admitted to catalog multicast groups as a
    /// positive token, distinct from the non-catalog default.
    pub(in crate::afxdp) ndp_positive: bool,
}

impl ZoneHostInbound {
    /// Returns true iff a host-bound packet with the given L4 protocol,
    /// destination port and (for ICMP/ICMPv6) type is admitted by this zone's
    /// host-inbound set. `icmp_type` is the first L4 byte for protocol 1 / 58
    /// and is ignored for every other protocol.
    pub(in crate::afxdp) fn admits(
        &self,
        protocol: u8,
        dst_port: u16,
        is_v6: bool,
        icmp_type: u8,
    ) -> bool {
        // Only `system-services { any-service }` is a full admit. NEITHER
        // `system-services { all }` (#3226) NOR `protocols { all }` (#3199) is
        // a blanket bypass: each expands to its concrete signatures at classify
        // time and is matched below via tcp/udp/icmp/ip_protocols, so a
        // `system-services all` zone can never admit a raw IP protocol
        // (GRE/ESP/OSPF/PIM/VRRP/...) that was not separately permitted, and a
        // `protocols all` zone can never admit a system service (SSH, HTTPS,
        // SNMP, ...) that was not separately permitted.
        if self.all_services {
            return true;
        }
        match protocol {
            // TCP
            6 => self.tcp_ports.contains(&dst_port),
            // UDP — dual-family ports OR the family-scoped set for this packet's
            // family (#3225: dhcp/rip are v4-only, dhcpv6/ripng v6-only).
            17 => {
                self.udp_ports.contains(&dst_port)
                    || if is_v6 {
                        self.udp_ports_v6.contains(&dst_port)
                    } else {
                        self.udp_ports_v4.contains(&dst_port)
                    }
            }
            // ICMPv4 — admit only the configured subtypes (#3201/#3240), e.g.
            // `ping` → echo-request (8), `router-discovery` → 9/10. Error /
            // PMTUD subtypes are admitted earlier by the global exemption.
            1 => self.icmp_types_v4.contains(&icmp_type),
            // ICMPv6 — admit only the configured subtypes (#3201/#3240).
            58 => self.icmp_types_v6.contains(&icmp_type),
            other => {
                // Bare IP protocol — dual-family OR the family-scoped set
                // (#3225: ospf=OSPFv2 v4-only, ospf3=OSPFv3 v6-only, igmp v4).
                self.ip_protocols.contains(&other)
                    || if is_v6 {
                        self.ip_protocols_v6.contains(&other)
                    } else {
                        self.ip_protocols_v4.contains(&other)
                    }
            }
        }
    }
    /// #15931: ND admission to a catalog multicast destination. The
    /// non-catalog ND default does not extend here (mirrors the kernel
    /// catalog-group guards); only an explicit ndp positive, or a full
    /// any-service admit, opens it. `ndp except` has already withdrawn
    /// the default at the caller.
    pub(in crate::afxdp) fn ndp_admits_multicast(&self) -> bool {
        self.all_services || self.ndp_positive
    }

    /// Admission predicate for a packet with its actual destination IP.
    ///
    /// The ordinary service/protocol sets above intentionally remain the
    /// admission model for non-catalog destinations. A destination in the
    /// well-known routing multicast catalog is different: transport alone is
    /// insufficient (`igmp` and `dvmrp` share protocol 2, while `ospf` and
    /// `ospf3` share protocol 89), so admission requires the exact catalog
    /// group, address family, transport, and effective protocol token.
    pub(in crate::afxdp) fn admits_destination(
        &self,
        protocol: u8,
        dst_port: u16,
        is_v6: bool,
        icmp_type: u8,
        dst_ip: IpAddr,
    ) -> bool {
        // Preserve Junos' explicit `any-service` wildcard on every destination.
        if self.all_services {
            return true;
        }

        if is_host_inbound_multicast_group(dst_ip) {
            if dst_ip.is_ipv6() != is_v6 {
                return false;
            }
            return match dst_ip {
                IpAddr::V4(group) => match group.octets() {
                    [224, 0, 0, 1] => {
                        (self.mcast_igmp && protocol == 2)
                            || (self.mcast_router_discovery
                                && protocol == 1
                                && matches!(icmp_type, 9 | 10))
                    }
                    [224, 0, 0, 2] => {
                        self.mcast_router_discovery && protocol == 1 && matches!(icmp_type, 9 | 10)
                    }
                    [224, 0, 0, 4] => self.mcast_dvmrp && protocol == 2,
                    [224, 0, 0, 5] | [224, 0, 0, 6] => self.mcast_ospf && protocol == 89,
                    [224, 0, 0, 9] => self.mcast_rip && protocol == 17 && dst_port == 520,
                    [224, 0, 0, 13] => self.mcast_pim && protocol == 103,
                    [224, 0, 0, 18] => self.mcast_vrrp && protocol == 112,
                    [224, 0, 0, 22] => self.mcast_igmp && protocol == 2,
                    _ => false,
                },
                IpAddr::V6(group) => match group.segments() {
                    [0xff02, 0, 0, 0, 0, 0, 0, 5] | [0xff02, 0, 0, 0, 0, 0, 0, 6] => {
                        self.mcast_ospf3 && protocol == 89
                    }
                    [0xff02, 0, 0, 0, 0, 0, 0, 9] => {
                        self.mcast_ripng && protocol == 17 && dst_port == 521
                    }
                    [0xff02, 0, 0, 0, 0, 0, 0, 13] => self.mcast_pim && protocol == 103,
                    [0xff02, 0, 0, 0, 0, 0, 0, 18] => self.mcast_vrrp && protocol == 112,
                    _ => false,
                },
            };
        }

        self.admits(protocol, dst_port, is_v6, icmp_type)
    }
}

/// Whether `dst_ip` is any address in the Rust mirror of
/// `config.HostInboundMulticastGroups`. Those groups receive strict
/// token-specific gating; destinations outside the catalog stay on the
/// pre-existing host-inbound path.
pub(in crate::afxdp) fn is_host_inbound_multicast_group(dst_ip: IpAddr) -> bool {
    match dst_ip {
        IpAddr::V4(group) => matches!(
            group.octets(),
            [224, 0, 0, 1]
                | [224, 0, 0, 2]
                | [224, 0, 0, 4]
                | [224, 0, 0, 5]
                | [224, 0, 0, 6]
                | [224, 0, 0, 9]
                | [224, 0, 0, 13]
                | [224, 0, 0, 18]
                | [224, 0, 0, 22]
        ),
        IpAddr::V6(group) => matches!(
            group.segments(),
            [0xff02, 0, 0, 0, 0, 0, 0, 5]
                | [0xff02, 0, 0, 0, 0, 0, 0, 6]
                | [0xff02, 0, 0, 0, 0, 0, 0, 9]
                | [0xff02, 0, 0, 0, 0, 0, 0, 13]
                | [0xff02, 0, 0, 0, 0, 0, 0, 18]
        ),
    }
}
