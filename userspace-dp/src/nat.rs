use crate::prefix::{PrefixV4, PrefixV6};
use crate::{DestinationNATRuleSnapshot, SourceNATRuleSnapshot, StaticNATRuleSnapshot};
use ipnet::IpNet;
use rustc_hash::FxHashMap;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU32, Ordering};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct NatDecision {
    pub(crate) rewrite_src: Option<IpAddr>,
    pub(crate) rewrite_dst: Option<IpAddr>,
    pub(crate) rewrite_src_port: Option<u16>,
    pub(crate) rewrite_dst_port: Option<u16>,
    /// When true, this is a NAT64 cross-address-family translation.
    /// The forward session key is IPv6 and the reverse session key is IPv4
    /// (or vice versa for the return direction).
    pub(crate) nat64: bool,
    /// When true, this is an NPTv6 (RFC 6296) stateless prefix translation.
    /// No L4 checksum update is needed -- the prefix rewrite is checksum-neutral.
    pub(crate) nptv6: bool,
}

impl NatDecision {
    pub(crate) fn reverse(
        self,
        original_src: IpAddr,
        original_dst: IpAddr,
        original_src_port: u16,
        original_dst_port: u16,
    ) -> Self {
        Self {
            rewrite_src: self.rewrite_dst.map(|_| original_dst),
            rewrite_dst: self.rewrite_src.map(|_| original_src),
            rewrite_src_port: self.rewrite_dst_port.map(|_| original_dst_port),
            rewrite_dst_port: self.rewrite_src_port.map(|_| original_src_port),
            nat64: self.nat64,
            nptv6: self.nptv6,
        }
    }

    /// Merge two NAT decisions, preferring fields already set in `self`.
    /// Used to combine a pre-routing DNAT decision with a post-policy SNAT decision.
    pub(crate) fn merge(self, other: NatDecision) -> Self {
        Self {
            rewrite_src: self.rewrite_src.or(other.rewrite_src),
            rewrite_dst: self.rewrite_dst.or(other.rewrite_dst),
            rewrite_src_port: self.rewrite_src_port.or(other.rewrite_src_port),
            rewrite_dst_port: self.rewrite_dst_port.or(other.rewrite_dst_port),
            nat64: self.nat64 || other.nat64,
            nptv6: self.nptv6 || other.nptv6,
        }
    }
}

/// Round-robin port allocator for pool-mode SNAT.
///
/// Each pool address gets its own atomic counter. Ports are allocated by
/// incrementing the counter and wrapping within [port_low, port_high].
/// No per-port tracking — session expiry naturally frees ports.
#[derive(Debug)]
pub(crate) struct PortAllocator {
    /// One atomic counter per pool address, used for round-robin port allocation.
    counters: Vec<AtomicU32>,
    /// Index for IPv4 round-robin address selection.
    addr_counter_v4: AtomicU32,
    /// Index for IPv6 round-robin address selection.
    addr_counter_v6: AtomicU32,
    pub(crate) port_low: u16,
    pub(crate) port_high: u16,
}

impl Clone for PortAllocator {
    fn clone(&self) -> Self {
        Self {
            counters: self
                .counters
                .iter()
                .map(|c| AtomicU32::new(c.load(Ordering::Relaxed)))
                .collect(),
            addr_counter_v4: AtomicU32::new(self.addr_counter_v4.load(Ordering::Relaxed)),
            addr_counter_v6: AtomicU32::new(self.addr_counter_v6.load(Ordering::Relaxed)),
            port_low: self.port_low,
            port_high: self.port_high,
        }
    }
}

impl Default for PortAllocator {
    fn default() -> Self {
        Self {
            counters: Vec::new(),
            addr_counter_v4: AtomicU32::new(0),
            addr_counter_v6: AtomicU32::new(0),
            port_low: 1024,
            port_high: 65535,
        }
    }
}

impl PortAllocator {
    pub(crate) fn new(num_addresses: usize, port_low: u16, port_high: u16) -> Self {
        let counters = (0..num_addresses).map(|_| AtomicU32::new(0)).collect();
        Self {
            counters,
            addr_counter_v4: AtomicU32::new(0),
            addr_counter_v6: AtomicU32::new(0),
            port_low,
            port_high,
        }
    }

    /// Pick a pool address index for the current address family.
    pub(crate) fn address_index(
        &self,
        src_ip: IpAddr,
        family_offset: usize,
        family_len: usize,
        address_persistent: bool,
    ) -> usize {
        if family_len == 0 {
            return 0;
        }
        if address_persistent {
            return family_offset + sticky_pool_index(src_ip, family_len);
        }
        let counter = match src_ip {
            IpAddr::V4(_) => &self.addr_counter_v4,
            IpAddr::V6(_) => &self.addr_counter_v6,
        };
        let idx = counter.fetch_add(1, Ordering::Relaxed);
        family_offset + ((idx as usize) % family_len)
    }

    /// Allocate the next port for the given address index.
    pub(crate) fn next_port(&self, addr_index: usize) -> u16 {
        let range = (self.port_high as u32).saturating_sub(self.port_low as u32) + 1;
        if range == 0 || addr_index >= self.counters.len() {
            return self.port_low;
        }
        let counter = &self.counters[addr_index];
        let val = counter.fetch_add(1, Ordering::Relaxed);
        self.port_low + (val % range) as u16
    }
}

fn sticky_pool_index(src_ip: IpAddr, pool_len: usize) -> usize {
    if pool_len <= 1 {
        return 0;
    }

    let mut hasher = Sha256::new();
    hasher.update(b"xpf-userspace-snat-address-persistent-v1");
    match src_ip {
        IpAddr::V4(addr) => {
            hasher.update([4]);
            hasher.update(addr.octets());
        }
        IpAddr::V6(addr) => {
            hasher.update([6]);
            hasher.update(addr.octets());
        }
    }
    let digest = hasher.finalize();
    let mut first = [0u8; 8];
    first.copy_from_slice(&digest[..8]);
    (u64::from_be_bytes(first) % pool_len as u64) as usize
}

#[derive(Clone, Debug, Default)]
pub(crate) struct SourceNatRule {
    pub(crate) from_zone: String,
    pub(crate) to_zone: String,
    pub(crate) source_v4: Vec<PrefixV4>,
    pub(crate) source_v6: Vec<PrefixV6>,
    pub(crate) destination_v4: Vec<PrefixV4>,
    pub(crate) destination_v6: Vec<PrefixV6>,
    pub(crate) interface_mode: bool,
    pub(crate) off: bool,
    pub(crate) address_persistent: bool,
    pub(crate) pool_addresses_v4: Vec<Ipv4Addr>,
    pub(crate) pool_addresses_v6: Vec<Ipv6Addr>,
    pub(crate) pool_allocator: PortAllocator,
}

impl SourceNatRule {
    fn matches(&self, from_zone: &str, to_zone: &str, src_ip: IpAddr, dst_ip: IpAddr) -> bool {
        if !self.from_zone.is_empty() && self.from_zone != from_zone {
            return false;
        }
        if !self.to_zone.is_empty() && self.to_zone != to_zone {
            return false;
        }
        match (src_ip, dst_ip) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                nets_match_v4(&self.source_v4, src) && nets_match_v4(&self.destination_v4, dst)
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                nets_match_v6(&self.source_v6, src) && nets_match_v6(&self.destination_v6, dst)
            }
            _ => false,
        }
    }
}

pub(crate) fn parse_source_nat_rules(snaps: &[SourceNATRuleSnapshot]) -> Vec<SourceNatRule> {
    let mut out = Vec::with_capacity(snaps.len());
    for snap in snaps {
        let mut rule = SourceNatRule {
            from_zone: snap.from_zone.clone(),
            to_zone: snap.to_zone.clone(),
            interface_mode: snap.interface_mode,
            off: snap.off,
            address_persistent: snap.address_persistent,
            ..SourceNatRule::default()
        };
        for prefix in &snap.source_addresses {
            match prefix.parse::<IpNet>() {
                Ok(IpNet::V4(net)) => rule.source_v4.push(PrefixV4::from_net(net)),
                Ok(IpNet::V6(net)) => rule.source_v6.push(PrefixV6::from_net(net)),
                Err(_) => {}
            }
        }
        for prefix in &snap.destination_addresses {
            match prefix.parse::<IpNet>() {
                Ok(IpNet::V4(net)) => rule.destination_v4.push(PrefixV4::from_net(net)),
                Ok(IpNet::V6(net)) => rule.destination_v6.push(PrefixV6::from_net(net)),
                Err(_) => {}
            }
        }
        // Parse pool addresses and port range for pool-mode SNAT.
        for addr_str in &snap.pool_addresses {
            // Pool addresses may be bare IPs or /32 CIDRs — strip the mask.
            let ip_str = addr_str.split('/').next().unwrap_or(addr_str);
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                match ip {
                    IpAddr::V4(v4) => rule.pool_addresses_v4.push(v4),
                    IpAddr::V6(v6) => rule.pool_addresses_v6.push(v6),
                }
            }
        }
        let total_pool = rule.pool_addresses_v4.len() + rule.pool_addresses_v6.len();
        if total_pool > 0 {
            let port_low = if snap.port_low > 0 {
                snap.port_low
            } else {
                1024
            };
            let port_high = if snap.port_high > 0 {
                snap.port_high
            } else {
                65535
            };
            rule.pool_allocator = PortAllocator::new(total_pool, port_low, port_high);
        }
        out.push(rule);
    }
    out
}

pub(crate) fn match_source_nat(
    rules: &[SourceNatRule],
    from_zone: &str,
    to_zone: &str,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    egress_v4: Option<Ipv4Addr>,
    egress_v6: Option<Ipv6Addr>,
) -> Option<NatDecision> {
    for rule in rules {
        if !rule.matches(from_zone, to_zone, src_ip, dst_ip) {
            continue;
        }
        if rule.off {
            return Some(NatDecision::default());
        }
        if rule.interface_mode {
            let rewrite_src = match src_ip {
                IpAddr::V4(_) => egress_v4.map(IpAddr::V4),
                IpAddr::V6(_) => egress_v6.map(IpAddr::V6),
            };
            return Some(NatDecision {
                rewrite_src,
                rewrite_dst: None,
                ..NatDecision::default()
            });
        }
        // Pool-mode SNAT: pick address by source-IP hash when
        // address-persistent is enabled, otherwise round-robin by family.
        match src_ip {
            IpAddr::V4(_) if !rule.pool_addresses_v4.is_empty() => {
                let addr_idx = rule.pool_allocator.address_index(
                    src_ip,
                    0,
                    rule.pool_addresses_v4.len(),
                    rule.address_persistent,
                );
                let v4_idx = addr_idx;
                let pool_addr = rule.pool_addresses_v4[v4_idx];
                let port = rule.pool_allocator.next_port(addr_idx);
                return Some(NatDecision {
                    rewrite_src: Some(IpAddr::V4(pool_addr)),
                    rewrite_dst: None,
                    rewrite_src_port: Some(port),
                    rewrite_dst_port: None,
                    ..NatDecision::default()
                });
            }
            IpAddr::V6(_) if !rule.pool_addresses_v6.is_empty() => {
                let v6_offset = rule.pool_addresses_v4.len();
                let addr_idx = rule.pool_allocator.address_index(
                    src_ip,
                    v6_offset,
                    rule.pool_addresses_v6.len(),
                    rule.address_persistent,
                );
                let v6_idx = addr_idx - v6_offset;
                let pool_addr = rule.pool_addresses_v6[v6_idx];
                let port = rule.pool_allocator.next_port(addr_idx);
                return Some(NatDecision {
                    rewrite_src: Some(IpAddr::V6(pool_addr)),
                    rewrite_dst: None,
                    rewrite_src_port: Some(port),
                    rewrite_dst_port: None,
                    ..NatDecision::default()
                });
            }
            _ => {
                // This rule matched the zones/prefixes but the referenced pool
                // has no address for the packet family. Treat it as an
                // unusable rule and keep walking so a later compatible rule can
                // still apply. Returning a default NatDecision here would
                // silently shadow later SNAT rules.
                continue;
            }
        }
    }
    None
}

/// Static 1:1 NAT entry (bidirectional).
#[derive(Clone, Debug)]
pub(crate) struct StaticNatEntry {
    pub(crate) external_ip: IpAddr,
    pub(crate) internal_ip: IpAddr,
    pub(crate) from_zone: String,
}

/// Lookup table for static NAT -- indexed by IP for O(1) matching.
#[derive(Clone, Debug, Default)]
pub(crate) struct StaticNatTable {
    /// external_ip -> entry (for inbound DNAT)
    dnat: FxHashMap<IpAddr, StaticNatEntry>,
    /// internal_ip -> entry (for outbound SNAT)
    snat: FxHashMap<IpAddr, StaticNatEntry>,
}

impl StaticNatTable {
    pub(crate) fn from_snapshots(snaps: &[StaticNATRuleSnapshot]) -> Self {
        let mut table = StaticNatTable::default();
        for snap in snaps {
            let external_ip: IpAddr = match snap.external_ip.parse() {
                Ok(ip) => ip,
                Err(_) => continue,
            };
            let internal_ip: IpAddr = match snap.internal_ip.parse() {
                Ok(ip) => ip,
                Err(_) => continue,
            };
            let entry = StaticNatEntry {
                external_ip,
                internal_ip,
                from_zone: snap.from_zone.clone(),
            };
            table.dnat.insert(external_ip, entry.clone());
            table.snat.insert(internal_ip, entry);
        }
        table
    }

    /// Match inbound: if dst_ip is an external IP, return DNAT decision.
    pub(crate) fn match_dnat(&self, dst_ip: IpAddr, ingress_zone: &str) -> Option<NatDecision> {
        let entry = self.dnat.get(&dst_ip)?;
        if !entry.from_zone.is_empty() && entry.from_zone != ingress_zone {
            return None;
        }
        Some(NatDecision {
            rewrite_src: None,
            rewrite_dst: Some(entry.internal_ip),
            ..NatDecision::default()
        })
    }

    /// Match outbound: if src_ip is an internal IP, return SNAT decision.
    ///
    /// Note: from_zone is NOT checked for SNAT. The zone constraint on the
    /// static NAT rule set (`from zone X`) controls which ingress zone
    /// triggers DNAT only. For SNAT (outbound), the internal IP match is
    /// sufficient -- the traffic originates from the internal host regardless
    /// of which zone it enters through.
    pub(crate) fn match_snat(&self, src_ip: IpAddr, _ingress_zone: &str) -> Option<NatDecision> {
        let entry = self.snat.get(&src_ip)?;
        Some(NatDecision {
            rewrite_src: Some(entry.external_ip),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    }

    /// Returns true if the table has any entries.
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.dnat.is_empty()
    }

    /// Returns all external IPs (for local delivery recognition).
    pub(crate) fn external_ips(&self) -> impl Iterator<Item = &IpAddr> {
        self.dnat.keys()
    }
}

fn nets_match_v4(nets: &[PrefixV4], ip: Ipv4Addr) -> bool {
    nets.is_empty() || nets.iter().any(|net| net.contains(ip))
}

fn nets_match_v6(nets: &[PrefixV6], ip: Ipv6Addr) -> bool {
    nets.is_empty() || nets.iter().any(|net| net.contains(ip))
}

// ---------------------------------------------------------------------------
// Destination NAT (DNAT) table — O(1) lookup by (protocol, dst_ip, dst_port)
// ---------------------------------------------------------------------------

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) struct DnatKey {
    pub protocol: u8,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct DnatValue {
    pub new_dst_ip: IpAddr,
    pub new_dst_port: u16,
}

#[derive(Clone, Debug)]
struct DnatEntry {
    from_zone: Box<str>,
    value: DnatValue,
}

/// Destination NAT lookup table.
///
/// Entries are keyed by `(protocol, dst_ip, dst_port)`. A wildcard port
/// entry (`dst_port = 0`) matches any destination port when no exact-port
/// entry exists.
#[derive(Clone, Debug, Default)]
pub(crate) struct DnatTable {
    entries: FxHashMap<DnatKey, Vec<DnatEntry>>,
}

impl DnatTable {
    pub(crate) fn from_snapshots(snaps: &[DestinationNATRuleSnapshot]) -> Self {
        let mut table = DnatTable::default();
        for snap in snaps {
            let dst_ip: IpAddr = match snap.destination_address.parse() {
                Ok(ip) => ip,
                Err(_) => continue,
            };
            let pool_ip: IpAddr = match snap.pool_address.parse() {
                Ok(ip) => ip,
                Err(_) => continue,
            };
            // Determine protocol(s) to insert entries for.
            let protos: Vec<u8> = match snap.protocol.as_str() {
                "tcp" => vec![PROTO_TCP],
                "udp" => vec![PROTO_UDP],
                "" => {
                    if snap.destination_port != 0 {
                        // Port-based rule with no explicit protocol: default TCP
                        vec![PROTO_TCP]
                    } else {
                        // No protocol, no port: expand to both TCP and UDP
                        vec![PROTO_TCP, PROTO_UDP]
                    }
                }
                _ => continue,
            };
            for proto in protos {
                Self::insert_entry(
                    table.entries.entry(DnatKey {
                        protocol: proto,
                        dst_ip,
                        dst_port: snap.destination_port,
                    }),
                    DnatEntry {
                        from_zone: snap.from_zone.clone().into_boxed_str(),
                        value: DnatValue {
                            new_dst_ip: pool_ip,
                            new_dst_port: if snap.pool_port != 0 {
                                snap.pool_port
                            } else {
                                snap.destination_port
                            },
                        },
                    },
                );
            }
        }
        table
    }

    /// Look up a DNAT entry for the given packet fields.
    ///
    /// 1. Exact match: `(protocol, dst_ip, dst_port)`
    /// 2. Wildcard port fallback: `(protocol, dst_ip, 0)`
    pub(crate) fn lookup(
        &self,
        protocol: u8,
        dst_ip: IpAddr,
        dst_port: u16,
        ingress_zone: &str,
    ) -> Option<NatDecision> {
        let value = self
            .match_entries(
                self.entries.get(&DnatKey {
                    protocol,
                    dst_ip,
                    dst_port,
                }),
                ingress_zone,
            )
            .or_else(|| {
                self.match_entries(
                    self.entries.get(&DnatKey {
                        protocol,
                        dst_ip,
                        dst_port: 0,
                    }),
                    ingress_zone,
                )
            })?;
        let rewrite_dst_port = if value.new_dst_port != 0 && value.new_dst_port != dst_port {
            Some(value.new_dst_port)
        } else {
            None
        };
        Some(NatDecision {
            rewrite_src: None,
            rewrite_dst: Some(value.new_dst_ip),
            rewrite_src_port: None,
            rewrite_dst_port,
            nat64: false,
            nptv6: false,
        })
    }

    fn match_entries(
        &self,
        entries: Option<&Vec<DnatEntry>>,
        ingress_zone: &str,
    ) -> Option<DnatValue> {
        let entries = entries?;
        entries
            .iter()
            .find(|entry| !entry.from_zone.is_empty() && entry.from_zone.as_ref() == ingress_zone)
            .map(|entry| entry.value)
            .or_else(|| {
                entries
                    .iter()
                    .find(|entry| entry.from_zone.is_empty())
                    .map(|entry| entry.value)
            })
    }

    fn insert_entry(
        slot: std::collections::hash_map::Entry<'_, DnatKey, Vec<DnatEntry>>,
        entry: DnatEntry,
    ) {
        let entries = slot.or_default();
        if let Some(existing) = entries
            .iter_mut()
            .find(|existing| existing.from_zone == entry.from_zone)
        {
            *existing = entry;
            return;
        }
        entries.push(entry);
    }

    /// Returns true if the table has any entries.
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns all destination IPs (the external/public IPs that DNAT rules match on).
    /// These must be registered as local addresses so traffic to them is recognized.
    pub(crate) fn destination_ips(&self) -> impl Iterator<Item = IpAddr> + '_ {
        // Deduplicate by collecting unique dst_ip values.
        let mut seen = FxHashMap::default();
        for key in self.entries.keys() {
            seen.entry(key.dst_ip).or_insert(());
        }
        seen.into_keys()
    }
}

#[cfg(test)]
#[path = "nat_tests.rs"]
mod tests;
