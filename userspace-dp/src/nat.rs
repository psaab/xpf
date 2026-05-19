use crate::prefix::{PrefixV4, PrefixV6};
use crate::{
    DestinationNATRuleSnapshot, SourceNATRuleSnapshot, SourceNatPoolStatus, StaticNATRuleSnapshot,
};
use ipnet::IpNet;
use rustc_hash::FxHashMap;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const DEFAULT_PERSISTENT_NAT_TIMEOUT_SECS: i64 = 300;
const NS_PER_SEC: u64 = 1_000_000_000;
const MAX_SOURCE_NAT_POOL_TRACKED_FLOWS: usize = 262_144;

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SourceNatLookup {
    NoMatch,
    Matched(NatDecision),
    Unavailable(SourceNatFailure),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SourceNatFailure {
    pub(crate) rule_name: String,
    pub(crate) pool_name: String,
    pub(crate) reason: SourceNatFailureReason,
}

impl SourceNatFailure {
    fn for_rule(rule: &SourceNatRule, reason: SourceNatFailureReason) -> Self {
        Self {
            rule_name: rule.name.clone(),
            pool_name: rule.pool_name.clone(),
            reason,
        }
    }

    pub(crate) fn exception_reason(&self) -> &'static str {
        self.reason.exception_reason()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SourceNatFailureReason {
    MissingPool,
    EmptyPool,
    InvalidPool,
    InvalidPortRange,
    WrongAddressFamily,
    AllocatorExhausted,
}

impl SourceNatFailureReason {
    fn exception_reason(self) -> &'static str {
        match self {
            Self::MissingPool => "source_nat_pool_missing",
            Self::EmptyPool => "source_nat_pool_empty",
            Self::InvalidPool => "source_nat_pool_invalid",
            Self::InvalidPortRange => "source_nat_pool_invalid_port_range",
            Self::WrongAddressFamily => "source_nat_pool_wrong_family",
            Self::AllocatorExhausted => "source_nat_pool_exhausted",
        }
    }
}

fn source_nat_failure_reason_from_snapshot(reason: &str) -> SourceNatFailureReason {
    match reason {
        "missing_pool" => SourceNatFailureReason::MissingPool,
        "empty_pool" => SourceNatFailureReason::EmptyPool,
        "invalid_port_range" => SourceNatFailureReason::InvalidPortRange,
        "invalid_pool" => SourceNatFailureReason::InvalidPool,
        "wrong_address_family" => SourceNatFailureReason::WrongAddressFamily,
        "allocator_exhausted" => SourceNatFailureReason::AllocatorExhausted,
        _ => SourceNatFailureReason::InvalidPool,
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) struct SourceNatFlowKey {
    pub(crate) protocol: u8,
    pub(crate) src_ip: IpAddr,
    pub(crate) dst_ip: IpAddr,
    pub(crate) src_port: u16,
    pub(crate) dst_port: u16,
}

impl SourceNatFlowKey {
    fn persistent_source_key(self) -> PersistentSourceKey {
        PersistentSourceKey {
            protocol: self.protocol,
            src_ip: self.src_ip,
            src_port: self.src_port,
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct PersistentSourceKey {
    protocol: u8,
    src_ip: IpAddr,
    src_port: u16,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct TranslatedTuple {
    ip: IpAddr,
    port: u16,
}

#[derive(Clone, Copy, Debug)]
enum PoolAddressFamily<'a> {
    V4(&'a [Ipv4Addr]),
    V6(&'a [Ipv6Addr]),
}

impl PoolAddressFamily<'_> {
    fn len(self) -> usize {
        match self {
            Self::V4(addrs) => addrs.len(),
            Self::V6(addrs) => addrs.len(),
        }
    }

    fn ip_at(self, index: usize) -> IpAddr {
        match self {
            Self::V4(addrs) => IpAddr::V4(addrs[index]),
            Self::V6(addrs) => IpAddr::V6(addrs[index]),
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
enum AllocationOwner {
    Flow(SourceNatFlowKey),
    Persistent(PersistentSourceKey),
}

#[derive(Clone, Copy, Debug)]
struct LiveAllocation {
    translated: TranslatedTuple,
    persistent_key: Option<PersistentSourceKey>,
    persistent_lease_created: bool,
    persistent_previous_expires_at_ns: u64,
    persistent_previous_active_flows: u32,
}

#[derive(Clone, Copy, Debug)]
struct PersistentLease {
    translated: TranslatedTuple,
    expires_at_ns: u64,
    timeout_ns: u64,
    active_flows: u32,
}

#[derive(Debug, Default)]
struct PortAllocatorLiveState {
    live_by_flow: FxHashMap<SourceNatFlowKey, LiveAllocation>,
    owner_by_translated: FxHashMap<TranslatedTuple, AllocationOwner>,
    addr_index_by_translated: FxHashMap<TranslatedTuple, usize>,
    persistent_by_source: FxHashMap<PersistentSourceKey, PersistentLease>,
    lease_expirations: BTreeSet<(u64, PersistentSourceKey)>,
    next_port_offset_by_addr: Vec<u32>,
    recycled_ports_by_addr: Vec<Vec<u16>>,
    gc_counter: u32,
}

impl PortAllocatorLiveState {
    fn new(addr_count: usize) -> Self {
        Self {
            next_port_offset_by_addr: vec![0; addr_count],
            recycled_ports_by_addr: vec![Vec::new(); addr_count],
            ..Self::default()
        }
    }
}

/// Run full lease-expiration GC every N release_flow calls.
const GC_PERIOD: u32 = 10;

#[derive(Debug)]
struct PortAllocatorShared {
    /// One atomic counter per pool address, used for round-robin port allocation.
    counters: Vec<AtomicU32>,
    /// Index for IPv4 round-robin address selection.
    addr_counter_v4: AtomicU32,
    /// Index for IPv6 round-robin address selection.
    addr_counter_v6: AtomicU32,
    live: Mutex<PortAllocatorLiveState>,
    allocations_total: AtomicU64,
    reuses_total: AtomicU64,
    exhaustion_total: AtomicU64,
    max_tracked_flows: usize,
}

/// Bounded pool-mode SNAT allocator.
///
/// Address selection uses atomics for stable round-robin/sticky starting
/// points; live translated tuple ownership is tracked under a per-pool mutex
/// so ports are not reused while sessions are alive. Persistent NAT leases are
/// keyed by source tuple and retained until their inactivity timeout after the
/// last live flow releases them.
#[derive(Clone, Debug)]
pub(crate) struct PortAllocator {
    shared: Arc<PortAllocatorShared>,
    pub(crate) port_low: u16,
    pub(crate) port_high: u16,
}

impl Default for PortAllocator {
    fn default() -> Self {
        Self {
            shared: Arc::new(PortAllocatorShared {
                counters: Vec::new(),
                addr_counter_v4: AtomicU32::new(0),
                addr_counter_v6: AtomicU32::new(0),
                live: Mutex::new(PortAllocatorLiveState::default()),
                allocations_total: AtomicU64::new(0),
                reuses_total: AtomicU64::new(0),
                exhaustion_total: AtomicU64::new(0),
                max_tracked_flows: 0,
            }),
            port_low: 1024,
            port_high: 65535,
        }
    }
}

impl PortAllocator {
    pub(crate) fn new(num_addresses: usize, port_low: u16, port_high: u16) -> Self {
        let counters = (0..num_addresses).map(|_| AtomicU32::new(0)).collect();
        let max_tracked_flows = allocator_capacity(num_addresses, port_low, port_high)
            .min(MAX_SOURCE_NAT_POOL_TRACKED_FLOWS);
        Self {
            shared: Arc::new(PortAllocatorShared {
                counters,
                addr_counter_v4: AtomicU32::new(0),
                addr_counter_v6: AtomicU32::new(0),
                live: Mutex::new(PortAllocatorLiveState::new(num_addresses)),
                allocations_total: AtomicU64::new(0),
                reuses_total: AtomicU64::new(0),
                exhaustion_total: AtomicU64::new(0),
                max_tracked_flows,
            }),
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
            IpAddr::V4(_) => &self.shared.addr_counter_v4,
            IpAddr::V6(_) => &self.shared.addr_counter_v6,
        };
        let idx = counter.fetch_add(1, Ordering::Relaxed);
        family_offset + ((idx as usize) % family_len)
    }

    /// Allocate the next port for the given address index, reporting
    /// unusable allocator state to the caller instead of producing a
    /// no-op translation.
    pub(crate) fn try_next_port(&self, addr_index: usize) -> Result<u16, SourceNatFailureReason> {
        if self.port_low == 0 || self.port_high == 0 || self.port_low > self.port_high {
            return Err(SourceNatFailureReason::InvalidPortRange);
        }
        let range = (self.port_high as u32).saturating_sub(self.port_low as u32) + 1;
        if range == 0 || addr_index >= self.shared.counters.len() {
            return Err(SourceNatFailureReason::AllocatorExhausted);
        }
        let counter = &self.shared.counters[addr_index];
        let val = counter.fetch_add(1, Ordering::Relaxed);
        Ok(self.port_low + (val % range) as u16)
    }

    #[allow(clippy::too_many_arguments)]
    fn allocate_translation(
        &self,
        flow: SourceNatFlowKey,
        family_addresses: PoolAddressFamily<'_>,
        family_offset: usize,
        address_persistent: bool,
        persistent_nat: bool,
        persistent_nat_timeout_ns: u64,
        now_ns: u64,
    ) -> Result<TranslatedTuple, SourceNatFailureReason> {
        if self.port_low == 0 || self.port_high == 0 || self.port_low > self.port_high {
            return Err(SourceNatFailureReason::InvalidPortRange);
        }
        let family_len = family_addresses.len();
        if family_len == 0 {
            return Err(SourceNatFailureReason::WrongAddressFamily);
        }
        let range = (self.port_high as u32).saturating_sub(self.port_low as u32) + 1;
        if range == 0 || self.shared.max_tracked_flows == 0 {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(SourceNatFailureReason::AllocatorExhausted);
        }

        let mut live = self.shared.live.lock().unwrap_or_else(|e| e.into_inner());
        self.gc_expired_locked(&mut live, now_ns);

        if let Some(existing) = live.live_by_flow.get(&flow) {
            self.shared.reuses_total.fetch_add(1, Ordering::Relaxed);
            return Ok(existing.translated);
        }
        if live.live_by_flow.len() >= self.shared.max_tracked_flows {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(SourceNatFailureReason::AllocatorExhausted);
        }

        let persistent_key = persistent_nat.then(|| flow.persistent_source_key());
        if let Some(key) = persistent_key {
            if live.persistent_by_source.contains_key(&key) {
                let mut reusable = None;
                let mut expired = None;
                let mut previous_expires_at_ns = 0;
                let mut previous_active_flows = 0;
                let mut remove_expiry = None;
                if let Some(lease) = live.persistent_by_source.get_mut(&key) {
                    if lease.active_flows > 0 || lease.expires_at_ns > now_ns {
                        let translated = lease.translated;
                        previous_expires_at_ns = lease.expires_at_ns;
                        previous_active_flows = lease.active_flows;
                        if lease.active_flows == 0 {
                            remove_expiry = Some(lease.expires_at_ns);
                        }
                        lease.active_flows = lease.active_flows.saturating_add(1);
                        let expires_at_ns =
                            now_ns.saturating_add(persistent_nat_timeout_ns.max(NS_PER_SEC));
                        lease.expires_at_ns = expires_at_ns;
                        reusable = Some(translated);
                    } else {
                        expired = Some(lease.translated);
                    }
                }
                if let Some(expires_at_ns) = remove_expiry {
                    live.lease_expirations.remove(&(expires_at_ns, key));
                }
                if let Some(translated) = reusable {
                    live.live_by_flow.insert(
                        flow,
                        LiveAllocation {
                            translated,
                            persistent_key: Some(key),
                            persistent_lease_created: false,
                            persistent_previous_expires_at_ns: previous_expires_at_ns,
                            persistent_previous_active_flows: previous_active_flows,
                        },
                    );
                    self.shared.reuses_total.fetch_add(1, Ordering::Relaxed);
                    return Ok(translated);
                }
                if let Some(translated) = expired {
                    self.release_translated_locked(&mut live, translated);
                    live.persistent_by_source.remove(&key);
                }
            }
            if live.persistent_by_source.len() >= self.shared.max_tracked_flows {
                self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
                return Err(SourceNatFailureReason::AllocatorExhausted);
            }
        }

        let start_abs =
            self.address_index(flow.src_ip, family_offset, family_len, address_persistent);
        let start_rel = start_abs.saturating_sub(family_offset);
        let address_attempts = if address_persistent { 1 } else { family_len };
        for offset in 0..address_attempts {
            let rel = (start_rel + offset) % family_len;
            let abs = family_offset + rel;
            let translated_ip = family_addresses.ip_at(rel);
            let Some(translated) =
                self.claim_free_port_locked(&mut live, abs, translated_ip, flow, persistent_key)
            else {
                continue;
            };
            if let Some(key) = persistent_key {
                let expires_at_ns =
                    now_ns.saturating_add(persistent_nat_timeout_ns.max(NS_PER_SEC));
                live.persistent_by_source.insert(
                    key,
                    PersistentLease {
                        translated,
                        expires_at_ns,
                        timeout_ns: persistent_nat_timeout_ns.max(NS_PER_SEC),
                        active_flows: 1,
                    },
                );
            }
            live.live_by_flow.insert(
                flow,
                LiveAllocation {
                    translated,
                    persistent_key,
                    persistent_lease_created: persistent_key.is_some(),
                    persistent_previous_expires_at_ns: 0,
                    persistent_previous_active_flows: 0,
                },
            );
            self.shared
                .allocations_total
                .fetch_add(1, Ordering::Relaxed);
            return Ok(translated);
        }

        self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
        Err(SourceNatFailureReason::AllocatorExhausted)
    }

    fn claim_free_port_locked(
        &self,
        live: &mut PortAllocatorLiveState,
        addr_index: usize,
        translated_ip: IpAddr,
        flow: SourceNatFlowKey,
        persistent_key: Option<PersistentSourceKey>,
    ) -> Option<TranslatedTuple> {
        if addr_index >= self.shared.counters.len() {
            return None;
        }
        let range = (self.port_high as u32).saturating_sub(self.port_low as u32) + 1;
        let next_offset = &mut live.next_port_offset_by_addr[addr_index];
        if *next_offset < range {
            let port = self.port_low + *next_offset as u16;
            *next_offset += 1;
            let translated = TranslatedTuple {
                ip: translated_ip,
                port,
            };
            if self.assign_owner_locked(live, addr_index, translated, flow, persistent_key) {
                return Some(translated);
            }
        }

        while let Some(port) = live.recycled_ports_by_addr[addr_index].pop() {
            let translated = TranslatedTuple {
                ip: translated_ip,
                port,
            };
            if self.assign_owner_locked(live, addr_index, translated, flow, persistent_key) {
                return Some(translated);
            }
        }
        None
    }

    fn assign_owner_locked(
        &self,
        live: &mut PortAllocatorLiveState,
        addr_index: usize,
        translated: TranslatedTuple,
        flow: SourceNatFlowKey,
        persistent_key: Option<PersistentSourceKey>,
    ) -> bool {
        if live.owner_by_translated.contains_key(&translated) {
            return false;
        }
        let owner = persistent_key
            .map(AllocationOwner::Persistent)
            .unwrap_or(AllocationOwner::Flow(flow));
        live.owner_by_translated.insert(translated, owner);
        live.addr_index_by_translated.insert(translated, addr_index);
        true
    }

    fn release_translated_locked(
        &self,
        live: &mut PortAllocatorLiveState,
        translated: TranslatedTuple,
    ) -> bool {
        if live.owner_by_translated.remove(&translated).is_none() {
            return false;
        }
        let Some(addr_index) = live.addr_index_by_translated.remove(&translated) else {
            return true;
        };
        if addr_index >= live.recycled_ports_by_addr.len() {
            return true;
        }
        if translated.port < self.port_low || translated.port > self.port_high {
            return true;
        }
        live.recycled_ports_by_addr[addr_index].push(translated.port);
        true
    }

    fn release_flow(
        &self,
        flow: SourceNatFlowKey,
        translated: TranslatedTuple,
        now_ns: u64,
    ) -> bool {
        let mut live = self.shared.live.lock().unwrap_or_else(|e| e.into_inner());
        let Some(existing) = live.live_by_flow.get(&flow).copied() else {
            return false;
        };
        if existing.translated != translated {
            return false;
        }
        live.live_by_flow.remove(&flow);
        if let Some(key) = existing.persistent_key {
            let mut insert_expiry = None;
            if let Some(lease) = live.persistent_by_source.get_mut(&key) {
                lease.active_flows = lease.active_flows.saturating_sub(1);
                if lease.active_flows == 0 {
                    let expires_at_ns = now_ns.saturating_add(lease.timeout_ns);
                    lease.expires_at_ns = expires_at_ns;
                    insert_expiry = Some(expires_at_ns);
                }
            }
            if let Some(expires_at_ns) = insert_expiry {
                live.lease_expirations.insert((expires_at_ns, key));
            }
        } else {
            self.release_translated_locked(&mut live, translated);
        }
        live.gc_counter = live.gc_counter.wrapping_add(1);
        if live.gc_counter % GC_PERIOD == 0 {
            self.gc_expired_locked(&mut live, now_ns);
        }
        true
    }

    fn rollback_flow(&self, flow: SourceNatFlowKey, translated: TranslatedTuple) -> bool {
        let mut live = self.shared.live.lock().unwrap_or_else(|e| e.into_inner());
        let Some(existing) = live.live_by_flow.get(&flow).copied() else {
            return false;
        };
        if existing.translated != translated {
            return false;
        }
        live.live_by_flow.remove(&flow);
        if let Some(key) = existing.persistent_key {
            if existing.persistent_lease_created {
                live.persistent_by_source.remove(&key);
                self.release_translated_locked(&mut live, translated);
            } else if let Some(lease) = live.persistent_by_source.get_mut(&key) {
                lease.active_flows = existing.persistent_previous_active_flows;
                lease.expires_at_ns = existing.persistent_previous_expires_at_ns;
                let insert_expiry = (lease.active_flows == 0).then_some(lease.expires_at_ns);
                if let Some(expires_at_ns) = insert_expiry {
                    live.lease_expirations.insert((expires_at_ns, key));
                }
            }
        } else {
            self.release_translated_locked(&mut live, translated);
        }
        true
    }

    fn snapshot(&self) -> PortAllocatorSnapshot {
        let live = self.shared.live.lock().unwrap_or_else(|e| e.into_inner());
        PortAllocatorSnapshot {
            live_flows: live.live_by_flow.len() as u64,
            used_ports: live.owner_by_translated.len() as u64,
            persistent_leases: live.persistent_by_source.len() as u64,
            max_tracked_flows: self.shared.max_tracked_flows as u64,
            allocations_total: self.shared.allocations_total.load(Ordering::Relaxed),
            reuses_total: self.shared.reuses_total.load(Ordering::Relaxed),
            exhaustion_total: self.shared.exhaustion_total.load(Ordering::Relaxed),
        }
    }

    fn gc_expired_locked(&self, live: &mut PortAllocatorLiveState, now_ns: u64) {
        if now_ns == 0 {
            return;
        }
        while let Some((expires_at_ns, key)) = live.lease_expirations.iter().next().copied() {
            if expires_at_ns > now_ns {
                break;
            }
            live.lease_expirations.remove(&(expires_at_ns, key));
            let Some(lease) = live.persistent_by_source.get(&key).copied() else {
                continue;
            };
            if lease.active_flows != 0 || lease.expires_at_ns != expires_at_ns {
                continue;
            }
            let translated = lease.translated;
            live.persistent_by_source.remove(&key);
            match live.owner_by_translated.get(&translated) {
                Some(AllocationOwner::Persistent(owner)) if *owner == key => {
                    self.release_translated_locked(live, translated);
                }
                _ => {}
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PortAllocatorSnapshot {
    pub(crate) live_flows: u64,
    pub(crate) used_ports: u64,
    pub(crate) persistent_leases: u64,
    pub(crate) max_tracked_flows: u64,
    pub(crate) allocations_total: u64,
    pub(crate) reuses_total: u64,
    pub(crate) exhaustion_total: u64,
}

fn allocator_capacity(num_addresses: usize, port_low: u16, port_high: u16) -> usize {
    if num_addresses == 0 || port_low == 0 || port_high == 0 || port_low > port_high {
        return 0;
    }
    let ports = (u64::from(port_high) - u64::from(port_low)) + 1;
    ports
        .saturating_mul(num_addresses as u64)
        .min(usize::MAX as u64) as usize
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
    pub(crate) name: String,
    pub(crate) from_zone: String,
    pub(crate) to_zone: String,
    pub(crate) source_v4: Vec<PrefixV4>,
    pub(crate) source_v6: Vec<PrefixV6>,
    pub(crate) destination_v4: Vec<PrefixV4>,
    pub(crate) destination_v6: Vec<PrefixV6>,
    pub(crate) interface_mode: bool,
    pub(crate) off: bool,
    pub(crate) pool_name: String,
    pub(crate) pool_mode: bool,
    pub(crate) pool_failure: Option<SourceNatFailureReason>,
    pub(crate) address_persistent: bool,
    pub(crate) persistent_nat: bool,
    pub(crate) persistent_nat_permit_any_remote_host: bool,
    pub(crate) persistent_nat_inactivity_timeout_secs: i64,
    pub(crate) persistent_nat_timeout_ns: u64,
    pub(crate) pool_addresses_v4: Vec<Ipv4Addr>,
    pub(crate) pool_addresses_v6: Vec<Ipv6Addr>,
    pub(crate) pool_allocator: PortAllocator,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct SourceNatPoolAllocatorKey {
    pool_name: String,
    pool_addresses_v4: Vec<Ipv4Addr>,
    pool_addresses_v6: Vec<Ipv6Addr>,
    port_low: u16,
    port_high: u16,
}

impl SourceNatRule {
    fn allocator_key(&self) -> Option<SourceNatPoolAllocatorKey> {
        let total_pool = self.pool_addresses_v4.len() + self.pool_addresses_v6.len();
        (self.pool_mode && total_pool > 0 && self.pool_failure.is_none()).then(|| {
            SourceNatPoolAllocatorKey {
                pool_name: self.pool_name.clone(),
                pool_addresses_v4: self.pool_addresses_v4.clone(),
                pool_addresses_v6: self.pool_addresses_v6.clone(),
                port_low: self.pool_allocator.port_low,
                port_high: self.pool_allocator.port_high,
            }
        })
    }
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

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn parse_source_nat_rules(snaps: &[SourceNATRuleSnapshot]) -> Vec<SourceNatRule> {
    parse_source_nat_rules_with_previous(snaps, None)
}

pub(crate) fn parse_source_nat_rules_with_previous(
    snaps: &[SourceNATRuleSnapshot],
    previous: Option<&[SourceNatRule]>,
) -> Vec<SourceNatRule> {
    let mut out = Vec::with_capacity(snaps.len());
    let mut previous_allocators = FxHashMap::<SourceNatPoolAllocatorKey, PortAllocator>::default();
    if let Some(prev_rules) = previous {
        for prev in prev_rules {
            if let Some(key) = prev.allocator_key() {
                previous_allocators
                    .entry(key)
                    .or_insert_with(|| prev.pool_allocator.clone());
            }
        }
    }
    let mut pool_allocators = FxHashMap::<SourceNatPoolAllocatorKey, PortAllocator>::default();
    for snap in snaps {
        let timeout_secs = if snap.persistent_nat_inactivity_timeout > 0 {
            snap.persistent_nat_inactivity_timeout
        } else {
            DEFAULT_PERSISTENT_NAT_TIMEOUT_SECS
        };
        let mut rule = SourceNatRule {
            name: snap.name.clone(),
            from_zone: snap.from_zone.clone(),
            to_zone: snap.to_zone.clone(),
            interface_mode: snap.interface_mode,
            off: snap.off,
            pool_name: snap.pool_name.clone(),
            pool_mode: !snap.pool_name.is_empty() || !snap.pool_addresses.is_empty(),
            address_persistent: snap.address_persistent,
            persistent_nat: snap.persistent_nat,
            persistent_nat_permit_any_remote_host: snap.persistent_nat_permit_any_remote_host,
            persistent_nat_inactivity_timeout_secs: timeout_secs,
            persistent_nat_timeout_ns: (timeout_secs as u64).saturating_mul(NS_PER_SEC),
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
        let mut invalid_pool_address = false;
        for addr_str in &snap.pool_addresses {
            // Pool addresses may be bare IPs or /32 CIDRs — strip the mask.
            let ip_str = addr_str.split('/').next().unwrap_or(addr_str);
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                match ip {
                    IpAddr::V4(v4) => rule.pool_addresses_v4.push(v4),
                    IpAddr::V6(v6) => rule.pool_addresses_v6.push(v6),
                }
            } else {
                invalid_pool_address = true;
            }
        }
        let total_pool = rule.pool_addresses_v4.len() + rule.pool_addresses_v6.len();
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
        if snap.pool_unusable {
            rule.pool_failure = Some(source_nat_failure_reason_from_snapshot(
                &snap.pool_unusable_reason,
            ));
        } else if rule.pool_mode && invalid_pool_address {
            rule.pool_failure = Some(SourceNatFailureReason::InvalidPool);
        } else if rule.pool_mode && total_pool == 0 {
            rule.pool_failure = Some(if snap.pool_addresses.is_empty() {
                SourceNatFailureReason::EmptyPool
            } else {
                SourceNatFailureReason::MissingPool
            });
        } else if rule.pool_mode && port_low > port_high {
            rule.pool_failure = Some(SourceNatFailureReason::InvalidPortRange);
        }
        if total_pool > 0 {
            rule.pool_allocator = PortAllocator::new(total_pool, port_low, port_high);
        }
        if let Some(key) = rule.allocator_key() {
            if let Some(existing) = pool_allocators.get(&key) {
                rule.pool_allocator = existing.clone();
            } else {
                let allocator = previous_allocators
                    .get(&key)
                    .cloned()
                    .unwrap_or_else(|| rule.pool_allocator.clone());
                rule.pool_allocator = allocator.clone();
                pool_allocators.insert(key, allocator);
            }
        }
        out.push(rule);
    }
    out
}

#[allow(dead_code)]
fn source_nat_runtime_compatible(new_rule: &SourceNatRule, old_rule: &SourceNatRule) -> bool {
    new_rule.name == old_rule.name
        && new_rule.pool_name == old_rule.pool_name
        && new_rule.pool_mode == old_rule.pool_mode
        && new_rule.pool_failure == old_rule.pool_failure
        && new_rule.address_persistent == old_rule.address_persistent
        && new_rule.persistent_nat == old_rule.persistent_nat
        && new_rule.persistent_nat_permit_any_remote_host
            == old_rule.persistent_nat_permit_any_remote_host
        && new_rule.persistent_nat_inactivity_timeout_secs
            == old_rule.persistent_nat_inactivity_timeout_secs
        && new_rule.pool_addresses_v4 == old_rule.pool_addresses_v4
        && new_rule.pool_addresses_v6 == old_rule.pool_addresses_v6
        && new_rule.pool_allocator.port_low == old_rule.pool_allocator.port_low
        && new_rule.pool_allocator.port_high == old_rule.pool_allocator.port_high
}

pub(crate) fn release_source_nat_allocation(
    rules: &[SourceNatRule],
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
) {
    release_source_nat_allocation_with_mode(rules, key, nat, is_reverse, now_ns, false);
}

pub(crate) fn rollback_source_nat_allocation(
    rules: &[SourceNatRule],
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
) {
    release_source_nat_allocation_with_mode(rules, key, nat, is_reverse, now_ns, true);
}

fn release_source_nat_allocation_with_mode(
    rules: &[SourceNatRule],
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    _now_ns: u64,
    rollback: bool,
) {
    if is_reverse {
        return;
    }
    let Some(rewrite_src) = nat.rewrite_src else {
        return;
    };
    let Some(rewrite_src_port) = nat.rewrite_src_port else {
        return;
    };
    let translated = TranslatedTuple {
        ip: rewrite_src,
        port: rewrite_src_port,
    };
    let flow = SourceNatFlowKey {
        protocol: key.protocol,
        src_ip: key.src_ip,
        dst_ip: nat.rewrite_dst.unwrap_or(key.dst_ip),
        src_port: key.src_port,
        dst_port: key.dst_port,
    };
    for rule in rules {
        if !rule.pool_mode {
            continue;
        }
        let released = if rollback {
            rule.pool_allocator.rollback_flow(flow, translated)
        } else {
            rule.pool_allocator.release_flow(flow, translated, _now_ns)
        };
        if released {
            break;
        }
    }
}

pub(crate) fn source_nat_pool_statuses(rules: &[SourceNatRule]) -> Vec<SourceNatPoolStatus> {
    rules
        .iter()
        .filter(|rule| rule.pool_mode)
        .map(|rule| {
            let snap = rule.pool_allocator.snapshot();
            SourceNatPoolStatus {
                rule_name: rule.name.clone(),
                pool_name: rule.pool_name.clone(),
                address_count: rule.pool_addresses_v4.len() + rule.pool_addresses_v6.len(),
                port_low: rule.pool_allocator.port_low,
                port_high: rule.pool_allocator.port_high,
                persistent_nat: rule.persistent_nat,
                persistent_nat_permit_any_remote_host: rule.persistent_nat_permit_any_remote_host,
                persistent_nat_inactivity_timeout: rule.persistent_nat_inactivity_timeout_secs,
                live_flows: snap.live_flows,
                used_ports: snap.used_ports,
                persistent_leases: snap.persistent_leases,
                max_tracked_flows: snap.max_tracked_flows,
                allocations_total: snap.allocations_total,
                reuses_total: snap.reuses_total,
                exhaustion_total: snap.exhaustion_total,
            }
        })
        .collect()
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
    match match_source_nat_result(
        rules, from_zone, to_zone, src_ip, dst_ip, egress_v4, egress_v6,
    ) {
        SourceNatLookup::Matched(decision) => Some(decision),
        SourceNatLookup::NoMatch | SourceNatLookup::Unavailable(_) => None,
    }
}

pub(crate) fn match_source_nat_result(
    rules: &[SourceNatRule],
    from_zone: &str,
    to_zone: &str,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    egress_v4: Option<Ipv4Addr>,
    egress_v6: Option<Ipv6Addr>,
) -> SourceNatLookup {
    match_source_nat_result_for_tuple(
        rules, from_zone, to_zone, src_ip, dst_ip, 0, 0, 0, egress_v4, egress_v6, 0,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn match_source_nat_result_for_tuple(
    rules: &[SourceNatRule],
    from_zone: &str,
    to_zone: &str,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    egress_v4: Option<Ipv4Addr>,
    egress_v6: Option<Ipv6Addr>,
    now_ns: u64,
) -> SourceNatLookup {
    let flow = SourceNatFlowKey {
        protocol,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
    };
    for rule in rules {
        if !rule.matches(from_zone, to_zone, src_ip, dst_ip) {
            continue;
        }
        if rule.off {
            return SourceNatLookup::Matched(NatDecision::default());
        }
        if rule.interface_mode {
            let rewrite_src = match src_ip {
                IpAddr::V4(_) => egress_v4.map(IpAddr::V4),
                IpAddr::V6(_) => egress_v6.map(IpAddr::V6),
            };
            return SourceNatLookup::Matched(NatDecision {
                rewrite_src,
                rewrite_dst: None,
                ..NatDecision::default()
            });
        }
        if rule.pool_mode {
            if let Some(reason) = rule.pool_failure {
                return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(rule, reason));
            }
        } else {
            continue;
        }
        // Pool-mode SNAT: pick address by source-IP hash when
        // address-persistent is enabled, otherwise round-robin by family.
        let tupleless_lookup = protocol == 0 && src_port == 0 && dst_port == 0;
        match src_ip {
            IpAddr::V4(_) if !rule.pool_addresses_v4.is_empty() => {
                if tupleless_lookup {
                    let addr_idx = rule.pool_allocator.address_index(
                        src_ip,
                        0,
                        rule.pool_addresses_v4.len(),
                        rule.address_persistent,
                    );
                    let pool_addr = rule.pool_addresses_v4[addr_idx];
                    let port = match rule.pool_allocator.try_next_port(addr_idx) {
                        Ok(port) => port,
                        Err(reason) => {
                            return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(
                                rule, reason,
                            ));
                        }
                    };
                    return SourceNatLookup::Matched(NatDecision {
                        rewrite_src: Some(IpAddr::V4(pool_addr)),
                        rewrite_dst: None,
                        rewrite_src_port: Some(port),
                        rewrite_dst_port: None,
                        ..NatDecision::default()
                    });
                }
                let translated = match rule.pool_allocator.allocate_translation(
                    flow,
                    PoolAddressFamily::V4(&rule.pool_addresses_v4),
                    0,
                    rule.address_persistent,
                    rule.persistent_nat,
                    rule.persistent_nat_timeout_ns,
                    now_ns,
                ) {
                    Ok(translated) => translated,
                    Err(reason) => {
                        return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(
                            rule, reason,
                        ));
                    }
                };
                return SourceNatLookup::Matched(NatDecision {
                    rewrite_src: Some(translated.ip),
                    rewrite_dst: None,
                    rewrite_src_port: Some(translated.port),
                    rewrite_dst_port: None,
                    ..NatDecision::default()
                });
            }
            IpAddr::V6(_) if !rule.pool_addresses_v6.is_empty() => {
                let v6_offset = rule.pool_addresses_v4.len();
                if tupleless_lookup {
                    let addr_idx = rule.pool_allocator.address_index(
                        src_ip,
                        v6_offset,
                        rule.pool_addresses_v6.len(),
                        rule.address_persistent,
                    );
                    let v6_idx = addr_idx - v6_offset;
                    let pool_addr = rule.pool_addresses_v6[v6_idx];
                    let port = match rule.pool_allocator.try_next_port(addr_idx) {
                        Ok(port) => port,
                        Err(reason) => {
                            return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(
                                rule, reason,
                            ));
                        }
                    };
                    return SourceNatLookup::Matched(NatDecision {
                        rewrite_src: Some(IpAddr::V6(pool_addr)),
                        rewrite_dst: None,
                        rewrite_src_port: Some(port),
                        rewrite_dst_port: None,
                        ..NatDecision::default()
                    });
                }
                let translated = match rule.pool_allocator.allocate_translation(
                    flow,
                    PoolAddressFamily::V6(&rule.pool_addresses_v6),
                    v6_offset,
                    rule.address_persistent,
                    rule.persistent_nat,
                    rule.persistent_nat_timeout_ns,
                    now_ns,
                ) {
                    Ok(translated) => translated,
                    Err(reason) => {
                        return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(
                            rule, reason,
                        ));
                    }
                };
                return SourceNatLookup::Matched(NatDecision {
                    rewrite_src: Some(translated.ip),
                    rewrite_dst: None,
                    rewrite_src_port: Some(translated.port),
                    rewrite_dst_port: None,
                    ..NatDecision::default()
                });
            }
            _ => {
                return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(
                    rule,
                    SourceNatFailureReason::WrongAddressFamily,
                ));
            }
        }
    }
    SourceNatLookup::NoMatch
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
