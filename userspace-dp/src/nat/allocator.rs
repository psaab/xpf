// Pool-mode SNAT port allocator + persistent lease state machine.
//
// #2852 Phase 1 (lock-free port claim): the port-ownership state is no
// longer serialized behind the single `Mutex<PortAllocatorLiveState>`.
// Per-pool-address occupancy is an atomic bitmap (`AddressOccupancy`,
// `Vec<AtomicU64>` + an atomic fresh-port cursor); a CAS on the bit IS the
// port-ownership token (a set bit cannot be re-claimed), replacing the
// pre-#2852 `owner_by_translated` / `addr_index_by_translated` maps and the
// per-address `next_port_offset_by_addr` cursor. The port CLAIM (the
// contended hot path in `allocate_translation`) is therefore lock-free: a
// non-persistent new flow claims its port with zero global-mutex contention
// and takes the (retained) mutex only for the tiny `live_by_flow`
// insert/reuse-check/exact-cap-check critical section. The microbench
// `benches/snat_allocator.rs` (results in docs/research/2852-portalloc/)
// proved the pre-Phase-1 single mutex negative-scales (2.87M->0.62M
// allocs/sec, M=1->8); Phase 1 is 1.4-1.6x at M=6/8.
//
// What stays under `Mutex<PortAllocatorLiveState>`: the flow map
// (`live_by_flow`), the persistent-lease lifecycle (`persistent_by_source` +
// the two expiration indexes), and `gc_counter`. Phase 2 (hash-sharding
// those maps, deferred) is only warranted if the residual map mutex is the
// next bottleneck.
//
// F4 (global tracked-flow cap): kept EXACT with no overshoot. The cap is
// `live_by_flow.len()` re-checked under the tiny insert mutex, where the map
// length is authoritative — so it never overshoots and a tiny pool near
// capacity is NOT falsely exhausted. This is strictly better than the
// microbench's atomic `fetch_add`-reserve model (which surfaced an M-in-
// flight overshoot on tiny pools): that overshoot only exists when the cap
// is checked OUTSIDE any lock (the Phase-2 sharded world); Phase 1 keeps the
// maps under one mutex, so the exact `len()` check is available and used.
//
// FIFO recycle (#3011): freed ports still recycle oldest-first to spread
// reuse across the upstream 2MSL/TIME_WAIT window. The queue is a per-ADDRESS
// `Mutex<VecDeque<u16>>` (`AddressOccupancy::recycle`) — a much smaller,
// per-address critical section than the pre-#2852 global mutex, and it
// preserves the EXACT `push_back`/`pop_front` ordering the #3011 tests pin
// (a fully lock-free MPMC recycle ring is a Phase-2 option; `crossbeam` is
// not a dependency and a hand-rolled lock-free ring is not worth the risk on
// this hot NAT path). Lock ordering is always global -> recycle (the recycle
// mutex is innermost, never held while acquiring the global mutex), so there
// is no deadlock (plan F5 is sidestepped entirely: Phase 1 has no two-map-
// shard path).
//
// Port claim (AddressOccupancy::claim) collision handling (#3047):
// - Sequential phase: the monotonic per-address cursor is probed FORWARD,
//   one offset at a time (a bounded CAS hands each fresh offset to exactly
//   one claimer and never advances past the range), until a free port is
//   CAS-claimed or the range is genuinely exhausted. A single collision with
//   an out-of-band occupant (a persistent lease or an HA-synced install
//   whose bit sits at the cursor's offset) advances past it instead of
//   aborting the whole allocation (062-05). The common case claims on the
//   first probe.
// - Recycled phase: when the sequential range is spent, recycled ports are
//   drained FIFO (oldest-freed first, pop_front) so a just-freed port is the
//   LAST to be reassigned — this spreads port reuse across the upstream's
//   2MSL/TIME_WAIT window instead of immediately recycling the most recent
//   port (#3011). A popped port whose bit is already set is RETAINED (re-
//   queued at the back), never discarded, so a transient collision cannot
//   permanently shrink the reusable pool (062-10). The retain buffer
//   allocates lazily only when a collision actually occurs.
//
// Aggregate construction budget (#6812): `PortAllocator::new` is the memory
// heavyweight — one `AddressOccupancy` word array per pool address, sized to
// the port range (one bit per port slot). Construction is therefore gated
// TWICE upstream in `source.rs`: the Go #5877 strict commit gate rejects an
// over-budget config outright, and `resolve_pool_allocators` enforces the
// same budgets (pool count / total addresses / total port slots, charged
// per distinct allocator key, reuse-before-build, nothing built for a
// failed pool) at this apply boundary — the final backstop for a tolerated
// (lenient-load / peer-synced) or hand-crafted snapshot. Three full-range
// /16 pools would otherwise materialise 12,683,575,296 bitmap bits
// (~1.48 GiB) during apply.
//
// Cross-submodule visibility (per #1542 plan v3):
// - PortAllocator and PortAllocatorSnapshot are pub(crate) at definition
//   (re-exported by nat/mod.rs).
// - PortAllocator's state-machine methods (try_next_port, address_index,
//   allocate_translation, release_flow, rollback_flow, snapshot) are
//   pub(super) so source.rs / status.rs can drive them.
// - Live state struct + the fields that white-box tests inspect
//   (persistent_by_source, lease_expirations, lease_expirations_by_addr) are
//   pub(super). Port-ownership is inspected via the `#[cfg(test)]` debug
//   accessors (debug_is_port_occupied / debug_recycled_ports /
//   debug_set_cursor / debug_set_recycled / debug_occupied_count).
// - PersistentLease + its fields are pub(super) for the same reason.
// - The remaining types (LiveAllocation, AddressOccupancy, PortAllocatorShared
//   and its private fields, GC constants, capacity/sticky helpers) stay
//   fully private to this file.

use super::source::SourceNatFlowKey;
use rustc_hash::FxHashMap;
use std::collections::{BTreeSet, VecDeque};
use std::hash::Hasher;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
// #4800: both are now used unconditionally by `PortAllocator::lock_live`
// (previously `MutexGuard` was test-only, for `debug_live`).
use std::sync::{MutexGuard, TryLockError};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};

pub(super) const NS_PER_SEC: u64 = 1_000_000_000;
const MAX_SOURCE_NAT_POOL_TRACKED_FLOWS: usize = 262_144;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct PersistentSourceKey {
    pub(super) protocol: u8,
    pub(super) src_ip: IpAddr,
    pub(super) src_port: u16,
    /// #2397: remote (destination) endpoint scope. `None` => the lease is
    /// reusable by ANY remote host (`persistent-nat permit-any-remote-host`).
    /// `Some((dst_ip, dst_port))` => the lease is bound to the original remote
    /// endpoint (the disabled-flag / Junos target-host[-port] mode): a second
    /// flow from the same local source to a DIFFERENT remote 5-tuple keys to a
    /// distinct lease and therefore gets a distinct translated mapping.
    pub(super) remote: Option<(IpAddr, u16)>,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) struct TranslatedTuple {
    pub(crate) ip: IpAddr,
    pub(crate) port: u16,
}

/// #6751: how many PAT candidates one `live`-mutex acquisition may probe
/// before releasing it and yielding. A full-cycle probe on an exhausted
/// identity space is 64512 map lookups; holding the mutex across all of them
/// would stall every other worker's admission on this egress address for the
/// whole walk. The #4676 `gc_expired_chunked` budget discipline, applied to the
/// only other unbounded loop under this mutex.
const INTERFACE_PAT_PROBE_CHUNK: u32 = 64;

/// #6751: the outcome of an interface-mode identity mint.
///
/// `patted` is the discriminator the caller needs and cannot re-derive: it
/// decides whether the decision carries `rewrite_src_port: Some(port)` (the
/// wire moves) or leaves it unset (the wire is byte-identical to pre-#6751).
/// Returning the port alone would force the caller to compare it against the
/// flow's source port, which is the same thing said less directly and goes
/// wrong the moment a port-less protocol reports 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct InterfaceIdentity {
    pub(super) port: u16,
    pub(super) patted: bool,
}

/// #6751 §5.3: a domain's answer to "do you own this translated identity?".
///
/// The tri-state distinction lives in [`super::source::SyncedReserveOutcome`]
/// for the whole synced-reserve scan; this is the per-allocator half of it, and
/// deliberately carries only the two answers an allocator that HAS been asked
/// can give. "Not this domain" is decided one level up, by whether the registry
/// holds an allocator for the address at all — an allocator cannot report that
/// about itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum InterfaceDomainReserve {
    /// The reservation is held for this flow.
    Owned,
    /// A DIFFERENT flow owns the requested identity. The caller must fail
    /// closed — never fall through to another domain, or the two domains both
    /// hand out one identity.
    IdentityConflict,
    /// The allocator could not create a further ownership record (its
    /// per-address tracked-flow cap). Kept SEPARATE from `IdentityConflict`
    /// because the two have different remedies and different §5.8 counters:
    /// this one says the node is out of bookkeeping capacity, that one says a
    /// live flow already owns this exact translated identity. Folding them
    /// would leave an operator unable to tell "raise capacity" from "a peer's
    /// session lost a race with a local flow".
    RegistryCap,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum PoolAddressFamily<'a> {
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

/// #6211 F2: the widest `worker_id` the [`LiveAllocation::holders`] bitmask can
/// represent. A worker whose id does not fit could set no bit on reserve and
/// clear no bit on release — self-consistent, but it collapses that worker back
/// to the pre-#6211-F2 single-holder behaviour (first release frees a port a
/// still-forwarding worker holds). The bound is therefore enforced where worker
/// ids are MINTED (`server::helpers::planning::replan_bindings_from_candidates`,
/// which refuses the whole plan), not here — an out-of-range id must never reach
/// the allocator in the first place.
///
/// Enforced at the mint site rather than on the raw `--workers` value because
/// the effective id range is `min(queue_count, workers)`: `queue_count` is the
/// per-interface RX-queue minimum, computed independently of `workers`, and the
/// id is `queue_id % workers` with `queue_id < queue_count`. Capping `--workers`
/// alone would refuse a SAFE configuration (`--workers 200` on a 16-queue NIC
/// mints ids 0..15).
pub(crate) const MAX_NAT_HOLDER_WORKERS: u32 = 128;

/// Tie the mask WIDTH to the constant so the two cannot drift apart: widening
/// `holders` without raising the bound (or vice versa) fails the build here
/// rather than silently truncating a holder bit at runtime.
const _: () = assert!(u128::BITS == MAX_NAT_HOLDER_WORKERS);

/// #6765: what a `reseed_retained_from` pass carried and what it could not.
/// Returned rather than logged inside the allocator so the caller can report it
/// once per apply with the pool name attached — and so a drop is never silent,
/// which is the same class of defect the re-seed exists to fix.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReseedOutcome {
    /// Live allocations re-seeded onto a retained address.
    pub(crate) reseeded: usize,
    /// Skipped: the port falls outside the NEW port range (range narrowed).
    pub(crate) skipped_out_of_range: usize,
    /// Skipped: an address-only (`port no-translation`) token, which holds no
    /// port bit and is outside the port-reissue defect.
    pub(crate) skipped_address_only: usize,
    /// `reserve_flow` refused — the tuple is already owned in the new
    /// allocator. Expected to be zero on a freshly built allocator.
    pub(crate) refused: usize,
}

/// #6211 F2: which worker is taking or dropping a reservation.
///
/// `Untracked` reproduces the pre-#6211-F2 contract exactly — a reserve sets no
/// holder bit and a release frees on the first call.
///
/// #7093: it is NOT "what every LOCAL allocation path uses", and the reason
/// given for that — "RSS steers a given 5-tuple to exactly ONE worker so a local
/// allocation has exactly one holder" — is false. A locally-born session is
/// replicated to every OTHER worker and each sibling reserves against the
/// owner's record, so the mask named every worker except the one forwarding.
/// #6522 fixed that: `allocate_translation` and friends now take a `holder` and
/// production passes `Worker(id)`. `Untracked` is what the `#[cfg(test)]` entry
/// points and the read-only fragment probe pass, and nothing else.
///
/// `Worker(id)` is used by the HA-synced reservation path, where the SAME
/// `(flow, translated)` is reserved once per worker: `handle_upsert_synced` runs
/// on every worker (`afxdp/ha/session_import.rs` fans the entry out to each
/// worker's command queue) against ONE shared allocator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NatHolder {
    Untracked,
    Worker(u32),
}

impl NatHolder {
    /// The holder's bit in [`LiveAllocation::holders`]. `Untracked` — and any id
    /// the mint-site check should have refused — contributes no bit.
    fn bit(self) -> u128 {
        match self {
            Self::Untracked => 0,
            Self::Worker(id) => {
                debug_assert!(
                    id < MAX_NAT_HOLDER_WORKERS,
                    "worker_id {id} exceeds MAX_NAT_HOLDER_WORKERS; \
                     replan_bindings_from_candidates must refuse the plan"
                );
                1u128.checked_shl(id).unwrap_or(0)
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct LiveAllocation {
    translated: TranslatedTuple,
    persistent_key: Option<PersistentSourceKey>,
    // #2852 F7: the pool-address index this translation was claimed on, stored
    // in the record so release is O(1) — the pre-#2852 `addr_index_by_translated`
    // reverse map is gone (the occupancy bitmap is per-address, so freeing the
    // bit needs the address index, and reading it off the record avoids a map
    // lookup). For a persistent flow the authoritative index is on the lease;
    // this copy mirrors it so the non-persistent / deterministic release paths
    // are uniform.
    addr_index: usize,
    // #4559: a deterministic CGNAT block allocation. Its port is NOT pushed onto
    // the per-address recycle queue on release (`free`-path `recycle = false`) —
    // the deterministic claim scans its subscriber block against the occupancy
    // bitmap directly, so a freed port becomes claimable again the moment its
    // bit clears. Recycling it too would let the queue grow without bound across
    // per-subscriber flow churn (a deterministic-only pool never drains the
    // recycle queue). `false` for every round-robin/persistent allocation
    // (unchanged behaviour).
    deterministic: bool,
    // #5269: an address-only occupancy token (port no-translation / port-less
    // source NAT). No pool PORT is consumed on the occupancy bitmap — the packet
    // keeps its own source port on the wire — so release must NOT free a port
    // bit; instead it clears the reverse-identity entry in `address_only_owners`.
    // `false` for every PAT / deterministic / persistent allocation.
    address_only: bool,
    // #6211 F2: the set of WORKERS holding this reservation, one bit per
    // `worker_id` (see `NatHolder` / `MAX_NAT_HOLDER_WORKERS`). An HA-synced
    // session is pushed to EVERY worker's session table while the source-NAT
    // allocator is a single shared `Arc`, so N workers reserve the same
    // `(flow, translated)` and each releases it independently — the reap, the
    // fanned-out `DeleteSynced`, and the alias purge all run per worker.
    //
    // Before this field the N reserves collapsed into one record (`reserve_flow`
    // returns `true` and does nothing when the flow already holds this exact
    // tuple) and the FIRST release freed the port while the other N-1 workers
    // still held the session and forwarded through it. That is the steady state
    // after any failover carrying a synced SNAT session older than the
    // inactivity timeout: the active's periodic `UpsertSynced` refresh stops,
    // RSS lands the traffic on exactly one worker, and the other N-1 replicas
    // idle out with nothing refreshing them.
    //
    // `0` means "untracked" — a LOCAL allocation, which by construction has a
    // single holder (RSS steers a 5-tuple to one worker) — and keeps the
    // pre-#6211-F2 contract: the first release frees. A non-zero mask frees only
    // when the LAST holder's bit clears.
    //
    // A bitmask rather than a counter because `reserve_flow`'s idempotent early
    // return is BOTH where workers 2..N first land AND the path every refresh
    // from an ALREADY-holding worker takes (each HA session-sync reconnect, each
    // periodic re-`UpsertSynced`). OR is idempotent there; increment is not, and
    // would inflate without bound and never drain to zero.
    //
    // `u128` keeps `LiveAllocation` `Copy` (both read paths use `.copied()`), so
    // no `Vec`/`HashSet` allocation enters the per-flow record.
    holders: u128,
}

/// #5269: reverse-identity ownership key for an address-only (port
/// no-translation / port-less) source-NAT translation. The reverse conntrack
/// demux keys a reply on (protocol, translated source IP, translated source
/// port, remote IP, remote port); two forward flows that would produce the SAME
/// reverse identity cannot coexist because their replies are indistinguishable,
/// so the allocator grants each identity to exactly ONE flow and denies a
/// genuinely-colliding second flow as exhaustion. `translated_port` is the
/// PRESERVED source port for a port-bearing protocol, or 0 for a port-less
/// protocol (GRE/ESP/AH/...). This is the address-only analogue of the PAT
/// occupancy bit: PAT keeps `(pool_addr, port)` unique by handing out a fresh
/// port; address-only cannot move the port, so it enforces uniqueness on the
/// full reverse identity instead.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(super) struct AddressOnlyReverseKey {
    pub(super) protocol: u8,
    pub(super) translated_ip: IpAddr,
    pub(super) translated_port: u16,
    pub(super) dst_ip: IpAddr,
    pub(super) dst_port: u16,
}

impl AddressOnlyReverseKey {
    /// #6751: the ONE construction the interface-mode registry uses, for the
    /// occupancy CHECK, the record INSERT and the synced RESERVE alike.
    ///
    /// These three must agree by construction, not by three literals that
    /// happen to match. A check keyed differently from its insert is invisible
    /// to every behavioural test: the check finds nothing, so every flow
    /// preserves and every mint "succeeds" — which is exactly the pre-#6751
    /// behaviour the fix exists to remove, restored silently. (The pool-mode
    /// paths keep their own inline literals; they are the shipped shape, and
    /// re-keying them is not this change's business. The end-to-end release
    /// test binds this constructor against what
    /// `unlink_live_allocation_locked` removes.)
    fn for_flow(flow: &SourceNatFlowKey, translated_ip: IpAddr, translated_port: u16) -> Self {
        Self {
            protocol: flow.protocol,
            translated_ip,
            translated_port,
            dst_ip: flow.dst_ip,
            dst_port: flow.dst_port,
        }
    }
}

/// #4559: IPv4 deterministic CGNAT (mode 1) block-allocation parameters,
/// precomputed by the Go compiler and carried on the source-NAT rule. The
/// mapping is `subscriber internal IPv4 -> fixed (external pool IP, port
/// block)`, reversible from `(external IP, port)` back to the subscriber with
/// NO per-flow state (the whole point of deterministic NAT: lawful-intercept /
/// CGN audit without per-connection logging). Reproduces the retired-eBPF
/// `nat_pool_alloc_deterministic_v4` logic (pkg/dataplane/compiler_nat.go /
/// the deleted bpf/xdp/xdp_policy.c) in the userspace dataplane.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DeterministicV4 {
    /// Ports per subscriber block (Junos `block-size`).
    pub(crate) block_size: u16,
    /// Blocks each external pool address carries
    /// (`(port_high - port_low + 1) / block_size`).
    pub(crate) blocks_per_ip: u16,
    /// Subscriber-CIDR network address, host-order u32.
    pub(crate) host_base: u32,
    /// Subscriber count in the host CIDR (`1 << (32 - prefix_len)`).
    pub(crate) host_count: u32,
}

/// #4559: map a subscriber IPv4 to its deterministic `(ip_idx, block_idx)`.
/// `ip_idx` selects the external pool address; `block_idx` selects the port
/// block within that address. Returns `None` when the subscriber is outside the
/// configured host range or the parameters are degenerate (`blocks_per_ip == 0`
/// / `block_size == 0`) — the caller fails the allocation closed rather than
/// silently round-robining a subscriber that has no reserved block.
pub(crate) fn deterministic_indices_v4(
    params: &DeterministicV4,
    src: Ipv4Addr,
) -> Option<(usize, u32)> {
    let bpi = params.blocks_per_ip as u32;
    if bpi == 0 || params.block_size == 0 {
        return None;
    }
    let src_h = u32::from(src);
    if src_h < params.host_base {
        return None;
    }
    let sub_idx = src_h - params.host_base;
    if sub_idx >= params.host_count {
        return None;
    }
    let ip_idx = (sub_idx / bpi) as usize;
    let block_idx = sub_idx % bpi;
    Some((ip_idx, block_idx))
}

/// #5660: O(1) reverse index for a deterministic-NAT external pool. Maps each
/// external pool IPv4 address to its position in the ordered `pool_v4` list —
/// the SAME index the forward path selects with `pool_v4[ip_idx]`. It replaces
/// the reverse path's `pool_v4.iter().position()` linear scan (up to
/// `MAX_POOL_PREFIX_HOSTS` = 65536 addresses) with a single hash lookup.
///
/// The pool is an ARBITRARY, possibly non-contiguous ordered address list (the
/// NAT64 path builds it by parsing configured pool strings, and a source-NAT
/// pool may span several disjoint ranges), so `ip_idx` is a POSITION in the
/// list, not an arithmetic offset from a base — a direct `translated_ip -
/// pool_base` subtraction would be wrong. Build this ONCE at prefix/rule build
/// time with [`build_pool_reverse_index`] and reuse it for every reverse
/// lookup; rebuilding it per lookup is O(N) again (and allocates). First
/// occurrence of a (pathologically) duplicated pool address wins, exactly
/// mirroring the `position()` first-match semantics it replaces.
pub(crate) type PoolReverseIndex = FxHashMap<Ipv4Addr, u32>;

/// #5660: build the [`PoolReverseIndex`] from an ordered deterministic-NAT
/// external pool. First-match wins for a duplicated address (matches the
/// `position()` scan this replaces).
pub(crate) fn build_pool_reverse_index(pool_v4: &[Ipv4Addr]) -> PoolReverseIndex {
    let mut index = FxHashMap::default();
    index.reserve(pool_v4.len());
    for (idx, &addr) in pool_v4.iter().enumerate() {
        index.entry(addr).or_insert(idx as u32);
    }
    index
}

/// #4559: reverse a deterministic translated `(external pool IP, port)` back to
/// the subscriber's internal IPv4 with NO per-flow state — the CGN-compliance
/// property that motivates deterministic NAT. `pool_index` is the pool's O(1)
/// reverse index ([`build_pool_reverse_index`], keyed by the same ordered
/// external-address list the forward path indexes); `port_low` is the pool's
/// low port. Returns `None` when the tuple does not fall in the deterministic
/// space (unknown external IP, port below `port_low`, or a block/subscriber
/// index out of range).
pub(crate) fn reverse_deterministic_v4(
    params: &DeterministicV4,
    pool_index: &PoolReverseIndex,
    port_low: u16,
    translated_ip: Ipv4Addr,
    translated_port: u16,
) -> Option<Ipv4Addr> {
    if params.block_size == 0 {
        return None;
    }
    let ip_idx = *pool_index.get(&translated_ip)?;
    if translated_port < port_low {
        return None;
    }
    let offset = (translated_port - port_low) as u32;
    let block_idx = offset / params.block_size as u32;
    if block_idx >= params.blocks_per_ip as u32 {
        return None;
    }
    let sub_idx = ip_idx
        .checked_mul(params.blocks_per_ip as u32)?
        .checked_add(block_idx)?;
    if sub_idx >= params.host_count {
        return None;
    }
    let host = params.host_base.checked_add(sub_idx)?;
    Some(Ipv4Addr::from(host))
}

/// #4559: IPv6-subscriber deterministic CGNAT (mode 2, NAPT64) block-allocation
/// parameters. An IPv6 subscriber deterministically maps to a fixed external
/// IPv4 pool address + port block, reversible from `(external IPv4, port)` back
/// to the subscriber's IPv6 prefix with NO per-flow state — the same
/// lawful-intercept / CGN-audit property as mode 1, but for the v6→v4 (NAT64)
/// direction. Reproduces the retired-eBPF `nat_pool_alloc_deterministic_v6`
/// logic (the deleted bpf/xdp/xdp_policy.c). The difference from mode 1 is the
/// subscriber-index derivation: the 32-bit word AFTER the configured IPv6
/// prefix (`/32` → octet offset 4, `/64` → octet offset 8) is the subscriber
/// index, not an IPv4 host offset.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DeterministicV6 {
    /// Ports per subscriber block (Junos `block-size`).
    pub(crate) block_size: u16,
    /// Blocks each external pool address carries
    /// (`(port_high - port_low + 1) / block_size`), computed against the fixed
    /// NAT64 translated-port range so block boundaries align with the allocator.
    pub(crate) blocks_per_ip: u16,
    /// IPv6 subscriber-prefix length: 32 or 64. Selects the subscriber-index
    /// word offset (32 → octets[4..8], 64 → octets[8..12]).
    pub(crate) host_prefix_len: u8,
    /// IPv6 subscriber-CIDR network base, network-order octets. Forward
    /// extraction reads the subscriber word off `src` at the prefix-selected
    /// offset relative to this base; the reverse path reconstructs it.
    pub(crate) host_base: [u8; 16],
    /// Maximum subscriber index the pool can serve
    /// (`pool_v4.len() * blocks_per_ip`). An IPv6 subscriber word extends far
    /// beyond pool capacity, so — unlike mode 1's CIDR-derived count — this is
    /// bounded by the pool, computed at `Nat64Prefix` build time from the parsed
    /// pool. A subscriber beyond it fails the allocation closed.
    pub(crate) host_count: u32,
}

/// #4559: byte offset of the 32-bit subscriber-index word for a mode-2 prefix
/// length. `/64` → octets[8..12] (the word after a /64 prefix), everything else
/// (only `/32` is otherwise built) → octets[4..8]. Mirrors the retired-eBPF
/// `host_prefix_len == 64 ? +8 : +4` split.
fn deterministic_v6_word_offset(host_prefix_len: u8) -> usize {
    if host_prefix_len == 64 { 8 } else { 4 }
}

/// #4559: map an IPv6 subscriber to its deterministic `(ip_idx, block_idx)` for
/// mode 2 (NAPT64). `ip_idx` selects the external IPv4 pool address; `block_idx`
/// selects the port block within it. The subscriber index is the host-order
/// 32-bit word AFTER the configured prefix minus the base's same word. Returns
/// `None` when the subscriber is below the base, beyond the pool-bounded
/// `host_count`, or the parameters are degenerate — the caller fails the
/// allocation closed rather than silently round-robining.
///
/// #4863: the source MUST lie inside the configured subscriber prefix. The
/// subscriber index is derived only from the 32-bit word at `off`, so a source
/// in a DIFFERENT prefix that happens to share that word would otherwise be
/// accepted and mapped into the in-prefix subscriber's fixed block — and the
/// stateless `reverse_deterministic_v6` (which reconstructs from `host_base`)
/// would then attribute the external `(IPv4, port)` to the WRONG subscriber
/// (cross-tenant block assignment + a lying reverse map). Reject any source
/// whose prefix bytes before the subscriber word differ from `host_base`. For
/// a /32 the checked prefix is `octets[0..4]`, for a /64 `octets[0..8]` — the
/// bytes at `off` are exactly the configured prefix length. This is a
/// drop-only tightening: an in-prefix source is unaffected.
pub(crate) fn deterministic_indices_v6(
    params: &DeterministicV6,
    src: Ipv6Addr,
) -> Option<(usize, u32)> {
    let bpi = params.blocks_per_ip as u32;
    if bpi == 0 || params.block_size == 0 {
        return None;
    }
    let off = deterministic_v6_word_offset(params.host_prefix_len);
    let src_octets = src.octets();
    // #4863: fail closed for any source outside the configured subscriber
    // prefix. The subscriber word alone does not identify the tenant — the
    // prefix bytes before it must match the configured base exactly, else a
    // colliding subscriber word in a different prefix would steal an in-prefix
    // subscriber's block and be reverse-mapped to the wrong subscriber.
    if src_octets[..off] != params.host_base[..off] {
        return None;
    }
    let src_word = u32::from_be_bytes([
        src_octets[off],
        src_octets[off + 1],
        src_octets[off + 2],
        src_octets[off + 3],
    ]);
    let base_word = u32::from_be_bytes([
        params.host_base[off],
        params.host_base[off + 1],
        params.host_base[off + 2],
        params.host_base[off + 3],
    ]);
    if src_word < base_word {
        return None;
    }
    let sub_idx = src_word - base_word;
    if sub_idx >= params.host_count {
        return None;
    }
    let ip_idx = (sub_idx / bpi) as usize;
    let block_idx = sub_idx % bpi;
    Some((ip_idx, block_idx))
}

/// #4559: reverse a deterministic translated `(external IPv4 pool address,
/// port)` back to the subscriber's IPv6 prefix with NO per-flow state — the
/// CGN-compliance property that motivates deterministic NAPT64. `pool_index` is
/// the prefix's O(1) reverse index ([`build_pool_reverse_index`], keyed by the
/// same ordered external-address list the forward path indexes); `port_low` is
/// the allocator's low port. The recovered address is the subscriber PREFIX
/// (network base + subscriber word, trailing interface-identifier bytes left as
/// the base's — zero for a network base): the deterministic unit is the
/// subscriber prefix, not the full /128 host. Returns `None` when the tuple
/// does not fall in the deterministic space.
pub(crate) fn reverse_deterministic_v6(
    params: &DeterministicV6,
    pool_index: &PoolReverseIndex,
    port_low: u16,
    translated_ip: Ipv4Addr,
    translated_port: u16,
) -> Option<Ipv6Addr> {
    if params.block_size == 0 {
        return None;
    }
    let ip_idx = *pool_index.get(&translated_ip)?;
    if translated_port < port_low {
        return None;
    }
    let offset = (translated_port - port_low) as u32;
    let block_idx = offset / params.block_size as u32;
    if block_idx >= params.blocks_per_ip as u32 {
        return None;
    }
    let sub_idx = ip_idx
        .checked_mul(params.blocks_per_ip as u32)?
        .checked_add(block_idx)?;
    if sub_idx >= params.host_count {
        return None;
    }
    let off = deterministic_v6_word_offset(params.host_prefix_len);
    let base_word = u32::from_be_bytes([
        params.host_base[off],
        params.host_base[off + 1],
        params.host_base[off + 2],
        params.host_base[off + 3],
    ]);
    let sub_word = base_word.checked_add(sub_idx)?;
    let mut octets = params.host_base;
    octets[off..off + 4].copy_from_slice(&sub_word.to_be_bytes());
    Some(Ipv6Addr::from(octets))
}

#[derive(Clone, Copy, Debug)]
pub(super) struct PersistentLease {
    pub(super) translated: TranslatedTuple,
    pub(super) addr_index: usize,
    pub(super) expires_at_ns: u64,
    pub(super) timeout_ns: u64,
    pub(super) active_flows: u32,
    pub(super) completed_flows: u64,
    // Rollback needs per-activation completion state, not a comparison
    // against lifetime completion counters. The latter can saturate over
    // long-lived persistent leases and make a fresh completion invisible.
    pub(super) activation_saw_completion: bool,
    pub(super) activation_previous_expires_at_ns: u64,
    pub(super) activation_had_previous_lease: bool,
    // #6041: an ADDRESS-ONLY persistent lease (`persistent-nat` + `port
    // no-translation` / a port-less protocol). It pins a public ADDRESS across
    // the permit scope but consumes NO pool port — `translated.port` carries the
    // FIRST flow's preserved source port for status/debug only and is never a
    // bit on the occupancy bitmap. So every lease teardown site
    // (`reuse_existing_lease_locked` expired, `rollback_flow` remove-lease,
    // `reclaim_expired_lease_locked` GC) MUST skip `free_translated_port` when
    // this is set — there is no port bit to free, and freeing address `port`
    // would clear a DIFFERENT flow's PAT bit that happens to share the offset.
    // Per-flow reverse-identity collision ownership (#5269) is still tracked in
    // `address_only_owners`, minted/cleared per flow, independent of the lease.
    // `false` for every port-translating PAT lease (unchanged behaviour).
    pub(super) address_only: bool,
}

#[derive(Debug, Default)]
pub(super) struct PortAllocatorLiveState {
    live_by_flow: FxHashMap<SourceNatFlowKey, LiveAllocation>,
    pub(super) persistent_by_source: FxHashMap<PersistentSourceKey, PersistentLease>,
    pub(super) lease_expirations: BTreeSet<(u64, PersistentSourceKey)>,
    pub(super) lease_expirations_by_addr: Vec<BTreeSet<(u64, PersistentSourceKey)>>,
    // #5269: address-only occupancy tokens — the translated reverse identity of a
    // `port no-translation` / port-less flow mapped to its owning FORWARD flow.
    // Populated by `reserve_address_only` (which denies a second flow that would
    // claim an already-owned identity) and cleared by `release_flow` /
    // `rollback_flow` for an `address_only` `LiveAllocation`. Distinct from the
    // per-address occupancy bitmap, which tracks PAT port ownership.
    address_only_owners: FxHashMap<AddressOnlyReverseKey, SourceNatFlowKey>,
    gc_counter: u32,
}

impl PortAllocatorLiveState {
    fn new(addr_count: usize) -> Self {
        Self {
            lease_expirations_by_addr: vec![BTreeSet::new(); addr_count],
            ..Self::default()
        }
    }
}

/// #2852 Phase 1: per-pool-address atomic occupancy for lock-free port claim.
///
/// `words` is the occupancy bitmap (bit set => that port offset is claimed);
/// a `fetch_or` CAS is the sole port-ownership arbiter and replaces the
/// pre-#2852 `owner_by_translated` map. `cursor` is the monotonic fresh-port
/// hand-out counter (the pre-#2852 `next_port_offset_by_addr`). `recycle` is
/// the #3011 FIFO reuse ring, behind a per-ADDRESS mutex (never the global
/// allocator mutex). `port_low`/`range` map ports to bit offsets.
#[derive(Debug)]
struct AddressOccupancy {
    words: Vec<AtomicU64>,
    cursor: AtomicU32,
    recycle: Mutex<VecDeque<u16>>,
    port_low: u16,
    range: u32,
}

impl AddressOccupancy {
    fn new(port_low: u16, range: u32) -> Self {
        let nwords = (range as usize).div_ceil(64);
        let mut words = Vec::with_capacity(nwords);
        for _ in 0..nwords {
            words.push(AtomicU64::new(0));
        }
        Self {
            words,
            cursor: AtomicU32::new(0),
            recycle: Mutex::new(VecDeque::new()),
            port_low,
            range,
        }
    }

    #[inline]
    fn offset_of(&self, port: u16) -> Option<u32> {
        if port < self.port_low {
            return None;
        }
        let off = (port - self.port_low) as u32;
        (off < self.range).then_some(off)
    }

    /// Map a bitmap `offset` back to its wire port. #5660: the offset is
    /// range-checked before the `u32 -> u16` narrowing so an out-of-range value
    /// is REJECTED (`None`) rather than silently truncated into a valid-looking
    /// but WRONG port. `offset < range` guarantees `port_low + offset <=
    /// port_high <= u16::MAX`, so the cast neither truncates nor overflows; a
    /// bare `offset as u16` would wrap (e.g. `65536 + k` -> `k`) and forge a
    /// port `port_low + k` inside the pool. Callers on the claim path already
    /// hold `offset < range`, so this returns `Some` for every legitimate claim.
    #[inline]
    fn port_of(&self, offset: u32) -> Option<u16> {
        if offset >= self.range {
            return None;
        }
        Some(self.port_low + offset as u16)
    }

    /// CAS-set the bit at `offset`. Returns true iff this call transitioned it
    /// 0 -> 1 (the caller now owns the port). The set bit is the ownership
    /// token: a held bit cannot be re-claimed, so no separate owner-identity
    /// check is needed, and it is ABA-safe because the bit is never cleared
    /// between a claim and its legitimate free.
    #[inline]
    fn claim_offset(&self, offset: u32) -> bool {
        let w = (offset / 64) as usize;
        let mask = 1u64 << (offset % 64);
        self.words[w].fetch_or(mask, Ordering::AcqRel) & mask == 0
    }

    /// Clear the bit at `offset`. Returns true iff it was set (1 -> 0).
    #[inline]
    fn free_offset(&self, offset: u32) -> bool {
        let w = (offset / 64) as usize;
        let mask = 1u64 << (offset % 64);
        self.words[w].fetch_and(!mask, Ordering::Release) & mask != 0
    }

    #[inline]
    fn is_occupied(&self, offset: u32) -> bool {
        let w = (offset / 64) as usize;
        let mask = 1u64 << (offset % 64);
        self.words[w].load(Ordering::Acquire) & mask != 0
    }

    /// Claim the next free port: forward-probe the monotonic fresh cursor
    /// (#3047 skip-occupied-out-of-band), then drain the FIFO recycle ring
    /// (#3011, retain-on-collision 062-10). Lock-free w.r.t. the global
    /// allocator mutex (it takes only the per-address recycle mutex, and only
    /// once the fresh range is spent). Returns the claimed PORT, or None when
    /// this address is genuinely full.
    fn claim(&self) -> Option<u16> {
        // Sequential phase: hand out fresh offsets in ascending order, one per
        // claimer via a bounded CAS. The cursor never exceeds `range`, so it
        // does not grow unboundedly once the fresh range is spent.
        loop {
            let cur = self.cursor.load(Ordering::Relaxed);
            if cur >= self.range {
                break;
            }
            if self
                .cursor
                .compare_exchange_weak(cur, cur + 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
            {
                // Another claimer advanced the cursor; re-read and retry.
                continue;
            }
            // We own the right to try offset `cur`. Its bit is normally clear
            // (fresh), but an out-of-band occupant (reserve/persistent/HA) may
            // have set it — then CAS fails and we advance to the next offset.
            if self.claim_offset(cur) {
                // `cur < self.range` (checked above), so `port_of` is `Some`.
                return self.port_of(cur);
            }
        }

        // Recycled phase: FIFO drain (oldest-freed first). A popped port whose
        // bit is already set collided with an out-of-band occupant and is
        // RETAINED (re-queued at the back), never discarded (062-10). The
        // retain buffer allocates lazily only on an actual collision.
        let mut recycle = self.recycle.lock().unwrap_or_else(|e| e.into_inner());
        let mut retained: Vec<u16> = Vec::new();
        let mut claimed = None;
        while let Some(port) = recycle.pop_front() {
            match self.offset_of(port) {
                Some(offset) if self.claim_offset(offset) => {
                    claimed = Some(port);
                    break;
                }
                // Out-of-range (stale) ports are dropped; occupied ports are
                // retained so a transient collision cannot shrink the pool.
                Some(_) => retained.push(port),
                None => {}
            }
        }
        if !retained.is_empty() {
            recycle.extend(retained);
        }
        claimed
    }

    /// Free `port`, pushing it onto the FIFO recycle ring (push_back) so it is
    /// reused oldest-first (#3011). Returns true iff the bit was set.
    fn free_recycle(&self, port: u16) -> bool {
        let Some(offset) = self.offset_of(port) else {
            return false;
        };
        if !self.free_offset(offset) {
            return false;
        }
        self.recycle
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push_back(port);
        true
    }

    /// Free `port` WITHOUT recycling it (#4559 deterministic path — the bit is
    /// the only reuse gate, and a deterministic-only pool never drains the
    /// recycle queue). Returns true iff the bit was set.
    fn free_no_recycle(&self, port: u16) -> bool {
        match self.offset_of(port) {
            Some(offset) => self.free_offset(offset),
            None => false,
        }
    }

    /// Reserve a SPECIFIC port (CAS-set its exact bit). Returns true iff the
    /// bit transitioned 0 -> 1 (the caller now owns it); false when the port
    /// is out of range or already owned (do-not-steal).
    fn reserve(&self, port: u16) -> bool {
        match self.offset_of(port) {
            Some(offset) => self.claim_offset(offset),
            None => false,
        }
    }

    /// Count of currently-occupied ports on this address (popcount over the
    /// bitmap). Cold path (snapshot / tests only).
    fn occupied_count(&self) -> usize {
        self.words
            .iter()
            .map(|w| w.load(Ordering::Relaxed).count_ones() as usize)
            .sum()
    }
}

/// Run bounded lease-expiration GC every N release_flow calls.
const GC_PERIOD: u32 = 10;
pub(super) const ALLOCATION_GC_BUDGET: usize = 8;
const RELEASE_GC_BUDGET: usize = 64;
const PRESSURE_GC_BUDGET: usize = 64;
/// #4676: leases reclaimed per short `live` critical section by the chunked
/// opportunistic GC (`gc_expired_chunked`). The sweep drops the alloc mutex
/// and frees the reclaimed ports on the lock-free occupancy bitmap between
/// chunks, so a concurrent `allocate_translation` map-insert is not blocked
/// for the full sweep. Sized to `ALLOCATION_GC_BUDGET` so the hot-path amortized
/// GC (budget 8) is a single chunk (no extra lock churn) while the larger
/// release/idle budgets (64) yield the mutex several times.
const GC_CHUNK: usize = 8;

#[derive(Debug)]
struct PortAllocatorShared {
    /// One atomic counter per pool address, used for the stateless round-robin
    /// `try_next_port` (address-only / `port no-translation` paths). Separate
    /// from `occupancy` (which tracks flow-keyed pool-mode PAT allocation).
    counters: Vec<AtomicU32>,
    /// Index for IPv4 round-robin address selection.
    addr_counter_v4: AtomicU32,
    /// Index for IPv6 round-robin address selection.
    addr_counter_v6: AtomicU32,
    /// #2852 Phase 1: lock-free per-address occupancy bitmap + recycle ring.
    /// One entry per pool address; the port claim/free run WITHOUT the global
    /// `live` mutex.
    occupancy: Vec<AddressOccupancy>,
    live: Mutex<PortAllocatorLiveState>,
    allocations_total: AtomicU64,
    reuses_total: AtomicU64,
    exhaustion_total: AtomicU64,
    /// #4800: production acquisitions of the `live` mutex (allocate /
    /// reserve / release / rollback / GC), and the subset of those that
    /// found the mutex already held. Together they give the contention
    /// RATIO for the residual Phase-1 (#2852) map mutex, which is the only
    /// form in which "is the NAT allocator the new-flow bottleneck?" has an
    /// answer: a raw acquisition rate says nothing without the denominator.
    ///
    /// Counted by `lock_live()`, which try-locks first — the LOCK on the
    /// uncontended path costs exactly one CAS, the same as `lock()` did. It is
    /// not free, though: the acquisition counter is bumped unconditionally, so
    /// an uncontended acquisition is 2 relaxed atomic RMWs where it used to be
    /// 1. The contended path pays one further relaxed increment on top of a
    /// block that was already going to happen.
    ///
    /// Deliberately NOT counted: `snapshot()` (the ~1s status poll that
    /// READS these counters — the observer must not appear in its own
    /// observation) and the `debug_*` test/diagnostic accessors.
    live_lock_acquisitions: AtomicU64,
    live_lock_contended: AtomicU64,
    max_tracked_flows: usize,
    /// #4676 test seam: counts how many times `gc_expired_chunked` acquired the
    /// `live` mutex. A std `Mutex` is non-reentrant, so N > 1 acquisitions over
    /// a single sweep is proof the sweep RELEASED the lock between chunks (you
    /// cannot re-acquire a lock you still hold). Reverting the chunking to a
    /// single critical section collapses this to 1.
    #[cfg(test)]
    gc_lock_acquisitions: AtomicUsize,
}

/// Bounded pool-mode SNAT allocator.
///
/// Address selection uses atomics for stable round-robin/sticky starting
/// points; port ownership is a lock-free per-address occupancy bitmap so ports
/// are not reused while sessions are alive, and only the flow map + persistent
/// leases are guarded by the per-pool mutex (#2852 Phase 1). Persistent NAT
/// leases are keyed by source tuple and retained until their inactivity timeout
/// after the last live flow releases them.
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
                occupancy: Vec::new(),
                live: Mutex::new(PortAllocatorLiveState::default()),
                allocations_total: AtomicU64::new(0),
                reuses_total: AtomicU64::new(0),
                exhaustion_total: AtomicU64::new(0),
                live_lock_acquisitions: AtomicU64::new(0),
                live_lock_contended: AtomicU64::new(0),
                max_tracked_flows: 0,
                #[cfg(test)]
                gc_lock_acquisitions: AtomicUsize::new(0),
            }),
            port_low: 1024,
            port_high: 65535,
        }
    }
}

/// Test-only PortAllocator CONSTRUCTION counter (#6812 F3 round 4).
///
/// The #6812 guards previously asserted only on the FINAL allocator a rule
/// carries — its identity, or its occupancy-word count. Both are end-state
/// assertions, and both are blind to the exact defect the reuse-before-build
/// and no-bitmap-for-a-failed-pool rules exist to prevent: a `PortAllocator::
/// new` that is built and then discarded. A throwaway construction immediately
/// before the reuse lookup restores the pre-#6812 build-then-discard behaviour
/// with every one of those assertions still green.
///
/// THREAD-LOCAL, deliberately. A process-global counter is shared by every test
/// `cargo test` runs in parallel and produced a master-red flake once already
/// (#6819). `resolve_pool_allocators` and everything it calls are synchronous
/// on the caller's thread, so a thread-local counts exactly the constructions
/// the test under it caused, with no serialisation and no cross-test coupling.
#[cfg(test)]
thread_local! {
    static PORT_ALLOCATOR_BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Test-only: reset the calling thread's construction counter and return a
/// probe that reports constructions since the reset.
#[cfg(test)]
pub(super) fn reset_port_allocator_build_count() {
    PORT_ALLOCATOR_BUILDS.with(|c| c.set(0));
}

/// Test-only: PortAllocator constructions on this thread since the last reset.
#[cfg(test)]
pub(super) fn port_allocator_build_count() -> usize {
    PORT_ALLOCATOR_BUILDS.with(|c| c.get())
}

impl PortAllocator {
    pub(crate) fn new(num_addresses: usize, port_low: u16, port_high: u16) -> Self {
        #[cfg(test)]
        PORT_ALLOCATOR_BUILDS.with(|c| c.set(c.get() + 1));
        let counters = (0..num_addresses).map(|_| AtomicU32::new(0)).collect();
        let range = if port_low == 0 || port_high == 0 || port_low > port_high {
            0
        } else {
            (port_high as u32) - (port_low as u32) + 1
        };
        let occupancy = (0..num_addresses)
            .map(|_| AddressOccupancy::new(port_low, range))
            .collect();
        let max_tracked_flows = allocator_capacity(num_addresses, port_low, port_high)
            .min(MAX_SOURCE_NAT_POOL_TRACKED_FLOWS);
        Self {
            shared: Arc::new(PortAllocatorShared {
                counters,
                addr_counter_v4: AtomicU32::new(0),
                addr_counter_v6: AtomicU32::new(0),
                occupancy,
                live: Mutex::new(PortAllocatorLiveState::new(num_addresses)),
                allocations_total: AtomicU64::new(0),
                reuses_total: AtomicU64::new(0),
                exhaustion_total: AtomicU64::new(0),
                live_lock_acquisitions: AtomicU64::new(0),
                live_lock_contended: AtomicU64::new(0),
                max_tracked_flows,
                #[cfg(test)]
                gc_lock_acquisitions: AtomicUsize::new(0),
            }),
            port_low,
            port_high,
        }
    }

    /// #4800: acquire the residual `live` map mutex, counting acquisitions
    /// and the subset that had to block.
    ///
    /// `try_lock()` first: on an uncontended mutex that is a single CAS —
    /// exactly what `lock()` was already doing — so the LOCK ITSELF costs what
    /// it always did. The acquisition counter is bumped UNCONDITIONALLY, so an
    /// uncontended acquisition is 2 relaxed atomic read-modify-writes where it
    /// used to be 1; "unchanged" would be false, though both are relaxed,
    /// untimed and allocation-free. Only when the CAS fails (another worker
    /// holds the map mutex) do we bump `live_lock_contended` and fall through
    /// to the blocking `lock()`, which was going to happen regardless.
    ///
    /// Poison policy is preserved verbatim from the call sites this
    /// replaces (`unwrap_or_else(|e| e.into_inner())`): a worker that
    /// panicked mid-mutation must not strand every subsequent allocation.
    /// `try_lock` reports poison only when the mutex is FREE, so the
    /// blocking arm still has to handle it.
    ///
    /// Every production allocate / reserve / release / rollback / GC site
    /// goes through here. `snapshot()` deliberately does NOT — it is the
    /// ~1s status poll that reads these very counters, and counting it
    /// would inject the observer into the observation.
    fn lock_live(&self) -> MutexGuard<'_, PortAllocatorLiveState> {
        self.shared
            .live_lock_acquisitions
            .fetch_add(1, Ordering::Relaxed);
        match self.shared.live.try_lock() {
            Ok(guard) => return guard,
            Err(TryLockError::Poisoned(poisoned)) => return poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => {}
        }
        self.shared
            .live_lock_contended
            .fetch_add(1, Ordering::Relaxed);
        self.shared.live.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// #6751: live ownership records held by this allocator.
    ///
    /// The interface-mode registry uses it as its reclamation predicate — an
    /// allocator with no live records holds no occupancy any session depends
    /// on, so it can be dropped; one with live records must be retained until
    /// their releases have reached it. Takes the `live` mutex, so it belongs on
    /// apply / cap-saturation paths only, never per packet.
    pub(crate) fn live_flow_count(&self) -> usize {
        self.lock_live().live_by_flow.len()
    }

    /// White-box access to the live state for tests. NOT for production
    /// callers — they should use the typed `allocate_translation` /
    /// `release_flow` / `rollback_flow` / `snapshot` entry points. Port
    /// ownership is inspected via the dedicated debug accessors below (the
    /// bitmap lives outside this mutex).
    #[cfg(test)]
    pub(super) fn debug_live(&self) -> MutexGuard<'_, PortAllocatorLiveState> {
        self.shared.live.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Test-only: total occupancy-bitmap WORDS across every pool address.
    /// The #6812 aggregate-budget tests assert a refused / failed pool
    /// materialised ZERO words (no eager bitmap) while an admitted pool
    /// carries `addresses x div_ceil(port_range, 64)` — the direct white-box
    /// proof the bitmap was (or was not) allocated.
    #[cfg(test)]
    pub(super) fn debug_occupancy_words(&self) -> usize {
        self.shared.occupancy.iter().map(|o| o.words.len()).sum()
    }

    /// Test-only: identity of the shared allocator state, for proving a
    /// re-apply REUSED the previous allocator (same Arc) instead of building
    /// a fresh bitmap (#6812 reuse-before-build).
    #[cfg(test)]
    pub(super) fn debug_shared_identity(&self) -> usize {
        Arc::as_ptr(&self.shared) as usize
    }

    /// Test-only: mark a translated tuple as owned (set its occupancy bit)
    /// without advancing the sequential cursor. Models an out-of-band occupant
    /// (a persistent lease or an HA-synced install) sitting inside the
    /// sequential port range — the precondition for the #3047 collision paths.
    /// `_translated_ip` is retained for call-site clarity; the bitmap is keyed
    /// by `addr_index`.
    #[cfg(test)]
    pub(super) fn debug_seed_owner(&self, addr_index: usize, _translated_ip: IpAddr, port: u16) {
        if let Some(occ) = self.shared.occupancy.get(addr_index) {
            occ.reserve(port);
        }
    }

    /// Test-only: clear a synthetic owner seeded via `debug_seed_owner`
    /// (clear its occupancy bit) without pushing the port onto the recycle
    /// queue.
    #[cfg(test)]
    pub(super) fn debug_clear_owner(&self, addr_index: usize, _translated_ip: IpAddr, port: u16) {
        if let Some(occ) = self.shared.occupancy.get(addr_index) {
            occ.free_no_recycle(port);
        }
    }

    /// #6979 F6: do these two handles refer to the SAME allocator?
    ///
    /// Allocator sharing between rules is by `Arc`, so pointer identity is the
    /// question — not key equality. The resolver reaches a shared allocator by
    /// several routes (an exact previous-generation key, a this-apply key
    /// already assigned, a rename carry), and the peer-overlap wiring must
    /// treat every one of them as "one occupancy domain, nothing to check".
    pub(crate) fn same_allocator(&self, other: &PortAllocator) -> bool {
        Arc::ptr_eq(&self.shared, &other.shared)
    }

    /// #6979 F6: is `port` currently OWNED on pool address `addr_index` in this
    /// allocator?
    ///
    /// The occupancy bit is the sole ownership token for a PAT allocation, so
    /// this is the question a PEER allocator over the same pool address has to
    /// ask before it may publish that identity: two pools covering one address
    /// are two independent bitmaps, and without this each is blind to the
    /// other's live translations.
    ///
    /// A port outside this address's configured range, or an `addr_index` past
    /// the end (an empty default allocator), answers `false` — it owns nothing
    /// there, which is the honest answer and the fail-open direction only in
    /// the sense that there is nothing to protect.
    pub(crate) fn holds_port(&self, addr_index: usize, port: u16) -> bool {
        match self.shared.occupancy.get(addr_index) {
            Some(occ) => match occ.offset_of(port) {
                Some(offset) => occ.is_occupied(offset),
                None => false,
            },
            None => false,
        }
    }

    /// Test-only alias of [`Self::holds_port`]. Kept as an ALIAS rather than a
    /// second copy of the lookup so the tests that pin occupancy keep asking
    /// the production question (#6979).
    #[cfg(test)]
    pub(crate) fn debug_is_port_occupied(&self, addr_index: usize, port: u16) -> bool {
        self.holds_port(addr_index, port)
    }

    /// Test-only: map a bitmap `offset` to its port on pool address
    /// `addr_index`, exercising the #5660 range-checked `port_of`. Returns
    /// `None` for an unknown address OR an out-of-range offset (the value a bare
    /// `offset as u16` would silently truncate).
    #[cfg(test)]
    pub(super) fn debug_port_of(&self, addr_index: usize, offset: u32) -> Option<u16> {
        self.shared
            .occupancy
            .get(addr_index)
            .and_then(|occ| occ.port_of(offset))
    }

    /// Test-only: total occupied ports across all pool addresses.
    #[cfg(test)]
    pub(super) fn debug_occupied_count(&self) -> usize {
        self.shared
            .occupancy
            .iter()
            .map(AddressOccupancy::occupied_count)
            .sum()
    }

    /// Test-only: snapshot the FIFO recycle queue for pool address `addr_index`.
    #[cfg(test)]
    pub(super) fn debug_recycled_ports(&self, addr_index: usize) -> Vec<u16> {
        match self.shared.occupancy.get(addr_index) {
            Some(occ) => occ
                .recycle
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .copied()
                .collect(),
            None => Vec::new(),
        }
    }

    /// Test-only: replace the FIFO recycle queue for pool address `addr_index`.
    #[cfg(test)]
    pub(super) fn debug_set_recycled(&self, addr_index: usize, ports: Vec<u16>) {
        if let Some(occ) = self.shared.occupancy.get(addr_index) {
            *occ.recycle.lock().unwrap_or_else(|e| e.into_inner()) = VecDeque::from(ports);
        }
    }

    /// Test-only: set the monotonic fresh-port cursor for pool address
    /// `addr_index` (e.g. push it past the range to force the recycle phase).
    #[cfg(test)]
    pub(super) fn debug_set_cursor(&self, addr_index: usize, offset: u32) {
        if let Some(occ) = self.shared.occupancy.get(addr_index) {
            occ.cursor.store(offset, Ordering::Relaxed);
        }
    }

    /// Test-only: drive the #4676 chunked opportunistic GC directly (the same
    /// entry point the hot allocation path and the periodic release path use),
    /// so a white-box test can assert both the reclaim result and the seam
    /// (`debug_gc_lock_acquisitions`).
    #[cfg(test)]
    pub(super) fn debug_gc_expired_chunked(&self, now_ns: u64, budget: usize) -> usize {
        self.gc_expired_chunked(now_ns, budget)
    }

    /// Test-only: how many times `gc_expired_chunked` has acquired the `live`
    /// mutex. Because a std `Mutex` is non-reentrant, a value > 1 over a single
    /// sweep is direct proof the sweep RELEASED the lock between chunks.
    #[cfg(test)]
    pub(super) fn debug_gc_lock_acquisitions(&self) -> usize {
        self.shared.gc_lock_acquisitions.load(Ordering::Relaxed)
    }

    /// Pick a pool address index for the current address family.
    pub(super) fn address_index(
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
    pub(super) fn try_next_port(
        &self,
        addr_index: usize,
    ) -> Result<u16, super::source::SourceNatFailureReason> {
        if self.port_low == 0 || self.port_high == 0 || self.port_low > self.port_high {
            return Err(super::source::SourceNatFailureReason::InvalidPortRange);
        }
        let range = (self.port_high as u32).saturating_sub(self.port_low as u32) + 1;
        if range == 0 || addr_index >= self.shared.counters.len() {
            return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
        }
        let counter = &self.shared.counters[addr_index];
        let val = counter.fetch_add(1, Ordering::Relaxed);
        Ok(self.port_low + (val % range) as u16)
    }

    /// Free a translated port's occupancy bit. `recycle` pushes the port onto
    /// the FIFO reuse ring (#3011); the deterministic path passes `false`.
    /// Returns true iff the bit was set.
    fn free_translated_port(&self, addr_index: usize, port: u16, recycle: bool) -> bool {
        let Some(occ) = self.shared.occupancy.get(addr_index) else {
            return false;
        };
        if recycle {
            occ.free_recycle(port)
        } else {
            occ.free_no_recycle(port)
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn allocate_translation(
        &self,
        flow: SourceNatFlowKey,
        family_addresses: PoolAddressFamily<'_>,
        family_offset: usize,
        address_persistent: bool,
        persistent_nat: bool,
        persistent_nat_permit: super::source::PersistentNatPermit,
        persistent_nat_timeout_ns: u64,
        now_ns: u64,
        // #6522: the worker performing this LOCAL allocation, so the record
        // it inserts already names its own holder before any sibling replica
        // reserves against it. `NatHolder::Untracked` reproduces the
        // pre-#6522 single-holder contract and is what the test entry points
        // and the read-only fragment probe pass.
        holder: NatHolder,
    ) -> Result<TranslatedTuple, super::source::SourceNatFailureReason> {
        if self.port_low == 0 || self.port_high == 0 || self.port_low > self.port_high {
            return Err(super::source::SourceNatFailureReason::InvalidPortRange);
        }
        let family_len = family_addresses.len();
        if family_len == 0 {
            return Err(super::source::SourceNatFailureReason::WrongAddressFamily);
        }
        let range = (self.port_high as u32).saturating_sub(self.port_low as u32) + 1;
        if range == 0 || self.shared.max_tracked_flows == 0 {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
        }

        // ---- Non-persistent hot path: lock-free port claim, tiny map lock. ----
        //
        // The port claim (forward-probe cursor + bitmap CAS + FIFO recycle) runs
        // WITHOUT the global mutex; the mutex is taken only for the tiny
        // reuse-check + exact-cap-check + `live_by_flow` insert critical section.
        // A GC-of-expired-leases-first pass is preserved for the near-capacity
        // case by falling through to `allocate_translation_locked` when every
        // target address's bitmap is full (the fast, non-GC'd view).
        if !persistent_nat {
            let start_abs =
                self.address_index(flow.src_ip, family_offset, family_len, address_persistent);
            let start_rel = start_abs.saturating_sub(family_offset);
            let address_attempts = if address_persistent { 1 } else { family_len };
            for offset in 0..address_attempts {
                let rel = (start_rel + offset) % family_len;
                let abs = family_offset + rel;
                let Some(occ) = self.shared.occupancy.get(abs) else {
                    continue;
                };
                let Some(port) = occ.claim() else {
                    continue;
                };
                let translated = TranslatedTuple {
                    ip: family_addresses.ip_at(rel),
                    port,
                };
                // #4676: run the amortized expiry GC OFF the insert critical
                // section — chunked, the alloc mutex released between batches,
                // reclaimed ports freed lock-free. GC touches only the
                // persistent-lease maps + occupancy while the insert CS below
                // touches only `live_by_flow`, so the two are disjoint and the
                // insert CS stays genuinely tiny (the port is already claimed on
                // the lock-free bitmap, so GC here is opportunistic cleanup, not
                // load-bearing for this allocation).
                self.gc_expired_chunked(now_ns, ALLOCATION_GC_BUDGET);
                let mut live = self.lock_live();
                if let Some(existing) = live.live_by_flow.get(&flow) {
                    // Idempotent re-entry for an already-allocated flow (a second
                    // packet racing session install). Give back the port we just
                    // claimed and return the existing translation.
                    let existing = existing.translated;
                    self.shared.reuses_total.fetch_add(1, Ordering::Relaxed);
                    drop(live);
                    self.free_translated_port(abs, port, true);
                    return Ok(existing);
                }
                if live.live_by_flow.len() >= self.shared.max_tracked_flows {
                    // Exact cap (F4): `live_by_flow.len()` under the mutex is
                    // authoritative — no overshoot. Give back the claimed port.
                    self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
                    drop(live);
                    self.free_translated_port(abs, port, true);
                    return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
                }
                live.live_by_flow.insert(
                    flow,
                    LiveAllocation {
                        translated,
                        persistent_key: None,
                        addr_index: abs,
                        deterministic: false,
                        address_only: false,
                        // #6522: the ALLOCATING worker's holder bit. A locally-born session is
                        // replicated to every SIBLING worker (`replicate_session_upsert` fans a
                        // `WorkerLocalImport` entry to `peer_worker_commands`, which EXCLUDES
                        // this worker) and each sibling reserves against this same record, so
                        // without this bit the mask holds every worker EXCEPT the one actually
                        // forwarding — and the last sibling replica to age-reap frees a
                        // `(pool_addr, port)` still in use. Recording the owner here makes the
                        // mask complete, so the port survives until the owner itself releases.
                        holders: holder.bit(),
                    },
                );
                self.shared
                    .allocations_total
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(translated);
            }
            // Every target address's bitmap was full on the fast (non-GC'd)
            // view. Fall through to the pressured, GC-first locked path.
        }

        self.allocate_translation_locked(
            flow,
            family_addresses,
            family_offset,
            address_persistent,
            persistent_nat,
            persistent_nat_permit,
            persistent_nat_timeout_ns,
            now_ns,
            holder,
        )
    }

    /// The persistent-NAT path (lease decision + claim MUST be atomic so two
    /// flows sharing a lease cannot both claim a port) and the non-persistent
    /// near-capacity pressure fallback (bounded expiry GC per address, then
    /// retry). Both hold the global mutex; the port claim uses the same lock-
    /// free bitmap (correctness is unaffected by whether the mutex is held).
    #[allow(clippy::too_many_arguments)]
    fn allocate_translation_locked(
        &self,
        flow: SourceNatFlowKey,
        family_addresses: PoolAddressFamily<'_>,
        family_offset: usize,
        address_persistent: bool,
        persistent_nat: bool,
        persistent_nat_permit: super::source::PersistentNatPermit,
        persistent_nat_timeout_ns: u64,
        now_ns: u64,
        // #6522: the worker performing this LOCAL allocation, so the record
        // it inserts already names its own holder before any sibling replica
        // reserves against it. `NatHolder::Untracked` reproduces the
        // pre-#6522 single-holder contract and is what the test entry points
        // and the read-only fragment probe pass.
        holder: NatHolder,
    ) -> Result<TranslatedTuple, super::source::SourceNatFailureReason> {
        let family_len = family_addresses.len();
        let mut live = self.lock_live();
        self.gc_expired_locked(&mut live, now_ns, ALLOCATION_GC_BUDGET);

        if let Some(existing) = live.live_by_flow.get(&flow) {
            self.shared.reuses_total.fetch_add(1, Ordering::Relaxed);
            return Ok(existing.translated);
        }
        if live.live_by_flow.len() >= self.shared.max_tracked_flows {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
        }

        let persistent_key =
            persistent_nat.then(|| flow.persistent_source_key(persistent_nat_permit));
        if let Some(key) = persistent_key {
            if let Some(translated) = self.reuse_existing_lease_locked(
                &mut live,
                key,
                flow,
                persistent_nat_timeout_ns,
                now_ns,
                holder,
            ) {
                return Ok(translated);
            }
        }

        let start_abs =
            self.address_index(flow.src_ip, family_offset, family_len, address_persistent);
        let start_rel = start_abs.saturating_sub(family_offset);
        let address_attempts = if address_persistent { 1 } else { family_len };
        for offset in 0..address_attempts {
            let rel = (start_rel + offset) % family_len;
            let abs = family_offset + rel;
            if abs >= self.shared.occupancy.len() {
                continue;
            }
            let translated_ip = family_addresses.ip_at(rel);
            if persistent_key.is_some()
                && live.persistent_by_source.len() >= self.shared.max_tracked_flows
            {
                // Lease-table pressure is also budgeted. A full persistent
                // table gets one global PRESSURE_GC_BUDGET pass before this
                // address attempt is treated as unavailable.
                self.gc_expired_locked(&mut live, now_ns, PRESSURE_GC_BUDGET);
                if live.persistent_by_source.len() >= self.shared.max_tracked_flows {
                    continue;
                }
            }

            let mut port = self.shared.occupancy[abs].claim();
            if port.is_none() {
                // Pressure handling is budgeted, not strict O(1). A
                // non-address-persistent full family can visit each
                // family-compatible address and run at most
                // PRESSURE_GC_BUDGET expiry checks for that selected
                // address before declaring exhaustion.
                self.gc_expired_for_addr_locked(&mut live, abs, now_ns, PRESSURE_GC_BUDGET);
                port = self.shared.occupancy[abs].claim();
            }
            let Some(port) = port else {
                continue;
            };
            let translated = TranslatedTuple {
                ip: translated_ip,
                port,
            };
            if let Some(key) = persistent_key {
                let expires_at_ns =
                    now_ns.saturating_add(persistent_nat_timeout_ns.max(NS_PER_SEC));
                live.persistent_by_source.insert(
                    key,
                    PersistentLease {
                        translated,
                        addr_index: abs,
                        expires_at_ns,
                        timeout_ns: persistent_nat_timeout_ns.max(NS_PER_SEC),
                        active_flows: 1,
                        completed_flows: 0,
                        activation_saw_completion: false,
                        activation_previous_expires_at_ns: 0,
                        activation_had_previous_lease: false,
                        address_only: false,
                    },
                );
            }
            live.live_by_flow.insert(
                flow,
                LiveAllocation {
                    translated,
                    persistent_key,
                    addr_index: abs,
                    deterministic: false,
                    address_only: false,
                    // #6522: the ALLOCATING worker's holder bit. A locally-born session is
                    // replicated to every SIBLING worker (`replicate_session_upsert` fans a
                    // `WorkerLocalImport` entry to `peer_worker_commands`, which EXCLUDES
                    // this worker) and each sibling reserves against this same record, so
                    // without this bit the mask holds every worker EXCEPT the one actually
                    // forwarding — and the last sibling replica to age-reap frees a
                    // `(pool_addr, port)` still in use. Recording the owner here makes the
                    // mask complete, so the port survives until the owner itself releases.
                    holders: holder.bit(),
                },
            );
            self.shared
                .allocations_total
                .fetch_add(1, Ordering::Relaxed);
            return Ok(translated);
        }

        self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
        Err(super::source::SourceNatFailureReason::AllocatorExhausted)
    }

    /// #2397 persistent-NAT lease reuse, run under the live-state lock as the
    /// first persistent-key step of `allocate_translation_locked`.
    ///
    /// When a lease already exists for `key`:
    ///   - a still-valid lease (an active flow, or one whose inactivity timeout
    ///     has not yet elapsed) is REUSED — on the 0 -> 1 active-flow edge its
    ///     activation-rollback bookkeeping is re-armed and its old expiry index
    ///     entry is dropped, its inactivity expiry is pushed out, the flow is
    ///     recorded in `live_by_flow`, `reuses_total` is bumped, and the reused
    ///     translated tuple is returned as `Some(_)` (the caller returns it
    ///     directly);
    ///   - an expired lease is torn down (expiry index entry removed, translated
    ///     tuple released, lease dropped) and `None` is returned so the caller
    ///     falls through to a fresh allocation.
    ///
    /// Returns `None` when no lease exists for `key` or the lease was expired and
    /// reclaimed.
    fn reuse_existing_lease_locked(
        &self,
        live: &mut PortAllocatorLiveState,
        key: PersistentSourceKey,
        flow: SourceNatFlowKey,
        persistent_nat_timeout_ns: u64,
        now_ns: u64,
        // #6522: the worker performing this LOCAL allocation, so the record
        // it inserts already names its own holder before any sibling replica
        // reserves against it. `NatHolder::Untracked` reproduces the
        // pre-#6522 single-holder contract and is what the test entry points
        // and the read-only fragment probe pass.
        holder: NatHolder,
    ) -> Option<TranslatedTuple> {
        if !live.persistent_by_source.contains_key(&key) {
            return None;
        }
        let mut reusable = None;
        let mut expired = None;
        let mut remove_expiry = None;
        if let Some(lease) = live.persistent_by_source.get_mut(&key) {
            if lease.active_flows > 0 || lease.expires_at_ns > now_ns {
                let translated = lease.translated;
                let addr_index = lease.addr_index;
                if lease.active_flows == 0 {
                    remove_expiry = Some((addr_index, lease.expires_at_ns));
                    lease.activation_saw_completion = false;
                    lease.activation_previous_expires_at_ns = lease.expires_at_ns;
                    lease.activation_had_previous_lease = true;
                }
                lease.active_flows = lease.active_flows.saturating_add(1);
                let expires_at_ns =
                    now_ns.saturating_add(persistent_nat_timeout_ns.max(NS_PER_SEC));
                lease.expires_at_ns = expires_at_ns;
                reusable = Some((translated, addr_index));
            } else {
                expired = Some((
                    lease.translated,
                    lease.addr_index,
                    lease.expires_at_ns,
                    lease.address_only,
                ));
            }
        }
        if let Some((addr_index, expires_at_ns)) = remove_expiry {
            Self::remove_lease_expiration_locked(live, addr_index, expires_at_ns, key);
        }
        if let Some((translated, addr_index)) = reusable {
            live.live_by_flow.insert(
                flow,
                LiveAllocation {
                    translated,
                    persistent_key: Some(key),
                    addr_index,
                    deterministic: false,
                    address_only: false,
                    // #6522: the ALLOCATING worker's holder bit. A locally-born session is
                    // replicated to every SIBLING worker (`replicate_session_upsert` fans a
                    // `WorkerLocalImport` entry to `peer_worker_commands`, which EXCLUDES
                    // this worker) and each sibling reserves against this same record, so
                    // without this bit the mask holds every worker EXCEPT the one actually
                    // forwarding — and the last sibling replica to age-reap frees a
                    // `(pool_addr, port)` still in use. Recording the owner here makes the
                    // mask complete, so the port survives until the owner itself releases.
                    holders: holder.bit(),
                },
            );
            self.shared.reuses_total.fetch_add(1, Ordering::Relaxed);
            return Some(translated);
        }
        if let Some((translated, addr_index, expires_at_ns, address_only)) = expired {
            Self::remove_lease_expiration_locked(live, addr_index, expires_at_ns, key);
            // #6041: an address-only lease owns no pool port, so there is no bit
            // to free — its per-flow reverse-identity tokens were already cleared
            // when each flow released (the lease is idle here). Freeing
            // `translated.port` would clear an UNRELATED PAT flow's bit that
            // happens to share the offset.
            if !address_only {
                self.free_translated_port(addr_index, translated.port, true);
            }
            live.persistent_by_source.remove(&key);
        }
        None
    }

    fn insert_lease_expiration_locked(
        live: &mut PortAllocatorLiveState,
        addr_index: usize,
        expires_at_ns: u64,
        key: PersistentSourceKey,
    ) {
        live.lease_expirations.insert((expires_at_ns, key));
        if let Some(by_addr) = live.lease_expirations_by_addr.get_mut(addr_index) {
            by_addr.insert((expires_at_ns, key));
        }
    }

    fn remove_lease_expiration_locked(
        live: &mut PortAllocatorLiveState,
        addr_index: usize,
        expires_at_ns: u64,
        key: PersistentSourceKey,
    ) {
        live.lease_expirations.remove(&(expires_at_ns, key));
        if let Some(by_addr) = live.lease_expirations_by_addr.get_mut(addr_index) {
            by_addr.remove(&(expires_at_ns, key));
        }
    }

    /// #6211 F2: drop `holder` from a reservation's holder set and report
    /// whether the reservation must SURVIVE this release.
    ///
    /// Returns `true` when other workers still hold the flow, in which case the
    /// caller returns without touching `live_by_flow`, the occupancy bitmap, the
    /// persistent lease, or the address-only reverse-identity token — the port
    /// stays claimed for the holders that remain.
    ///
    /// Returns `false` (proceed to free) in exactly two cases:
    ///   - `holders == 0`, an untracked record — one nothing has ever claimed a
    ///     bit on. #7093: an earlier revision of this line justified that arm
    ///     with "RSS steers a 5-tuple to one worker, so a local allocation has a
    ///     single holder by construction". **That premise is false and #6522
    ///     refuted it**: a locally-born session is replicated to every OTHER
    ///     worker (`replicate_session_upsert` over `peer_worker_commands`, a
    ///     list built with `.filter(|(id, _)| **id != worker_id)`), and
    ///     `SessionOrigin::is_peer_synced()` is TRUE for `WorkerLocalImport`, so
    ///     every sibling reserved and took a bit on the owner's record while the
    ///     owner held none. Since #6522 the allocating worker records its own
    ///     bit, so no PRODUCTION path reaches this arm any more — every reserve
    ///     names a `Worker(id)`. It survives for the `#[cfg(test)]` entry points
    ///     and the read-only fragment probe, which pass `Untracked`.
    ///   - clearing this holder's bit empties the mask: the LAST worker holding
    ///     the reservation is releasing it.
    ///
    /// [`NatHolder::Untracked`] contributes no bit, so an untracked release of a
    /// TRACKED reservation keeps it. That is the deliberate direction for a
    /// release site that was never taught its worker id: an under-release leaks
    /// a pool port (bounded, observable as `AllocatorExhausted`), whereas an
    /// over-release hands a live worker's `(pool_addr, port)` to a new flow —
    /// the NAT source collision this whole mechanism exists to prevent.
    fn drop_holder_locked(
        live: &mut PortAllocatorLiveState,
        flow: &SourceNatFlowKey,
        existing: LiveAllocation,
        holder: NatHolder,
    ) -> bool {
        if existing.holders == 0 {
            return false;
        }
        let remaining = existing.holders & !holder.bit();
        if remaining == 0 {
            return false;
        }
        if let Some(slot) = live.live_by_flow.get_mut(flow) {
            slot.holders = remaining;
        }
        true
    }


    /// #6528: unlink ONE flow's `live_by_flow` record, applying the teardown its
    /// allocation MODE requires. This is the half of a teardown that is
    /// IDENTICAL across all THREE paths that retire a record — `release_flow`,
    /// `rollback_flow`, and `reserve_flow`'s stale-tuple eviction — and it exists
    /// so a fourth cannot diverge from the other three.
    ///
    /// Three modes, three different obligations, and getting the mode wrong is
    /// not a no-op — it mutates state belonging to an UNRELATED flow:
    ///
    ///   - ADDRESS-ONLY (`port no-translation` / port-less, #5269/#6041): owns
    ///     NO occupancy bit. `addr_index` is a hardcoded 0 and `translated.port`
    ///     is the PRESERVED internal source port, so calling
    ///     `free_translated_port` on it clears whatever bit pool address 0
    ///     happens to hold at that offset — which, when a PAT rule shares the
    ///     allocator (`allocator_key()` is pool name + addresses + port range;
    ///     it does NOT include `no_translation`), is a LIVE PAT flow's port, and
    ///     `free_recycle` then hands it to the next allocation. What it owns
    ///     instead is the reverse-identity token in `address_only_owners`, which
    ///     must be cleared or that public identity is denied forever.
    ///   - PERSISTENT (`persistent_key = Some`): the port/address belongs to the
    ///     LEASE, not the flow. Freeing the bit here hands out a port the lease
    ///     still claims. Only the lease teardown frees it — see the caller-owned
    ///     lease arms below.
    ///   - Plain PAT: owns its port outright — free the bit, recycling it unless
    ///     it is a deterministic block port (#4559).
    ///
    /// The LEASE arm is deliberately NOT here: `release_flow` completes a flow
    /// (bump `completed_flows`, refresh the idle expiry) while `rollback_flow`
    /// undoes an activation (restore or remove the lease). Each caller runs its
    /// own; this helper owns only what they share.
    fn unlink_live_allocation_locked(
        &self,
        live: &mut PortAllocatorLiveState,
        flow: &SourceNatFlowKey,
        existing: LiveAllocation,
    ) {
        live.live_by_flow.remove(flow);
        // #6041: the address-only reverse-identity token (#5269) is orthogonal
        // to the persistent lease — it exists for BOTH a non-persistent
        // address-only flow AND an address-only PERSISTENT flow
        // (`persistent_key = Some` AND `address_only = true`). The key mirrors
        // what `reserve_address_only` / `reserve_address_only_roundrobin` /
        // `reserve_address_only_persistent` inserted (stored translated tuple +
        // the flow's remote endpoint).
        if existing.address_only {
            live.address_only_owners.remove(&AddressOnlyReverseKey {
                protocol: flow.protocol,
                translated_ip: existing.translated.ip,
                translated_port: existing.translated.port,
                dst_ip: flow.dst_ip,
                dst_port: flow.dst_port,
            });
        }
        if existing.persistent_key.is_none() && !existing.address_only {
            self.free_translated_port(
                existing.addr_index,
                existing.translated.port,
                !existing.deterministic,
            );
        }
    }

    /// #6528: the RELEASE-semantics persistent-lease arm — a flow that WAS in
    /// service on this translation has finished with it.
    ///
    /// Shared by `release_flow` and `reserve_flow`'s stale-tuple eviction: an
    /// evicted reservation was in service on the tuple it is being replaced on,
    /// so the flow completed on it. Dropping the refcount is what makes the
    /// lease reclaimable — a leaked refcount is never idle, so the lease never
    /// enters `lease_expirations` and NO GC path can reclaim it.
    ///
    /// No-op for a non-persistent record.
    fn complete_persistent_lease_locked(
        live: &mut PortAllocatorLiveState,
        existing: LiveAllocation,
        now_ns: u64,
    ) {
        let Some(key) = existing.persistent_key else {
            return;
        };
        let mut refresh_expiry = None;
        if let Some(lease) = live.persistent_by_source.get_mut(&key) {
            lease.completed_flows = lease.completed_flows.saturating_add(1);
            lease.activation_saw_completion = true;
            lease.active_flows = lease.active_flows.saturating_sub(1);
            if lease.active_flows == 0 {
                let old_expires_at_ns = lease.expires_at_ns;
                let expires_at_ns = now_ns.saturating_add(lease.timeout_ns);
                lease.expires_at_ns = expires_at_ns;
                refresh_expiry = Some((lease.addr_index, old_expires_at_ns, expires_at_ns));
            }
        }
        if let Some((addr_index, old_expires_at_ns, expires_at_ns)) = refresh_expiry {
            Self::remove_lease_expiration_locked(live, addr_index, old_expires_at_ns, key);
            Self::insert_lease_expiration_locked(live, addr_index, expires_at_ns, key);
        }
    }

    pub(super) fn release_flow(
        &self,
        flow: SourceNatFlowKey,
        translated: TranslatedTuple,
        now_ns: u64,
        holder: NatHolder,
    ) -> bool {
        let mut live = self.lock_live();
        let Some(existing) = live.live_by_flow.get(&flow).copied() else {
            return false;
        };
        if existing.translated != translated {
            return false;
        }
        if Self::drop_holder_locked(&mut live, &flow, existing, holder) {
            return false;
        }
        // #6528: mode-correct unlink + the release-semantics lease arm, both
        // shared with `reserve_flow`'s stale-tuple eviction so the two cannot
        // drift. `existing.translated == translated` was checked above, so
        // freeing `existing.translated.port` is the same port as before.
        self.unlink_live_allocation_locked(&mut live, &flow, existing);
        Self::complete_persistent_lease_locked(&mut live, existing, now_ns);
        live.gc_counter = live.gc_counter.wrapping_add(1);
        let run_gc = live.gc_counter % GC_PERIOD == 0;
        // #4676: drop the release guard BEFORE the periodic idle-lease sweep so
        // the (up to RELEASE_GC_BUDGET) sweep runs chunked with the alloc mutex
        // released between batches instead of blocking concurrent allocations
        // for the whole sweep. The release mutations above are already committed
        // under this guard, so the GC re-locking a fresh guard observes them.
        drop(live);
        if run_gc {
            self.gc_expired_chunked(now_ns, RELEASE_GC_BUDGET);
        }
        true
    }

    /// #7092: clear `worker_id`'s holder bit across every live allocation, and
    /// free any record the clear empties. Returns the number of records freed.
    ///
    /// THE LEAK THIS EXISTS FOR. A bit is SET on reserve and cleared only when
    /// that same worker later runs its own release. A worker that never runs one
    /// strands every reservation it holds for the life of the allocator, and
    /// both ways that happens are reachable:
    ///
    ///   * PANIC. `spawn_supervised_worker` (`coordinator/supervisor.rs`)
    ///     catches the unwind, sets `runtime_atomics.dead = true` and lets the
    ///     thread exit. Nothing respawns it — the only other consumer of `.dead`
    ///     is `coordinator/status.rs`, which REPORTS it — so its `SessionTable`
    ///     dies with the thread and never reaps.
    ///   * REPLAN. `worker_id` is minted as `queue_id % workers`
    ///     (`server/helpers/planning.rs`), so a plan that shrinks the worker set
    ///     retires ids that still hold bits. The allocator itself is carried
    ///     forward across the reload by `parse_source_nat_rules_with_previous`,
    ///     so the bits survive with it.
    ///
    /// There is no sweep, no TTL and no reconcile that clears them, so the pool
    /// addresses' occupancy bitmap never gets those ports back and SNAT for new
    /// flows eventually fails `AllocatorExhausted`.
    ///
    /// WHY THIS IS SAFE TO DO, and why it would NOT have been before #6522.
    /// Clearing one holder's bit is only sound if an empty mask really means no
    /// live holder remains. Under #6211 F2 it did not: the allocating worker
    /// recorded NO bit, so the mask named every worker EXCEPT the one actually
    /// forwarding, and emptying it would have freed a `(pool_addr, port)` still
    /// in use — the over-release this whole mechanism exists to prevent. #6522
    /// made the owner a holder of its own allocation, so an empty mask now means
    /// exactly what it says. This function is the last-holder release path
    /// applied to a worker that will never call it.
    ///
    /// UNTRACKED RECORDS ARE NOT TOUCHED. `holders == 0` is a record no worker
    /// ever claimed; `bit & 0 == 0`, so the filter below skips it and no
    /// `Untracked` allocation can be freed by a retirement it never joined.
    ///
    /// WIRED SINCE #6979, for the PANIC route only. The call site is the 1 Hz
    /// status tick, which this doc previously named as the candidate with a
    /// hazard: it "would walk `live_by_flow` under the alloc mutex on every tick
    /// unless it also carries 'already retired' state". It now carries exactly
    /// that -- `WorkerRuntimeAtomics::holders_retired`, a one-shot
    /// compare-and-swap -- so the sweep runs ONCE per dead worker and every
    /// later tick pays one relaxed atomic load per record and stops.
    ///
    /// THE REPLAN ROUTE IS STILL NOT COVERED, and that is stated rather than
    /// implied. `worker_id` is minted as `queue_id % workers`
    /// (`server/helpers/planning.rs`), so a plan that SHRINKS the worker set
    /// retires ids that still hold bits, and the allocator is carried across the
    /// reload by `parse_source_nat_rules_with_previous` so the bits survive with
    /// it. That route sets NO flag -- not `dead`, not anything -- so there is no
    /// signal for this sweep to react to, and the plan-application path that
    /// knows the retired ids does not hold the allocator. Closing it needs a
    /// signal that does not exist yet, which is why it is not in #6979.
    pub(crate) fn retire_worker(&self, worker_id: u32, now_ns: u64) -> usize {
        // An id too wide for the mask never SET a bit, so it holds nothing to
        // clear. Checked HERE rather than through `NatHolder::bit()`, whose
        // `debug_assert!` would fire on the very id this arm exists to tolerate.
        // `planning.rs` refuses a plan that would mint one, so this is a
        // total-function guard rather than a live case.
        //
        // ITS VALUE IS PROFILE-DEPENDENT, measured rather than assumed. In a
        // RELEASE build it is redundant: `debug_assert!` is compiled out and
        // `1u128.checked_shl(id >= 128)` returns `None` -> `unwrap_or(0)`, so the
        // `holders & 0 != 0` filter matches nothing and the walk frees nothing
        // anyway. Deleting these three lines leaves the whole release suite green
        // (mutation cell M3). In a DEBUG profile the `debug_assert!` panics, so
        // the guard is what keeps this function total there. Stated because the
        // boundary assertion in
        // `retire_worker_is_idempotent_and_ignores_out_of_range_ids_7092`
        // documents that intent without binding it under `make test-rust`, which
        // runs `--release`.
        if worker_id >= MAX_NAT_HOLDER_WORKERS {
            return 0;
        }
        let bit = NatHolder::Worker(worker_id).bit();
        let mut live = self.lock_live();
        let held: Vec<(SourceNatFlowKey, LiveAllocation)> = live
            .live_by_flow
            .iter()
            .filter(|(_, alloc)| alloc.holders & bit != 0)
            .map(|(flow, alloc)| (flow.clone(), *alloc))
            .collect();
        let mut freed = 0usize;
        for (flow, existing) in held {
            let remaining = existing.holders & !bit;
            if remaining != 0 {
                if let Some(slot) = live.live_by_flow.get_mut(&flow) {
                    slot.holders = remaining;
                }
                continue;
            }
            // Last holder retired: the same unlink + lease completion
            // `release_flow` performs, so the two cannot drift.
            self.unlink_live_allocation_locked(&mut live, &flow, existing);
            Self::complete_persistent_lease_locked(&mut live, existing, now_ns);
            freed += 1;
        }
        freed
    }

    pub(super) fn rollback_flow(
        &self,
        flow: SourceNatFlowKey,
        translated: TranslatedTuple,
        now_ns: u64,
        holder: NatHolder,
    ) -> bool {
        let mut live = self.lock_live();
        let Some(existing) = live.live_by_flow.get(&flow).copied() else {
            return false;
        };
        if existing.translated != translated {
            return false;
        }
        if Self::drop_holder_locked(&mut live, &flow, existing, holder) {
            return false;
        }
        // #6528: the shared mode-correct unlink. Rollback keeps its OWN lease
        // arm below — it undoes an activation rather than completing a flow.
        self.unlink_live_allocation_locked(&mut live, &flow, existing);
        if let Some(key) = existing.persistent_key {
            let mut remove_lease = false;
            let mut insert_expiry = None;
            if let Some(lease) = live.persistent_by_source.get_mut(&key) {
                lease.active_flows = lease.active_flows.saturating_sub(1);
                if lease.active_flows == 0 {
                    if lease.activation_saw_completion {
                        let expires_at_ns = now_ns.saturating_add(lease.timeout_ns);
                        lease.expires_at_ns = expires_at_ns;
                        insert_expiry = Some((lease.addr_index, expires_at_ns));
                    } else if lease.activation_had_previous_lease {
                        lease.expires_at_ns = lease.activation_previous_expires_at_ns;
                        insert_expiry = Some((lease.addr_index, lease.expires_at_ns));
                    } else {
                        remove_lease = true;
                    }
                }
            }
            if remove_lease {
                live.persistent_by_source.remove(&key);
                // #6041: an address-only lease holds no pool port bit — only a
                // PAT lease frees its port when the fresh-activation rollback
                // removes it.
                if !existing.address_only {
                    self.free_translated_port(existing.addr_index, translated.port, true);
                }
            }
            if let Some((addr_index, expires_at_ns)) = insert_expiry {
                Self::insert_lease_expiration_locked(&mut live, addr_index, expires_at_ns, key);
            }
        }
        true
    }

    /// #4559: allocate a deterministic CGNAT port from the subscriber's fixed
    /// block. The external pool IP and the port block are a pure function of the
    /// subscriber's internal IPv4 address (`deterministic_indices_v4`), so the
    /// `(external IP, port)` → subscriber reverse mapping needs no per-flow log.
    /// A live flow re-allocates its existing tuple (reuse); a fresh flow claims
    /// the first free port in `[port_start, port_end]` via the occupancy bitmap
    /// (collision-free CAS). Unlike round-robin PAT this does NOT touch the
    /// per-address fresh cursor, the recycle queue, or persistent leases — a
    /// deterministic pool is mutually exclusive with persistent-nat /
    /// address-persistent (enforced at commit). Returns the subscriber-out-of-
    /// range / exhaustion failure to the caller instead of silently falling back
    /// to round-robin.
    pub(super) fn allocate_deterministic_v4(
        &self,
        flow: SourceNatFlowKey,
        pool_v4: &[Ipv4Addr],
        params: DeterministicV4,
        src: Ipv4Addr,
        // #6522: the worker performing this LOCAL allocation, so the record
        // it inserts already names its own holder before any sibling replica
        // reserves against it. `NatHolder::Untracked` reproduces the
        // pre-#6522 single-holder contract and is what the test entry points
        // and the read-only fragment probe pass.
        holder: NatHolder,
    ) -> Result<TranslatedTuple, super::source::SourceNatFailureReason> {
        use super::source::SourceNatFailureReason;
        if self.port_low == 0 || self.port_high == 0 || self.port_low > self.port_high {
            return Err(SourceNatFailureReason::InvalidPortRange);
        }
        let (ip_idx, block_idx) = deterministic_indices_v4(&params, src)
            .ok_or(SourceNatFailureReason::DeterministicSubscriberOutOfRange)?;
        if ip_idx >= pool_v4.len() || ip_idx >= self.shared.occupancy.len() {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(SourceNatFailureReason::AllocatorExhausted);
        }
        let translated_ip = IpAddr::V4(pool_v4[ip_idx]);
        // Block boundaries: [port_low + block_idx*block_size,
        // that + block_size - 1], clamped to port_high. Widths align with the Go
        // compiler because both use the SAME defaulted port range.
        let port_start = self.port_low as u32 + block_idx * params.block_size as u32;
        if port_start > self.port_high as u32 {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(SourceNatFailureReason::AllocatorExhausted);
        }
        let port_end = (port_start + params.block_size as u32 - 1).min(self.port_high as u32);

        let mut live = self.lock_live();
        if let Some(existing) = live.live_by_flow.get(&flow) {
            self.shared.reuses_total.fetch_add(1, Ordering::Relaxed);
            return Ok(existing.translated);
        }
        if live.live_by_flow.len() >= self.shared.max_tracked_flows {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(SourceNatFailureReason::AllocatorExhausted);
        }
        // Claim the first free port in the subscriber's block. The block is small
        // (typically a few thousand ports) and this is the cold path (first
        // packet of a flow), so a linear CAS probe is fine.
        for p in port_start..=port_end {
            let port = p as u16;
            if self.shared.occupancy[ip_idx].reserve(port) {
                let translated = TranslatedTuple {
                    ip: translated_ip,
                    port,
                };
                live.live_by_flow.insert(
                    flow,
                    LiveAllocation {
                        translated,
                        persistent_key: None,
                        addr_index: ip_idx,
                        deterministic: true,
                        address_only: false,
                        // #6522: the ALLOCATING worker's holder bit. A locally-born session is
                        // replicated to every SIBLING worker (`replicate_session_upsert` fans a
                        // `WorkerLocalImport` entry to `peer_worker_commands`, which EXCLUDES
                        // this worker) and each sibling reserves against this same record, so
                        // without this bit the mask holds every worker EXCEPT the one actually
                        // forwarding — and the last sibling replica to age-reap frees a
                        // `(pool_addr, port)` still in use. Recording the owner here makes the
                        // mask complete, so the port survives until the owner itself releases.
                        holders: holder.bit(),
                    },
                );
                self.shared
                    .allocations_total
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(translated);
            }
        }
        // Every port in the subscriber's block is live — the block is full.
        self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
        Err(SourceNatFailureReason::AllocatorExhausted)
    }

    /// #4559: allocate a deterministic CGNAT port for a NAPT64 (mode 2) flow
    /// from the IPv6 subscriber's fixed block. Structurally identical to
    /// [`allocate_deterministic_v4`] — a live flow re-allocates its tuple, a
    /// fresh flow claims the first free port in the subscriber's block via the
    /// occupancy bitmap (collision-free, RFC 6146 BIB), and the freed port is
    /// not recycled onto the per-address queue — differing ONLY in the
    /// subscriber-index derivation ([`deterministic_indices_v6`]: the 32-bit
    /// word after the IPv6 prefix). The external IPv4 pool address and the port
    /// block are a pure function of the subscriber's IPv6 prefix, so
    /// [`reverse_deterministic_v6`] recovers it from `(external IPv4, port)`
    /// with no per-flow log. An out-of-range subscriber fails closed.
    pub(super) fn allocate_deterministic_v6(
        &self,
        flow: SourceNatFlowKey,
        pool_v4: &[Ipv4Addr],
        params: DeterministicV6,
        src: Ipv6Addr,
        // #6522: the worker performing this LOCAL allocation, so the record
        // it inserts already names its own holder before any sibling replica
        // reserves against it. `NatHolder::Untracked` reproduces the
        // pre-#6522 single-holder contract and is what the test entry points
        // and the read-only fragment probe pass.
        holder: NatHolder,
    ) -> Result<TranslatedTuple, super::source::SourceNatFailureReason> {
        use super::source::SourceNatFailureReason;
        if self.port_low == 0 || self.port_high == 0 || self.port_low > self.port_high {
            return Err(SourceNatFailureReason::InvalidPortRange);
        }
        let (ip_idx, block_idx) = deterministic_indices_v6(&params, src)
            .ok_or(SourceNatFailureReason::DeterministicSubscriberOutOfRange)?;
        if ip_idx >= pool_v4.len() || ip_idx >= self.shared.occupancy.len() {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(SourceNatFailureReason::AllocatorExhausted);
        }
        let translated_ip = IpAddr::V4(pool_v4[ip_idx]);
        // Block boundaries mirror the v4 path: [port_low + block_idx*block_size,
        // that + block_size - 1], clamped to port_high. The NAT64 allocator's
        // port_low/port_high are the fixed NAT64 translated-port range, the same
        // range the Go builder computes blocks_per_ip against, so boundaries
        // align.
        let port_start = self.port_low as u32 + block_idx * params.block_size as u32;
        if port_start > self.port_high as u32 {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(SourceNatFailureReason::AllocatorExhausted);
        }
        let port_end = (port_start + params.block_size as u32 - 1).min(self.port_high as u32);

        let mut live = self.lock_live();
        if let Some(existing) = live.live_by_flow.get(&flow) {
            self.shared.reuses_total.fetch_add(1, Ordering::Relaxed);
            return Ok(existing.translated);
        }
        if live.live_by_flow.len() >= self.shared.max_tracked_flows {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(SourceNatFailureReason::AllocatorExhausted);
        }
        for p in port_start..=port_end {
            let port = p as u16;
            if self.shared.occupancy[ip_idx].reserve(port) {
                let translated = TranslatedTuple {
                    ip: translated_ip,
                    port,
                };
                live.live_by_flow.insert(
                    flow,
                    LiveAllocation {
                        translated,
                        persistent_key: None,
                        addr_index: ip_idx,
                        deterministic: true,
                        address_only: false,
                        // #6522: the ALLOCATING worker's holder bit. A locally-born session is
                        // replicated to every SIBLING worker (`replicate_session_upsert` fans a
                        // `WorkerLocalImport` entry to `peer_worker_commands`, which EXCLUDES
                        // this worker) and each sibling reserves against this same record, so
                        // without this bit the mask holds every worker EXCEPT the one actually
                        // forwarding — and the last sibling replica to age-reap frees a
                        // `(pool_addr, port)` still in use. Recording the owner here makes the
                        // mask complete, so the port survives until the owner itself releases.
                        holders: holder.bit(),
                    },
                );
                self.shared
                    .allocations_total
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(translated);
            }
        }
        // Every port in the subscriber's block is live — the block is full.
        self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
        Err(SourceNatFailureReason::AllocatorExhausted)
    }

    /// #4388: reserve a SPECIFIC translated `(ip, port)` for `flow` WITHOUT
    /// running the round-robin allocator, so a peer-synced session's NAT pool
    /// port is marked allocated in this node's LOCAL allocator. Without this,
    /// the standby never learns that the active node handed `(pool_ip, port)`
    /// to a synced session (the standby imports the pre-computed NAT decision;
    /// it never calls `allocate_translation`), so post-failover a fresh local
    /// flow could `allocate_translation` the SAME `(pool_ip, port)` — two
    /// sessions colliding on one NAT source tuple (reply mis-delivery / session
    /// hijack surface).
    ///
    /// The reservation sets the occupancy bit (the ownership token) and records
    /// `live_by_flow` using the synced session's flow key, so:
    ///   - the fresh cursor skips the port when it later reaches that offset
    ///     (the #3047 forward-probe), and
    ///   - the EXISTING teardown path (`release_flow` / `rollback_flow` via
    ///     `release_source_nat_allocation`, already called for every reaped or
    ///     delete-synced session) frees it with the SAME flow key — no new
    ///     release site is needed.
    ///
    /// Idempotent: re-reserving the same `(flow, translated)` (a synced-session
    /// refresh) is a no-op that returns `true`. Returns `false` and leaves the
    /// incumbent untouched if the port is already owned by a DIFFERENT live
    /// allocation (the bit is set — a local flow raced ahead of the sync on the
    /// standby); the caller then tries the next pool rule.
    ///
    /// #5178: `deterministic` mirrors the ACTIVE node's allocation mode for this
    /// synced flow — `true` when the reservation belongs to a deterministic
    /// CGNAT (mode 1) / NAPT64 (mode 2) pool, `false` for round-robin PAT. It is
    /// stored on the `LiveAllocation` so the SAME `release_flow`/`rollback_flow`
    /// teardown frees a deterministic reservation via `free_no_recycle` (the bit
    /// is the only reuse gate) instead of pushing it onto the per-address recycle
    /// `VecDeque`. Before #5178 this was hardcoded `false`, so a standby running
    /// a deterministic pool tagged every synced reservation non-deterministic and
    /// leaked each released port into a recycle queue the deterministic
    /// allocation path never drains — unbounded standby memory growth under
    /// synced-session churn. Matches the non-HA deterministic release contract
    /// (#4559): a deterministic-only pool never grows the recycle queue.
    /// #6765: carry live port ownership across a PARTIAL-OVERLAP pool change.
    ///
    /// THE DEFECT. The allocator carry-over is keyed on the whole address list
    /// (`SourceNatPoolAllocatorKey`), so adding or removing ONE address from a
    /// pool of ten misses the reuse lookup and builds a fresh allocator for the
    /// WHOLE pool — including every RETAINED address. `AddressOccupancy::new`
    /// is all-zero with `cursor: 0` and the set bit is the sole ownership
    /// token, so the next new flow on a retained address is issued
    /// `(retained_addr, port_low)` — a tuple a pre-change live session may still
    /// hold, with the bit that would have blocked it now zeroed. Two sessions on
    /// one translated tuple is reply mis-delivery: traffic to the wrong host.
    ///
    /// WHY THIS SHAPE. The obvious fix — loosen the key and share the allocator
    /// when the pools overlap — is NOT available: `occupancy` is a `Vec` indexed
    /// by pool-address POSITION, so a changed list changes the indices and reuse
    /// would misindex. And the rebuild site holds the previous rules but NOT the
    /// session table, so the carry has to come from the previous allocator's own
    /// live state. That is exactly what the HA session-import path already does
    /// through `reserve_flow` — seed an allocator with a tuple someone else owns
    /// — so the mechanism is audited and exercised; only the caller is new.
    ///
    /// `index_map` maps a PREVIOUS pool-address index to its index in THIS
    /// allocator, for the addresses present in both pools. The caller owns that
    /// mapping because only it knows the address lists; this method owns the
    /// walk, so `live_by_flow` stays private to this module.
    ///
    /// Bounds, deliberately narrow:
    ///   - only addresses in `index_map` (retained) are re-seeded;
    ///   - only ports inside THIS allocator's range — a narrowed port range
    ///     cannot re-seed everything, and what is dropped is RETURNED to the
    ///     caller to log rather than silently discarded;
    ///   - `address_only` allocations hold no port bit (their token is the
    ///     `address_only_owners` reverse identity, not the occupancy bitmap), so
    ///     they are outside the port-reissue defect and are counted, not
    ///     re-seeded. Carrying them is the same class of question as the
    ///     persistent leases and is tracked separately.
    ///
    /// Runs at config-apply only. It does not touch `claim()` and adds no
    /// per-packet work.
    pub(crate) fn reseed_retained_from(
        &self,
        prev: &PortAllocator,
        index_map: &FxHashMap<usize, usize>,
        now_ns: u64,
    ) -> ReseedOutcome {
        let mut out = ReseedOutcome::default();
        if index_map.is_empty() {
            return out;
        }
        // Snapshot the previous live set and RELEASE its lock before touching
        // this allocator's, so the two mutexes are never held at once.
        let carried: Vec<(SourceNatFlowKey, LiveAllocation)> = {
            let prev_live = prev.lock_live();
            prev_live
                .live_by_flow
                .iter()
                .filter(|(_, a)| index_map.contains_key(&a.addr_index))
                .map(|(f, a)| (*f, *a))
                .collect()
        };
        for (flow, alloc) in carried {
            let Some(&new_index) = index_map.get(&alloc.addr_index) else {
                continue;
            };
            if alloc.address_only {
                out.skipped_address_only += 1;
                continue;
            }
            if !self.port_in_range(new_index, alloc.translated.port) {
                out.skipped_out_of_range += 1;
                continue;
            }
            // Preserve the holder set: an HA-synced flow is reserved once per
            // WORKER (#6211 F2) and the port must not be freed until the LAST
            // one lets go. Re-seeding with a single untracked holder would let
            // the first release free a port the other N-1 still forward
            // through. Untracked (holders == 0) is a LOCAL allocation and
            // re-seeds once.
            let mut reserved = false;
            if alloc.holders == 0 {
                reserved = self.reserve_flow(
                    flow,
                    alloc.translated,
                    new_index,
                    alloc.deterministic,
                    now_ns,
                    NatHolder::Untracked,
                );
            } else {
                for worker in 0..MAX_NAT_HOLDER_WORKERS {
                    if alloc.holders & (1u128 << worker) == 0 {
                        continue;
                    }
                    reserved |= self.reserve_flow(
                        flow,
                        alloc.translated,
                        new_index,
                        alloc.deterministic,
                        now_ns,
                        NatHolder::Worker(worker),
                    );
                }
            }
            if reserved {
                out.reseeded += 1;
            } else {
                out.refused += 1;
            }
        }
        out
    }

    /// True when `port` falls inside the configured range of the pool address
    /// at `index`. Read off that address's own `AddressOccupancy` rather than a
    /// shared field, because the range lives per-address — asking the wrong
    /// address would be the same class of positional mistake the whole re-seed
    /// exists to avoid. A zero-range occupancy (unset/invalid
    /// `port_low`/`port_high`) admits nothing.
    fn port_in_range(&self, index: usize, port: u16) -> bool {
        let Some(occ) = self.shared.occupancy.get(index) else {
            return false;
        };
        if occ.range == 0 {
            return false;
        }
        matches!((port as u32).checked_sub(occ.port_low as u32), Some(o) if o < occ.range)
    }

    pub(crate) fn reserve_flow(
        &self,
        flow: SourceNatFlowKey,
        translated: TranslatedTuple,
        addr_index: usize,
        deterministic: bool,
        // #6528: the stale-tuple eviction below retires the incumbent record
        // with RELEASE semantics, and a persistent lease that falls to zero
        // active flows needs a real clock to re-arm its idle expiry. Threaded
        // from `handle_upsert_synced`, the same `now_ns` the synced install
        // already uses.
        now_ns: u64,
        holder: NatHolder,
    ) -> bool {
        if addr_index >= self.shared.occupancy.len() {
            return false;
        }
        let mut live = self.lock_live();
        // A refresh of the same synced flow: if it already holds this exact
        // translated tuple, it is reserved — nothing to do. If the tuple
        // changed (should not happen on a stable sync), retire the stale
        // reservation first so we do not leak the old port's bit — through the
        // shared mode-correct teardown (#6528), which also honours a
        // deterministic reservation's free-without-recycle (#5178).
        if let Some(existing) = live.live_by_flow.get(&flow).copied() {
            if existing.translated == translated {
                // #6211 F2: this early return is where workers 2..N land — the
                // synced entry is fanned out to every worker and each calls
                // through to here against the ONE shared allocator, so this is
                // exactly where a new holder must be recorded. It is ALSO the
                // path an already-holding worker takes on every refresh (HA
                // session-sync reconnect, periodic re-upsert); OR is idempotent
                // so a refresh cannot inflate the mask, which is precisely why
                // this is a bitmask and not a counter.
                if let Some(slot) = live.live_by_flow.get_mut(&flow) {
                    slot.holders |= holder.bit();
                }
                return true;
            }
            // #6528: retire the incumbent through the SAME mode-correct
            // teardown `release_flow` uses. The unconditional
            // `free_translated_port` this replaces was correct for exactly one
            // of the three allocation modes:
            //   - an ADDRESS-ONLY incumbent owns no occupancy bit, so the call
            //     cleared a bit on pool address 0 (its hardcoded `addr_index`)
            //     at the offset of the PRESERVED internal source port — a LIVE
            //     PAT flow's bit whenever a PAT rule shares this allocator —
            //     and recycled it, putting two flows on one translated tuple;
            //     meanwhile its `address_only_owners` token was never cleared,
            //     denying that public reverse identity forever.
            //   - a PERSISTENT incumbent's port belongs to the LEASE, so the
            //     call freed a port the lease still claimed, and the lease's
            //     `active_flows` refcount was never dropped — a leaked refcount
            //     is never idle, so the lease never enters `lease_expirations`
            //     and no GC path can reclaim it.
            // The eviction uses RELEASE (not rollback) semantics because the
            // incumbent tuple WAS in service: this is a re-decision of a live
            // flow, not the withdrawal of an allocation that never shipped.
            self.unlink_live_allocation_locked(&mut live, &flow, existing);
            Self::complete_persistent_lease_locked(&mut live, existing, now_ns);
        }
        // Never steal a port owned by a DIFFERENT live allocation: the bit CAS
        // fails when the port is already occupied, so `reserve` returns false
        // and we leave the incumbent (and the caller falls through to the next
        // rule). The synced decision is authoritative on the wire, but on a
        // healthy standby the owning RG is passive so no local flow should hold
        // the port; if one does, not stealing is the safe choice.
        if !self.shared.occupancy[addr_index].reserve(translated.port) {
            return false;
        }
        live.live_by_flow.insert(
            flow,
            LiveAllocation {
                translated,
                persistent_key: None,
                addr_index,
                deterministic,
                address_only: false,
                // #6211 F2: the first holder. A stale-tuple replace lands here
                // too, and correctly starts a FRESH mask — the previous tuple's
                // holders were holding that tuple, not this one.
                holders: holder.bit(),
            },
        );
        true
    }

    /// #5269: mint an ADDRESS-ONLY occupancy token for a `port no-translation`
    /// or port-less source-NAT flow. Unlike PAT ([`allocate_translation`]) no
    /// pool PORT is consumed — the packet keeps its own source port on the wire
    /// — but the translated REVERSE identity (protocol, chosen pool address,
    /// PRESERVED source port, remote endpoint) is claimed so a SECOND flow that
    /// would map to the SAME public reverse tuple is DENIED as exhaustion
    /// instead of silently receiving an unowned duplicate whose replies the
    /// reverse (1:N) index cannot disambiguate.
    ///
    /// The FIRST flow owns the identity and succeeds; a genuinely-colliding
    /// second flow (same pool address, same preserved port, same remote — for a
    /// port-less protocol, same pool address + remote) fails closed, mirroring
    /// how a full port-translating pool reports exhaustion and the vSRX
    /// address-only / persistent capacity limit. A NON-colliding address-only
    /// flow (different preserved port, pool address, or remote) mints its own
    /// token and succeeds.
    ///
    /// The token is recorded in `live_by_flow` (flagged `address_only`) AND in
    /// `address_only_owners`, so the EXISTING teardown path
    /// (`release_flow`/`rollback_flow` via `release_source_nat_allocation`,
    /// already called for every reaped or delete-synced session) frees it — no
    /// new delete site. Idempotent: a second packet of the SAME flow returns its
    /// existing translated tuple.
    pub(super) fn reserve_address_only(
        &self,
        flow: SourceNatFlowKey,
        translated_ip: IpAddr,
        holder: NatHolder,
    ) -> Result<TranslatedTuple, super::source::SourceNatFailureReason> {
        let translated = TranslatedTuple {
            ip: translated_ip,
            // Port-bearing protocols preserve their source port; a port-less
            // protocol carries 0 here. This value is NOT written to the wire
            // (the caller leaves `rewrite_src_port` unset); it keys the reverse
            // identity and lets the SAME `release_flow` free the token.
            port: flow.src_port,
        };
        let rkey = AddressOnlyReverseKey {
            protocol: flow.protocol,
            translated_ip,
            translated_port: flow.src_port,
            dst_ip: flow.dst_ip,
            dst_port: flow.dst_port,
        };
        let mut live = self.lock_live();
        // Idempotent re-entry: a second packet of the same flow (racing session
        // install) reuses its first decision rather than re-keying.
        //
        // #6211 F2: this is also where workers 2..N land when a synced
        // ADDRESS-ONLY (#5338) token is fanned out, and where an already-holding
        // worker lands on every refresh — so record the holder here, exactly as
        // `reserve_flow` does on its own early return.
        if let Some(existing) = live.live_by_flow.get_mut(&flow) {
            existing.holders |= holder.bit();
            let translated = existing.translated;
            self.shared.reuses_total.fetch_add(1, Ordering::Relaxed);
            return Ok(translated);
        }
        // Collision: the reverse identity is already owned by a DIFFERENT flow.
        // Two flows sharing one public reverse tuple cannot coexist (their
        // replies are indistinguishable), so deny the second — the address-only
        // capacity limit. `flow` is not in `live_by_flow` here (checked above),
        // so any existing owner is necessarily a different flow.
        if live.address_only_owners.contains_key(&rkey) {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
        }
        if live.live_by_flow.len() >= self.shared.max_tracked_flows {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
        }
        live.address_only_owners.insert(rkey, flow);
        live.live_by_flow.insert(
            flow,
            LiveAllocation {
                translated,
                persistent_key: None,
                // No pool-port bit is claimed for an address-only token, so the
                // occupancy address index is irrelevant to its release.
                addr_index: 0,
                deterministic: false,
                address_only: true,
                // #6211 F2: the first holder of this synced address-only token.
                holders: holder.bit(),
            },
        );
        self.shared
            .allocations_total
            .fetch_add(1, Ordering::Relaxed);
        Ok(translated)
    }

    /// #6751: mint the translated identity for an INTERFACE-mode source-NAT
    /// flow — preserve the source port when its reverse identity is free, PAT
    /// the LATER collider when it is not.
    ///
    /// This is [`reserve_address_only`] plus the fallback pool mode cannot
    /// have. Pool mode denies a colliding address-only flow as exhaustion
    /// because `port no-translation` means what it says: the port must not
    /// move. Interface mode carries no such promise, so instead of dropping the
    /// second host it moves its port and both flows keep a UNIQUE reverse
    /// identity — which is the whole point, since the reply
    /// `(server -> egress:port)` carries nothing else to tell them apart.
    ///
    /// Occupancy is the full reverse identity `(protocol, egress address,
    /// translated port, remote ip, remote port)` — the shipped
    /// [`AddressOnlyReverseKey`]. So:
    ///   * the same source port to two DIFFERENT servers: BOTH preserve;
    ///   * TCP and UDP on the same numeric port: BOTH preserve;
    ///   * a source port below 1024: PRESERVED when free (PAT candidates are
    ///     drawn from the ephemeral range, but preservation is not);
    ///   * two hosts, one port, one server: the first preserves, the second
    ///     PATs. Only the second flow's wire tuple changes.
    ///
    /// No pool PORT bit is claimed (`address_only: true`), so the record is
    /// byte-identical in shape to every other address-only token and the
    /// EXISTING teardown (`release_flow` / `rollback_flow` via
    /// `release_source_nat_allocation*`) frees it — no new delete site. That is
    /// load-bearing: `release_source_nat_allocation_with_mode` reconstructs
    /// `translated.port` as `rewrite_src_port.unwrap_or(key.src_port)`, which
    /// is the preserved port for a preserved mint and the PAT'd port for a
    /// PAT'd one, matching `LiveAllocation::translated` in both cases.
    ///
    /// Idempotent: a second packet of the same flow returns its first decision.
    pub(super) fn allocate_interface_identity(
        &self,
        flow: SourceNatFlowKey,
        translated_ip: IpAddr,
        holder: NatHolder,
    ) -> Result<InterfaceIdentity, super::source::SourceNatFailureReason> {
        let rkey_for = |port: u16| AddressOnlyReverseKey::for_flow(&flow, translated_ip, port);
        let preserved = flow.src_port;
        {
            let mut live = self.lock_live();
            // Idempotent re-entry, and the point every already-holding worker
            // lands on for a refresh.
            if let Some(identity) =
                self.reenter_interface_record_locked(&mut live, &flow, holder, preserved)
            {
                return Ok(identity);
            }
            if live.live_by_flow.len() >= self.shared.max_tracked_flows {
                self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
                return Err(super::source::SourceNatFailureReason::InterfaceRegistryCap);
            }
            // PRESERVE-FIRST. Identity check and insert happen under ONE
            // acquisition, so two workers cannot both observe the port free.
            if !live.address_only_owners.contains_key(&rkey_for(preserved)) {
                self.insert_interface_record_locked(
                    &mut live,
                    flow,
                    translated_ip,
                    preserved,
                    holder,
                );
                return Ok(InterfaceIdentity {
                    port: preserved,
                    patted: false,
                });
            }
        }
        // The preserved identity is owned by a DIFFERENT flow: this is the
        // #6751 shape. Walk the ephemeral range for a free identity.
        //
        // The start ordinal is captured ONCE from the allocator's own cursor
        // and the walk is LOCAL from there. Re-reading a shared cursor
        // mid-walk would let a concurrent mint move it and turn a bounded
        // single cycle into an unbounded one.
        crate::nat::iface_registry::INTERFACE_SNAT_PAT_COLLISIONS.fetch_add(1, Ordering::Relaxed);
        let span = u32::from(self.port_high) - u32::from(self.port_low) + 1;
        let start = self.shared.addr_counter_v4.fetch_add(1, Ordering::Relaxed) % span;
        let mut probed = 0u32;
        while probed < span {
            let mut live = self.lock_live();
            // A chunk boundary released the mutex, so re-check the two
            // preconditions the first critical section established. Without
            // this a racing install of the SAME flow (a bulk-sync fan-out
            // landing while a local packet probes) would mint a SECOND record
            // for one flow, and only one of them would ever be released.
            if let Some(identity) =
                self.reenter_interface_record_locked(&mut live, &flow, holder, preserved)
            {
                return Ok(identity);
            }
            if live.live_by_flow.len() >= self.shared.max_tracked_flows {
                self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
                return Err(super::source::SourceNatFailureReason::InterfaceRegistryCap);
            }
            let chunk_end = (probed + INTERFACE_PAT_PROBE_CHUNK).min(span);
            while probed < chunk_end {
                // `span <= 65536` always (`port_high - port_low + 1`), so
                // `offset` fits a u16 and `port_low + offset <= port_high`
                // by construction — the saturating add is belt-and-braces,
                // never a reachable clamp.
                let offset = (start + probed) % span;
                let candidate = self.port_low.saturating_add(offset as u16);
                probed += 1;
                if live.address_only_owners.contains_key(&rkey_for(candidate)) {
                    continue;
                }
                self.insert_interface_record_locked(
                    &mut live,
                    flow,
                    translated_ip,
                    candidate,
                    holder,
                );
                return Ok(InterfaceIdentity {
                    port: candidate,
                    patted: true,
                });
            }
            // #4676 discipline: yield between chunks so a full-cycle probe
            // cannot hold the mutex against every other worker's admission.
            drop(live);
            std::thread::yield_now();
        }
        // Every port in the range is owned for this `(egress, remote)`
        // identity. Fail CLOSED — an unowned duplicate is precisely what this
        // function exists to prevent.
        self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
        Err(super::source::SourceNatFailureReason::InterfaceIdentityExhausted)
    }

    /// #6751: reserve a PEER-SYNCED interface-mode translated identity — the
    /// standby's mirror of [`allocate_interface_identity`], with the port
    /// already decided by the active node.
    ///
    /// The standby must hold the identities the active minted BEFORE it ever
    /// mints locally, or its first post-failover admission would preserve a
    /// port an imported live session is already using and reintroduce the
    /// ambiguity on the promoted node.
    ///
    /// Mirrors [`reserve_flow`]'s stale-tuple semantics rather than inventing
    /// new ones: a re-sync that carries a DIFFERENT translated port for a flow
    /// already on record replaces the record (freeing the old identity), so a
    /// tuple-changing refresh cannot strand an identity no release will ever
    /// name. `Owned` on success or idempotent re-entry; `IdentityConflict` when
    /// a DIFFERENT flow owns the requested identity.
    pub(super) fn reserve_interface_identity(
        &self,
        flow: SourceNatFlowKey,
        translated_ip: IpAddr,
        translated_port: u16,
        now_ns: u64,
        holder: NatHolder,
    ) -> InterfaceDomainReserve {
        let rkey = AddressOnlyReverseKey::for_flow(&flow, translated_ip, translated_port);
        let mut live = self.lock_live();
        if let Some(existing) = live.live_by_flow.get(&flow).copied() {
            if existing.translated.ip == translated_ip
                && existing.translated.port == translated_port
            {
                if let Some(slot) = live.live_by_flow.get_mut(&flow) {
                    slot.holders |= holder.bit();
                }
                self.shared.reuses_total.fetch_add(1, Ordering::Relaxed);
                return InterfaceDomainReserve::Owned;
            }
            // A different flow may already own the NEW identity; refuse before
            // tearing down the old record so a refused reserve is a no-op.
            if live
                .address_only_owners
                .get(&rkey)
                .is_some_and(|o| *o != flow)
            {
                return InterfaceDomainReserve::IdentityConflict;
            }
            self.unlink_live_allocation_locked(&mut live, &flow, existing);
            Self::complete_persistent_lease_locked(&mut live, existing, now_ns);
        } else if live
            .address_only_owners
            .get(&rkey)
            .is_some_and(|o| *o != flow)
        {
            return InterfaceDomainReserve::IdentityConflict;
        } else if live.live_by_flow.len() >= self.shared.max_tracked_flows {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return InterfaceDomainReserve::RegistryCap;
        }
        self.insert_interface_record_locked(
            &mut live,
            flow,
            translated_ip,
            translated_port,
            holder,
        );
        InterfaceDomainReserve::Owned
    }

    /// #6751: the idempotent-re-entry answer, shared by the first critical
    /// section and the chunk-boundary re-check.
    ///
    /// ONE body, because a divergence between the two is always a bug: the
    /// chunk re-check exists precisely to catch a racing install of the SAME
    /// flow, and a copy that computed `patted` differently would hand one flow
    /// two different wire decisions depending on which acquisition saw it.
    /// Records the holder on the way through, exactly as `reserve_address_only`
    /// does on its own early return.
    fn reenter_interface_record_locked(
        &self,
        live: &mut PortAllocatorLiveState,
        flow: &SourceNatFlowKey,
        holder: NatHolder,
        preserved: u16,
    ) -> Option<InterfaceIdentity> {
        let existing = live.live_by_flow.get_mut(flow)?;
        existing.holders |= holder.bit();
        let translated = existing.translated;
        self.shared.reuses_total.fetch_add(1, Ordering::Relaxed);
        Some(InterfaceIdentity {
            port: translated.port,
            patted: translated.port != preserved,
        })
    }

    /// The record shape shared by every interface-mode mint and reserve, so a
    /// preserved token, a PAT'd token and a synced token cannot drift apart in
    /// the one field that decides how they are torn down (`address_only`).
    fn insert_interface_record_locked(
        &self,
        live: &mut PortAllocatorLiveState,
        flow: SourceNatFlowKey,
        translated_ip: IpAddr,
        translated_port: u16,
        holder: NatHolder,
    ) {
        live.address_only_owners.insert(
            AddressOnlyReverseKey::for_flow(&flow, translated_ip, translated_port),
            flow,
        );
        live.live_by_flow.insert(
            flow,
            LiveAllocation {
                translated: TranslatedTuple {
                    ip: translated_ip,
                    port: translated_port,
                },
                persistent_key: None,
                // Interface mode claims no pool-port bit, so no address index
                // is meaningful; `address_only` routes the teardown to the
                // reverse-identity arm of `unlink_live_allocation_locked`.
                addr_index: 0,
                deterministic: false,
                address_only: true,
                holders: holder.bit(),
            },
        );
        self.shared
            .allocations_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// #6226: reserve a non-deterministic, non-persistent ADDRESS-ONLY token
    /// probing the WHOLE pool from the round-robin start, mirroring the
    /// port-translating [`allocate_translation`] loop.
    ///
    /// The pre-#6226 caller picked ONE round-robin address via [`address_index`]
    /// and called [`reserve_address_only`] on it — a single probe that returned
    /// `AllocatorExhausted` (→ drop) the moment that one address's reverse
    /// identity collided for this remote, even though a SIBLING pool address was
    /// free for the same remote. The shared round-robin counter is oblivious to
    /// per-remote occupancy, so an unrelated flow advancing it trivially lands a
    /// later flow on an already-owned address. This loops from the caller's
    /// round-robin start (`start_abs`, already resolved via [`address_index`] so
    /// the counter is advanced EXACTLY ONCE per flow — same as the old single
    /// probe) across every pool address and mints the token on the FIRST address
    /// whose reverse identity is free; it fails as exhaustion ONLY when EVERY
    /// pool address collides for this remote.
    ///
    /// `address_persistent` keeps the single-probe contract for sticky-by-source
    /// pools (`address_attempts == 1`): the sticky address is intentional, not
    /// round-robin, so it is not rotated away from on a collision. The
    /// deterministic-CGNAT (#5341) and address-only persistent-NAT (#6041)
    /// branches are untouched — they correctly single-probe their chosen address.
    ///
    /// The minted token is byte-identical to [`reserve_address_only`]'s
    /// (`translated = (chosen address, preserved source port)`, `address_only =
    /// true`, `persistent_key = None`, `addr_index = 0`), so the SAME
    /// `release_flow`/`rollback_flow` teardown frees it — no new leak, no new
    /// delete site. Idempotent re-entry (a racing second packet of the same
    /// flow) returns the existing translation regardless of the round-robin
    /// start.
    pub(super) fn reserve_address_only_roundrobin(
        &self,
        flow: SourceNatFlowKey,
        family_addresses: PoolAddressFamily<'_>,
        family_offset: usize,
        start_abs: usize,
        address_persistent: bool,
        // #6522: the worker performing this LOCAL allocation, so the record
        // it inserts already names its own holder before any sibling replica
        // reserves against it. `NatHolder::Untracked` reproduces the
        // pre-#6522 single-holder contract and is what the test entry points
        // and the read-only fragment probe pass.
        holder: NatHolder,
    ) -> Result<TranslatedTuple, super::source::SourceNatFailureReason> {
        let family_len = family_addresses.len();
        if family_len == 0 {
            return Err(super::source::SourceNatFailureReason::WrongAddressFamily);
        }
        let start_rel = start_abs.saturating_sub(family_offset) % family_len;
        // Sticky-by-source pools single-probe their chosen address; round-robin
        // pools rotate through the whole pool (mirrors `allocate_translation`).
        let address_attempts = if address_persistent { 1 } else { family_len };

        let mut live = self.lock_live();
        // Idempotent re-entry: a second packet of the same flow (racing session
        // install) reuses its first decision rather than re-keying.
        if let Some(existing) = live.live_by_flow.get(&flow) {
            self.shared.reuses_total.fetch_add(1, Ordering::Relaxed);
            return Ok(existing.translated);
        }
        // Global flow-table cap (the address-only token lives in `live_by_flow`);
        // one successful probe inserts exactly one entry, so check it once here.
        if live.live_by_flow.len() >= self.shared.max_tracked_flows {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
        }
        // Probe each pool address from the round-robin start; the FIRST whose
        // reverse identity is free for this remote wins.
        for offset in 0..address_attempts {
            let rel = (start_rel + offset) % family_len;
            let translated_ip = family_addresses.ip_at(rel);
            let rkey = AddressOnlyReverseKey {
                protocol: flow.protocol,
                translated_ip,
                translated_port: flow.src_port,
                dst_ip: flow.dst_ip,
                dst_port: flow.dst_port,
            };
            if live.address_only_owners.contains_key(&rkey) {
                // This address's reverse identity is owned by a DIFFERENT flow
                // for this remote — try the next sibling instead of dropping.
                continue;
            }
            let translated = TranslatedTuple {
                ip: translated_ip,
                // Port-bearing protocols preserve their source port; a port-less
                // protocol carries 0. NOT written to the wire (the caller leaves
                // `rewrite_src_port` unset); it keys the reverse identity and lets
                // the SAME `release_flow` free the token.
                port: flow.src_port,
            };
            live.address_only_owners.insert(rkey, flow);
            live.live_by_flow.insert(
                flow,
                LiveAllocation {
                    translated,
                    persistent_key: None,
                    // No pool-port bit is claimed for an address-only token.
                    addr_index: 0,
                    deterministic: false,
                    address_only: true,
                    // #6522: the ALLOCATING worker's holder bit. A locally-born session is
                    // replicated to every SIBLING worker (`replicate_session_upsert` fans a
                    // `WorkerLocalImport` entry to `peer_worker_commands`, which EXCLUDES
                    // this worker) and each sibling reserves against this same record, so
                    // without this bit the mask holds every worker EXCEPT the one actually
                    // forwarding — and the last sibling replica to age-reap frees a
                    // `(pool_addr, port)` still in use. Recording the owner here makes the
                    // mask complete, so the port survives until the owner itself releases.
                    holders: holder.bit(),
                },
            );
            self.shared
                .allocations_total
                .fetch_add(1, Ordering::Relaxed);
            return Ok(translated);
        }
        // Every pool address's reverse identity is already owned by a different
        // flow for this remote — genuine address-only exhaustion.
        self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
        Err(super::source::SourceNatFailureReason::AllocatorExhausted)
    }

    /// #6041: reserve an ADDRESS-ONLY PERSISTENT-NAT lease for a `port
    /// no-translation` (or port-less) flow whose pool also configures
    /// `persistent-nat`. Unlike [`reserve_address_only`] (the per-flow #5269
    /// collision token with NO lease) this PINS a public pool ADDRESS across the
    /// configured permit scope: every flow keyed to the same
    /// [`PersistentSourceKey`] reuses the SAME public address for the lease's
    /// lifetime, so persistence no longer depends on the global
    /// `address-persistent` hash (the #5819/#6041 defect the fail-closed reject
    /// stood in for). No pool PORT is consumed — the packet keeps its own source
    /// port on the wire — so the lease records `address_only = true` and every
    /// lease teardown site skips `free_translated_port`.
    ///
    /// Lifecycle mirrors the port-translating persistent lease
    /// ([`allocate_translation_locked`] + [`reuse_existing_lease_locked`]):
    ///   - a live/valid lease REUSES its pinned address, bumps `active_flows`,
    ///     re-arms the activation-rollback bookkeeping on the 0->1 edge, drops
    ///     its idle expiry-index entry, and pushes the inactivity expiry out;
    ///   - an EXPIRED idle lease is torn down (NO port to free) and a fresh
    ///     address is picked via [`address_index`];
    ///   - no lease => a fresh address is picked and a new lease created.
    ///
    /// The #5269 reverse-identity collision guard still runs PER FLOW: THIS
    /// flow's `(protocol, chosen address, preserved source port, remote)` token
    /// is claimed in `address_only_owners` and DENIED as exhaustion if a
    /// DIFFERENT flow already owns it (two flows sharing one public reverse tuple
    /// cannot coexist). On a collision the lease is left untouched. The token AND
    /// the lease refcount are torn down PER FLOW by the SAME teardown path
    /// (`release_flow`/`rollback_flow`) — no new delete site. Idempotent: a
    /// second packet of the same flow returns its existing translated tuple.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn reserve_address_only_persistent(
        &self,
        flow: SourceNatFlowKey,
        family_addresses: PoolAddressFamily<'_>,
        family_offset: usize,
        address_persistent: bool,
        persistent_nat_permit: super::source::PersistentNatPermit,
        persistent_nat_timeout_ns: u64,
        now_ns: u64,
        // #6522: the worker performing this LOCAL allocation, so the record
        // it inserts already names its own holder before any sibling replica
        // reserves against it. `NatHolder::Untracked` reproduces the
        // pre-#6522 single-holder contract and is what the test entry points
        // and the read-only fragment probe pass.
        holder: NatHolder,
    ) -> Result<TranslatedTuple, super::source::SourceNatFailureReason> {
        let family_len = family_addresses.len();
        if family_len == 0 {
            return Err(super::source::SourceNatFailureReason::WrongAddressFamily);
        }
        let key = flow.persistent_source_key(persistent_nat_permit);
        let timeout_ns = persistent_nat_timeout_ns.max(NS_PER_SEC);

        let mut live = self.lock_live();
        self.gc_expired_locked(&mut live, now_ns, ALLOCATION_GC_BUDGET);

        // Idempotent re-entry: a second packet of the same flow reuses its first
        // decision rather than re-keying / double-counting the lease refcount.
        if let Some(existing) = live.live_by_flow.get(&flow) {
            self.shared.reuses_total.fetch_add(1, Ordering::Relaxed);
            return Ok(existing.translated);
        }
        if live.live_by_flow.len() >= self.shared.max_tracked_flows {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
        }

        // Resolve the lease's pinned address: reuse a still-valid lease, tear down
        // an expired-idle one, else pick fresh.
        let mut reuse_addr: Option<(IpAddr, usize)> = None;
        let mut expired: Option<(usize, u64)> = None;
        if let Some(lease) = live.persistent_by_source.get(&key).copied() {
            if lease.active_flows > 0 || lease.expires_at_ns > now_ns {
                reuse_addr = Some((lease.translated.ip, lease.addr_index));
            } else {
                expired = Some((lease.addr_index, lease.expires_at_ns));
            }
        }
        if let Some((addr_index, expires_at_ns)) = expired {
            // Idle + past its inactivity window: drop it (an address-only lease
            // holds NO port bit to free) so a fresh address is picked below.
            Self::remove_lease_expiration_locked(&mut live, addr_index, expires_at_ns, key);
            live.persistent_by_source.remove(&key);
        }

        let reusing = reuse_addr.is_some();
        let (translated_ip, addr_index) = match reuse_addr {
            Some((ip, idx)) => (ip, idx),
            None => {
                let abs =
                    self.address_index(flow.src_ip, family_offset, family_len, address_persistent);
                let rel = abs.saturating_sub(family_offset) % family_len;
                (family_addresses.ip_at(rel), family_offset + rel)
            }
        };

        // #5269 reverse-identity collision guard for THIS flow, checked BEFORE any
        // lease mutation so a denied flow leaves the lease untouched. The
        // preserved source port keys the reverse identity (0 for a port-less
        // protocol); it is never written to the wire (the caller leaves
        // `rewrite_src_port` unset).
        let rkey = AddressOnlyReverseKey {
            protocol: flow.protocol,
            translated_ip,
            translated_port: flow.src_port,
            dst_ip: flow.dst_ip,
            dst_port: flow.dst_port,
        };
        if live.address_only_owners.contains_key(&rkey) {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
        }

        // Lease-table pressure cap for a FRESH lease, mirroring
        // `allocate_translation_locked`: one bounded GC pass, then treat a still-
        // full table as exhaustion.
        if !reusing && live.persistent_by_source.len() >= self.shared.max_tracked_flows {
            self.gc_expired_locked(&mut live, now_ns, PRESSURE_GC_BUDGET);
            if live.persistent_by_source.len() >= self.shared.max_tracked_flows {
                self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
                return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
            }
        }

        let translated = TranslatedTuple {
            ip: translated_ip,
            port: flow.src_port,
        };
        let expires_at_ns = now_ns.saturating_add(timeout_ns);

        // Commit this flow's reverse-identity token (freed per flow on teardown).
        live.address_only_owners.insert(rkey, flow);

        if reusing {
            // Bump the existing lease. On the 0->1 active-flow edge re-arm the
            // activation-rollback bookkeeping and drop the stale idle expiry-index
            // entry (an ACTIVE lease is not indexed). Always push the inactivity
            // expiry out.
            let mut remove_expiry = None;
            if let Some(lease) = live.persistent_by_source.get_mut(&key) {
                if lease.active_flows == 0 {
                    remove_expiry = Some((lease.addr_index, lease.expires_at_ns));
                    lease.activation_saw_completion = false;
                    lease.activation_previous_expires_at_ns = lease.expires_at_ns;
                    lease.activation_had_previous_lease = true;
                }
                lease.active_flows = lease.active_flows.saturating_add(1);
                lease.expires_at_ns = expires_at_ns;
            }
            if let Some((idx, old_expires_at_ns)) = remove_expiry {
                Self::remove_lease_expiration_locked(&mut live, idx, old_expires_at_ns, key);
            }
            self.shared.reuses_total.fetch_add(1, Ordering::Relaxed);
        } else {
            live.persistent_by_source.insert(
                key,
                PersistentLease {
                    translated,
                    addr_index,
                    expires_at_ns,
                    timeout_ns,
                    active_flows: 1,
                    completed_flows: 0,
                    activation_saw_completion: false,
                    activation_previous_expires_at_ns: 0,
                    activation_had_previous_lease: false,
                    address_only: true,
                },
            );
            self.shared
                .allocations_total
                .fetch_add(1, Ordering::Relaxed);
        }

        live.live_by_flow.insert(
            flow,
            LiveAllocation {
                translated,
                persistent_key: Some(key),
                addr_index,
                deterministic: false,
                address_only: true,
                // #6522: the ALLOCATING worker's holder bit. A locally-born session is
                // replicated to every SIBLING worker (`replicate_session_upsert` fans a
                // `WorkerLocalImport` entry to `peer_worker_commands`, which EXCLUDES
                // this worker) and each sibling reserves against this same record, so
                // without this bit the mask holds every worker EXCEPT the one actually
                // forwarding — and the last sibling replica to age-reap frees a
                // `(pool_addr, port)` still in use. Recording the owner here makes the
                // mask complete, so the port survives until the owner itself releases.
                holders: holder.bit(),
            },
        );
        Ok(translated)
    }

    /// Test-only: snapshot the address-only reverse-identity ownership map so a
    /// white-box test can assert the reverse index resolves each public tuple to
    /// exactly one owning forward flow (#5269).
    #[cfg(test)]
    pub(super) fn debug_address_only_owners(
        &self,
    ) -> Vec<(AddressOnlyReverseKey, SourceNatFlowKey)> {
        let live = self.shared.live.lock().unwrap_or_else(|e| e.into_inner());
        live.address_only_owners
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect()
    }

    pub(super) fn snapshot(&self) -> PortAllocatorSnapshot {
        let live = self.shared.live.lock().unwrap_or_else(|e| e.into_inner());
        let live_flows = live.live_by_flow.len() as u64;
        let persistent_leases = live.persistent_by_source.len() as u64;
        drop(live);
        // used_ports is the total set bits across the lock-free occupancy
        // bitmaps (popcount). Cold path (1/s status poll), so recomputing it
        // rather than maintaining a hot-path atomic is fine.
        let used_ports: u64 = self
            .shared
            .occupancy
            .iter()
            .map(|occ| occ.occupied_count() as u64)
            .sum();
        PortAllocatorSnapshot {
            live_flows,
            used_ports,
            persistent_leases,
            max_tracked_flows: self.shared.max_tracked_flows as u64,
            allocations_total: self.shared.allocations_total.load(Ordering::Relaxed),
            reuses_total: self.shared.reuses_total.load(Ordering::Relaxed),
            exhaustion_total: self.shared.exhaustion_total.load(Ordering::Relaxed),
            live_lock_acquisitions_total: self
                .shared
                .live_lock_acquisitions
                .load(Ordering::Relaxed),
            live_lock_contended_total: self.shared.live_lock_contended.load(Ordering::Relaxed),
        }
    }

    /// #4676: run the opportunistic global expiry GC WITHOUT holding the alloc
    /// mutex across the whole sweep.
    ///
    /// The sweep is chunked: each chunk collects up to `GC_CHUNK` expired
    /// leases from the global expiration index under a SHORT `live` critical
    /// section (the map mutations that MUST be serialized), releases the guard,
    /// then frees those ports on the lock-free occupancy bitmap
    /// (`AddressOccupancy::free_recycle`, a `fetch_and` + per-address recycle
    /// push) with `live` NOT held. Releasing `live` between chunks lets a
    /// concurrent `allocate_translation` acquire the mutex for its tiny
    /// `live_by_flow` insert instead of blocking for the full sweep — the
    /// Phase-1 (#2852) residual this addresses.
    ///
    /// Safety: each reclaim stays idempotent. Under the short CS the lease is
    /// re-checked (`active_flows == 0 && expires_at_ns` matches) before removal,
    /// so a concurrent `release_flow`/`rollback_flow` that refreshed or bumped
    /// the lease is skipped. The port bit is the ownership token and stays SET
    /// from lease removal until we free it, so a concurrent `claim()` cannot
    /// re-hand-out the port in the gap (no double-claim); once freed it returns
    /// to the pool. `budget` bounds total reclaims (amortized GC). This is
    /// disjoint from the caller's insert CS: GC touches only
    /// `persistent_by_source` + the expiration indexes + occupancy, never
    /// `live_by_flow`, so running it in its own lock scope is behaviorally
    /// equivalent to the pre-#4676 nested call.
    fn gc_expired_chunked(&self, now_ns: u64, budget: usize) -> usize {
        if now_ns == 0 || budget == 0 {
            return 0;
        }
        let mut reclaimed = 0;
        let mut freed: Vec<(usize, u16)> = Vec::new();
        while reclaimed < budget {
            let chunk = (budget - reclaimed).min(GC_CHUNK);
            freed.clear();
            let collected = {
                let mut live = self.lock_live();
                #[cfg(test)]
                self.shared
                    .gc_lock_acquisitions
                    .fetch_add(1, Ordering::Relaxed);
                self.collect_expired_global_locked(&mut live, now_ns, chunk, &mut freed)
                // `live` guard dropped here, BEFORE the lock-free port frees
                // below and BEFORE the loop re-acquires it for the next chunk.
            };
            for &(addr_index, port) in &freed {
                self.free_translated_port(addr_index, port, true);
            }
            reclaimed += collected;
            if collected < chunk {
                // A short chunk means the expired frontier is exhausted (the
                // earliest remaining lease is not yet expired, or the index is
                // empty). Stop instead of re-locking for a guaranteed-empty
                // chunk. Any lease that expires later is reclaimed by a
                // subsequent amortized GC pass — GC is opportunistic, never the
                // sole reclaim path.
                break;
            }
        }
        reclaimed
    }

    /// Nested (guard-held) global expiry GC for the near-capacity pressure
    /// fallback in `allocate_translation_locked`, where `live` is held across
    /// the whole claim+insert and cannot be released mid-flight. Shares the
    /// `collect_expired_global_locked` primitive with the chunked path; the
    /// only difference is that the reclaimed ports are freed inline while the
    /// caller still holds `live` (unchanged pre-#4676 behavior).
    fn gc_expired_locked(
        &self,
        live: &mut PortAllocatorLiveState,
        now_ns: u64,
        budget: usize,
    ) -> usize {
        let mut freed: Vec<(usize, u16)> = Vec::new();
        let reclaimed = self.collect_expired_global_locked(live, now_ns, budget, &mut freed);
        for (addr_index, port) in freed {
            self.free_translated_port(addr_index, port, true);
        }
        reclaimed
    }

    /// Nested (guard-held) per-address expiry GC for the pressure fallback.
    /// Same guard-held free discipline as `gc_expired_locked`.
    fn gc_expired_for_addr_locked(
        &self,
        live: &mut PortAllocatorLiveState,
        addr_index: usize,
        now_ns: u64,
        budget: usize,
    ) -> usize {
        let mut freed: Vec<(usize, u16)> = Vec::new();
        let reclaimed =
            self.collect_expired_for_addr_locked(live, addr_index, now_ns, budget, &mut freed);
        for (addr_index, port) in freed {
            self.free_translated_port(addr_index, port, true);
        }
        reclaimed
    }

    /// Collect up to `budget` expired idle leases from the GLOBAL expiration
    /// index under a HELD `live` guard: pop the earliest-expiring entries,
    /// remove them from `persistent_by_source` and both expiration indexes, and
    /// record each reclaimed lease's `(addr_index, port)` in `freed` for the
    /// caller to release on the lock-free occupancy bitmap. Returns the count
    /// collected. Does NOT touch the occupancy bitmap — port release is
    /// deferred so it need not be serialized behind the alloc mutex (#4676).
    fn collect_expired_global_locked(
        &self,
        live: &mut PortAllocatorLiveState,
        now_ns: u64,
        budget: usize,
        freed: &mut Vec<(usize, u16)>,
    ) -> usize {
        if now_ns == 0 || budget == 0 {
            return 0;
        }
        let mut reclaimed = 0;
        for _ in 0..budget {
            let Some((expires_at_ns, key)) = live.lease_expirations.iter().next().copied() else {
                break;
            };
            if expires_at_ns > now_ns {
                break;
            }
            live.lease_expirations.remove(&(expires_at_ns, key));
            if let Some(lease) = live.persistent_by_source.get(&key).copied() {
                if let Some(by_addr) = live.lease_expirations_by_addr.get_mut(lease.addr_index) {
                    by_addr.remove(&(expires_at_ns, key));
                }
            }
            if self.reclaim_expired_lease_locked(live, key, expires_at_ns, freed) {
                reclaimed += 1;
            }
        }
        reclaimed
    }

    /// Per-address variant of `collect_expired_global_locked`: pops from
    /// `lease_expirations_by_addr[addr_index]` (and mirrors the removal into the
    /// global index). Records reclaimed ports into `freed`.
    fn collect_expired_for_addr_locked(
        &self,
        live: &mut PortAllocatorLiveState,
        addr_index: usize,
        now_ns: u64,
        budget: usize,
        freed: &mut Vec<(usize, u16)>,
    ) -> usize {
        if now_ns == 0 || budget == 0 || addr_index >= live.lease_expirations_by_addr.len() {
            return 0;
        }
        let mut reclaimed = 0;
        for _ in 0..budget {
            let Some((expires_at_ns, key)) = live.lease_expirations_by_addr[addr_index]
                .iter()
                .next()
                .copied()
            else {
                break;
            };
            if expires_at_ns > now_ns {
                break;
            }
            live.lease_expirations_by_addr[addr_index].remove(&(expires_at_ns, key));
            live.lease_expirations.remove(&(expires_at_ns, key));
            if self.reclaim_expired_lease_locked(live, key, expires_at_ns, freed) {
                reclaimed += 1;
            }
        }
        reclaimed
    }

    /// Remove one expired idle lease from `persistent_by_source` under a HELD
    /// `live` guard and RECORD its `(addr_index, port)` in `freed` — it does NOT
    /// clear the occupancy bit (the caller frees the collected ports, possibly
    /// after dropping `live`, keeping the lock-free bitmap op off the alloc
    /// mutex, #4676). Re-checks the lease is still idle and its expiry still
    /// matches so a concurrent refresh/rollback is not clobbered. Returns true
    /// iff a lease was reclaimed.
    fn reclaim_expired_lease_locked(
        &self,
        live: &mut PortAllocatorLiveState,
        key: PersistentSourceKey,
        expires_at_ns: u64,
        freed: &mut Vec<(usize, u16)>,
    ) -> bool {
        let Some(lease) = live.persistent_by_source.get(&key).copied() else {
            return false;
        };
        if lease.active_flows != 0 || lease.expires_at_ns != expires_at_ns {
            return false;
        }
        // The lease still exists and is idle: its occupancy bit is still set
        // (no other allocation could have claimed it while the lease held it —
        // the bit is the ownership token). Remove the lease and record its port
        // so the caller frees it (recycle). Because the bit stays set until that
        // free, a concurrent claim cannot re-hand-out the port even after the
        // lease is gone from the map.
        live.persistent_by_source.remove(&key);
        // #6041: an address-only persistent lease holds no pool port bit — its
        // reverse-identity tokens were cleared per flow on release — so there is
        // nothing to free on the occupancy bitmap. A PAT lease records its port.
        if !lease.address_only {
            freed.push((lease.addr_index, lease.translated.port));
        }
        true
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
    /// #4800: `live` map-mutex acquisitions on the production
    /// allocate/reserve/release/rollback/GC paths, and the subset that
    /// blocked. Read as a ratio: `contended / acquisitions` is the NAT
    /// allocator's share of new-flow-install serialization, and the pair
    /// is what lets a connection-rate run say "the residual Phase-1
    /// (#2852) mutex saturated" instead of guessing from a flat
    /// allocations/sec curve. See `PortAllocator::lock_live`.
    pub(crate) live_lock_acquisitions_total: u64,
    pub(crate) live_lock_contended_total: u64,
}

pub(crate) fn allocator_capacity(num_addresses: usize, port_low: u16, port_high: u16) -> usize {
    if num_addresses == 0 || port_low == 0 || port_high == 0 || port_low > port_high {
        return 0;
    }
    let ports = (u64::from(port_high) - u64::from(port_low)) + 1;
    ports
        .saturating_mul(num_addresses as u64)
        .min(usize::MAX as u64) as usize
}

/// Map a source IP to a sticky pool-address slot for `address-persistent`
/// SNAT.
///
/// This is a load-distribution hash, not a security primitive: it only needs
/// to be deterministic (same source IP → same slot for a given pool size),
/// well-distributed across the pool, and cheap. It runs on the SNAT
/// *allocation* path (first flow for an address-persistent source), so under
/// connection churn a crypto hash is wasted work. We use a seeded FxHash
/// (`rustc_hash`, already a dependency for the allocator's hash maps) instead
/// of SHA-256 (#2349).
///
/// Stability scope: the mapping is computed live and is never persisted to
/// disk or synced across HA — `persistent_by_source` is an in-memory map — so
/// the only contract is same-source→same-slot within a process lifetime, and
/// identical results across nodes running the same binary. The `-v2` seed is a
/// hash-quality salt, not a cross-restart stability guarantee. Swapping the
/// hash (SHA-256 → FxHash) changes which pool address a given source lands on;
/// that is safe because existing sessions keep their already-allocated address
/// and only new flows pick up the new mapping.
pub(super) fn sticky_pool_index(src_ip: IpAddr, pool_len: usize) -> usize {
    if pool_len <= 1 {
        return 0;
    }

    let mut hasher = rustc_hash::FxHasher::default();
    // Seed with a fixed salt so the distribution does not key purely on the
    // raw IP bytes (FxHash of a small contiguous run can correlate adjacent
    // addresses).
    hasher.write(b"xpf-userspace-snat-address-persistent-v2");
    match src_ip {
        IpAddr::V4(addr) => {
            hasher.write_u8(4);
            hasher.write(&addr.octets());
        }
        IpAddr::V6(addr) => {
            hasher.write_u8(6);
            hasher.write(&addr.octets());
        }
    }
    (hasher.finish() % pool_len as u64) as usize
}
