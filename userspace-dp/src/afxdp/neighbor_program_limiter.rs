//! #5288: bounded, per-worker rate limiter for kernel neighbor-table
//! programming on the data-path ARP/NDP learn.
//!
//! ## Why
//! `stage_link_layer_classify` learns a dynamic neighbor from every accepted
//! ARP reply / NDP Neighbor Advertisement and then calls
//! [`super::neighbor::add_kernel_neighbor`], which — per accepted advert —
//! allocates request + IP `Vec`s, opens a raw `AF_NETLINK` socket, `sendto`s
//! an `RTM_NEWNEIGH`, and closes the socket synchronously ON THE XSK WORKER.
//! Before this limiter the call fired UNCONDITIONALLY, even for a same-key /
//! same-MAC repeat whose `insert_if_changed` result was discarded. An attacker
//! streaming valid ARP replies / NAs for a non-owned unicast IP therefore drove
//! a `socket()`/`sendto()`/`close()` + allocations per frame — forwarding
//! starvation on the affected queues (a DoS amplification).
//!
//! ## What this bounds
//! A fixed-size, SET-ASSOCIATIVE table of [`KERNEL_NEIGH_LIMITER_BUCKETS`]
//! buckets, each holding [`KERNEL_NEIGH_LIMITER_WAYS`] ways
//! ([`KERNEL_NEIGH_LIMITER_SLOTS`] slots total). Each way records the last
//! `(key -> mac)` this worker actually programmed and WHEN. The decision
//! ([`KernelNeighborProgramLimiter::should_program`]) is a pure function of the
//! bucket + the advert, with no allocation and no syscall, so it is
//! unit-testable in isolation (the syscall stays in `add_kernel_neighbor`).
//!
//! * **Same-key/same-MAC repeat** → skipped. The owning way already records the
//!   exact binding, and/or the authoritative userspace neighbor map was
//!   unchanged by this advert (`map_changed == false`), which proves the kernel
//!   was already told. This is the primary amplification fix.
//! * **Changed-flood (MAC cycling on one IP)** → those adverts all map to the
//!   SAME key's way, which drives at most one kernel program per
//!   [`KERNEL_NEIGH_MIN_INTERVAL_NS`].
//! * **Many-distinct-IP flood** → because the table is FIXED size, the
//!   AGGREGATE per-worker netlink rate is bounded to
//!   `≤ SLOTS / MIN_INTERVAL` programs regardless of how many distinct source
//!   IPs an attacker cycles: each way programs at most once per interval, and a
//!   colliding genuine change never evicts a way that is still within its
//!   interval (see below), so the fixed way count is the hard cap.
//!
//! ## Not losing a real change — even under a colliding-key flood (#6129)
//! A genuine MAC change (`map_changed == true`) is guaranteed to reach the
//! kernel within a bounded number of ticks:
//! * **Key owns a way** → the change is programmed immediately unless it is
//!   inside one interval of that way's last program, in which case the way
//!   keeps the OLD mac so the binding stays "owed" and is retried on the next
//!   advert once the interval elapses — even a same-MAC advert the userspace
//!   map already absorbed (`map_changed == false`). Steady-state re-adverts
//!   return early WITHOUT touching the timestamp, so a real change after a
//!   quiet period programs on its first advert.
//! * **Key owns NO way (the #6129 collision case)** → a foreign key occupying
//!   this key's bucket can no longer starve it. Instead of contending for a
//!   single direct-mapped slot, the genuine change CLAIMS a way in the bucket:
//!   a never-fired way if one is free, else the least-recently-programmed way.
//!   It then OWNS that way and is owed-tracked thereafter. A single colliding
//!   key A therefore cannot keep victim B out — B lands in a different way and
//!   programs. Up to `WAYS - 1` distinct foreign keys may be simultaneously hot
//!   in a bucket before a genuine victim change can be delayed, and even then
//!   only until one of those ways ages past its interval.
//!
//! The claim step still honors the rate cap on the way it evicts (a way within
//! its interval is NOT evicted), so the aggregate netlink rate stays bounded to
//! `≤ SLOTS / MIN_INTERVAL` — the #5288 property is preserved: an adversarial
//! flood of repeated/colliding adverts with no genuine change still programs
//! O(1), and a distinct-genuine-change flood is still capped by the fixed way
//! count, not O(adverts). Any residual kernel-table lag self-heals via
//! `NUD_STALE` + on-demand kernel ARP on the host path.
//!
//! ## Placement
//! Per-worker, owned by [`super::worker::BindingWorker`] and touched ONLY by the
//! owning worker thread (the ARP/NDP learn runs on the XSK poll loop), so no
//! `Arc`/`Mutex`/cross-core sync — consistent with the per-queue AF_XDP model
//! and the sibling `pending_neigh` / `neg_neigh_cache` per-worker structures.
//! Neighbor programming is a LOCAL kernel-table operation; it is NOT HA /
//! session-sync state, so a per-worker limiter needs no peer coordination.
//!
//! Persistent-socket + off-worker coalescing of the netlink send itself is a
//! deferred follow-up (out of scope for #5288); this limiter only ensures a
//! repeat/flood no longer does unbounded socket work on the XSK worker.

use crate::hot_hash_seed::HotPathSeededState;
use std::hash::BuildHasher;
use std::net::IpAddr;

/// Number of buckets. Power of two so the bucket index is a single mask.
/// 64 buckets × [`KERNEL_NEIGH_LIMITER_WAYS`] ways is far more than the distinct
/// next-hops a worker legitimately programs, so collisions between live
/// neighbors are rare, while the fixed slot count caps the aggregate netlink
/// rate under a many-IP flood.
pub(in crate::afxdp) const KERNEL_NEIGH_LIMITER_BUCKETS: usize = 64;
const _: () = assert!(KERNEL_NEIGH_LIMITER_BUCKETS.is_power_of_two());

/// Ways per bucket (set associativity). ≥ 2 so a single colliding key cannot
/// occupy every way and starve a genuine victim change (#6129): the victim
/// claims a different way. Kept small so the total table (and the aggregate
/// netlink cap) stays bounded.
pub(in crate::afxdp) const KERNEL_NEIGH_LIMITER_WAYS: usize = 4;
const _: () = assert!(KERNEL_NEIGH_LIMITER_WAYS >= 2);

/// Total slots = buckets × ways. This is the hard cap on the aggregate
/// per-worker netlink program rate per [`KERNEL_NEIGH_MIN_INTERVAL_NS`]
/// (each way programs at most once per interval).
pub(in crate::afxdp) const KERNEL_NEIGH_LIMITER_SLOTS: usize =
    KERNEL_NEIGH_LIMITER_BUCKETS * KERNEL_NEIGH_LIMITER_WAYS;

/// Minimum interval between two kernel-neighbor programs a single slot may
/// drive. 50 ms is far longer than any legitimate neighbor re-advertisement
/// cadence yet short enough that a genuine MAC change is reflected within one
/// interval even in the (flood-only) rate-limited-then-retried case.
pub(in crate::afxdp) const KERNEL_NEIGH_MIN_INTERVAL_NS: u64 = 50_000_000; // 50 ms

/// One direct-mapped slot: the last binding this worker programmed for the
/// key that currently owns the slot, and when.
#[derive(Clone, Copy)]
struct Slot {
    /// `None` only for a never-fired slot (fresh worker). Once a slot programs
    /// anything it holds `Some(key)` for the rest of the worker's life.
    key: Option<(i32, IpAddr)>,
    /// The MAC last programmed for `key`. Meaningless when `key` is `None`.
    mac: [u8; 6],
    /// Monotonic-nanos timestamp of the last ACTUAL program driven by this slot.
    last_program_ns: u64,
}

impl Default for Slot {
    fn default() -> Self {
        Self {
            key: None,
            mac: [0u8; 6],
            last_program_ns: 0,
        }
    }
}

/// One set-associative bucket: [`KERNEL_NEIGH_LIMITER_WAYS`] independent ways.
type Bucket = [Slot; KERNEL_NEIGH_LIMITER_WAYS];

fn bucket_index_with(key: &(i32, IpAddr), state: HotPathSeededState) -> usize {
    (state.hash_one(key) as usize) & (KERNEL_NEIGH_LIMITER_BUCKETS - 1)
}

/// Pick the way a genuine change should CLAIM when no way in `bucket` owns its
/// key: a never-fired (free) way if one exists, else the way with the oldest
/// `last_program_ns` (LRU). Returns the way index. The rate cap is applied by
/// the caller to the chosen way, so a way still within its interval is never
/// evicted — that is what keeps the aggregate netlink rate bounded (#5288).
fn choose_victim_way(bucket: &Bucket) -> usize {
    let mut victim = 0usize;
    for i in 0..KERNEL_NEIGH_LIMITER_WAYS {
        if bucket[i].key.is_none() {
            return i; // free way — claim it, no eviction
        }
        if bucket[i].last_program_ns < bucket[victim].last_program_ns {
            victim = i;
        }
    }
    victim
}

/// Per-worker gate for `add_kernel_neighbor`. See the module docs.
pub(in crate::afxdp) struct KernelNeighborProgramLimiter {
    /// Boxed so the table lives on the heap (allocated once at worker
    /// construction, never on the packet path) instead of inline in the large
    /// `BindingWorker`.
    buckets: Box<[Bucket; KERNEL_NEIGH_LIMITER_BUCKETS]>,
    min_interval_ns: u64,
    hash_state: HotPathSeededState,
}

impl KernelNeighborProgramLimiter {
    pub(in crate::afxdp) fn new() -> Self {
        Self::with_interval(KERNEL_NEIGH_MIN_INTERVAL_NS)
    }

    fn with_interval(min_interval_ns: u64) -> Self {
        Self::with_seed(min_interval_ns, crate::hot_hash_seed::hot_path_hash_seed())
    }

    fn with_seed(min_interval_ns: u64, seed: u64) -> Self {
        Self {
            buckets: Box::new(
                [[Slot::default(); KERNEL_NEIGH_LIMITER_WAYS]; KERNEL_NEIGH_LIMITER_BUCKETS],
            ),
            min_interval_ns,
            hash_state: HotPathSeededState::new(seed),
        }
    }

    /// Decide whether a data-path ARP/NDP learn of `(key -> mac)` should
    /// program the kernel neighbor table now, recording the decision.
    ///
    /// `map_changed` is the `ShardedNeighborMap::insert_if_changed` result for
    /// this advert: `false` means the authoritative userspace neighbor map
    /// already held this exact `(key -> mac)`, so the kernel was already told
    /// (by us or by the neigh monitor). `now_ns` is a CLOCK_MONOTONIC nanos
    /// stamp.
    ///
    /// Returns `true` at most once per key per [`Self::min_interval_ns`] for a
    /// changed binding, and never for a proven-present repeat. See the module
    /// docs for the "not losing a real change" argument.
    pub(in crate::afxdp) fn should_program(
        &mut self,
        key: (i32, IpAddr),
        mac: [u8; 6],
        map_changed: bool,
        now_ns: u64,
    ) -> bool {
        let min_interval_ns = self.min_interval_ns;
        let bucket = &mut self.buckets[bucket_index_with(&key, self.hash_state)];

        // Fast path: a way in this bucket already OWNS this key. Apply the
        // unchanged #5288 per-key decision on that way.
        if let Some(pos) = bucket.iter().position(|s| s.key == Some(key)) {
            let slot = &mut bucket[pos];
            // The way owns `key`, so "exact present" reduces to the mac
            // matching, and `owes_other` (owning the key with a DIFFERENT,
            // stale mac we have not yet pushed) to the mac differing. A change
            // we owe must never be skipped, or the latest desired state is lost.
            let owes_other = slot.mac != mac;
            // Skip when the kernel already holds this exact binding and we owe
            // nothing newer. `!map_changed` (userspace map unchanged by this
            // advert) is the other proof the kernel was already told.
            if !owes_other && (slot.mac == mac || !map_changed) {
                return false;
            }
            // Rate cap: at most one program per interval per way — bounds a
            // per-key MAC-cycling flood. A rate-limited change leaves the OLD
            // mac in place, so the owed binding is retried on a later advert.
            if now_ns.saturating_sub(slot.last_program_ns) < min_interval_ns {
                return false;
            }
            slot.mac = mac;
            slot.last_program_ns = now_ns;
            return true;
        }

        // No way owns this key. If the userspace map was UNCHANGED by this
        // advert, the kernel already holds the binding (told before — possibly
        // via a way since evicted by a colliding key, or by the neigh monitor).
        // Skip; no netlink needed.
        if !map_changed {
            return false;
        }

        // A GENUINE change whose key owns no way — either a brand-new neighbor
        // or (the #6129 case) this key's way was stolen by a colliding key.
        // CLAIM a way so the change is APPLIED now and owed-tracked thereafter,
        // instead of being starved by whichever foreign key holds the bucket.
        // Prefer a never-fired way; else evict the least-recently-programmed
        // way — but honor the rate cap on that way, so a way still inside its
        // interval is NOT evicted. That keeps the aggregate per-worker netlink
        // rate bounded to `≤ SLOTS / MIN_INTERVAL` (the #5288 invariant): a
        // distinct-key flood cannot drive more than one program per way per
        // interval, and a never-fired way is exempt so its zero timestamp does
        // not gate the first real program.
        let victim = choose_victim_way(bucket);
        let slot = &mut bucket[victim];
        if slot.key.is_some() && now_ns.saturating_sub(slot.last_program_ns) < min_interval_ns {
            // Every way in the bucket was programmed within the interval — the
            // aggregate cap is doing its job. Drop this tick (bounded); the
            // genuine change is retried on a later advert once a way ages out.
            return false;
        }
        slot.key = Some(key);
        slot.mac = mac;
        slot.last_program_ns = now_ns;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const MIN: u64 = KERNEL_NEIGH_MIN_INTERVAL_NS;
    // A realistic monotonic-nanos base (well past one interval) so the
    // never-fired exemption is not the thing under test.
    const T0: u64 = 1_000 * KERNEL_NEIGH_MIN_INTERVAL_NS;

    fn v4(last: u8) -> (i32, IpAddr) {
        (11, IpAddr::V4(Ipv4Addr::new(172, 16, 80, last)))
    }
    fn mac(tag: u8) -> [u8; 6] {
        [0x02, 0, 0, 0, 0, tag]
    }

    /// Drive N adverts of the SAME (key, mac) through the limiter exactly as
    /// `stage_link_layer_classify` would: the first advert reports
    /// `map_changed == true` (first insert), every repeat reports
    /// `map_changed == false` (the userspace map already held the binding).
    /// Returns how many times the kernel-program decision fired.
    fn program_count_for_identical_repeats(n: usize) -> usize {
        let mut lim = KernelNeighborProgramLimiter::new();
        let key = v4(9);
        let m = mac(0x09);
        let mut fired = 0usize;
        for i in 0..n {
            let map_changed = i == 0;
            // Same tick — repeats stream in far faster than MIN.
            if lim.should_program(key, m, map_changed, T0 + i as u64) {
                fired += 1;
            }
        }
        fired
    }

    /// #5288 FAIL-ON-REVERT. A same-key/same-MAC repeat flood must drive the
    /// kernel-program decision exactly ONCE across N identical accepted
    /// adverts — NOT once per advert. Reverting the gate in `should_program`
    /// (so it programs on every call) makes this count `N`, failing the
    /// `assert_eq!(.., 1)` RED. This is the DoS amplification the fix removes.
    #[test]
    fn identical_repeat_flood_programs_once_5288() {
        for n in [1usize, 2, 8, 64, 1000] {
            let fired = program_count_for_identical_repeats(n);
            assert_eq!(
                fired, 1,
                "a flood of {n} identical accepted adverts must program the \
                 kernel neighbor ONCE (#5288), not {n} times — the discarded \
                 insert_if_changed repeat was the amplification"
            );
        }
    }

    /// A MAC-cycling flood on ONE IP (attacker rotating the advertised MAC to
    /// defeat the same-MAC gate) is capped by the per-slot rate limit: at most
    /// one program per interval, regardless of how many distinct MACs stream in
    /// within that interval.
    #[test]
    fn mac_cycling_flood_on_one_ip_is_rate_capped_5288() {
        let mut lim = KernelNeighborProgramLimiter::new();
        let key = v4(9);
        let mut fired = 0usize;
        // 500 adverts within one interval, each a DIFFERENT mac (every one is a
        // genuine map change).
        for i in 0..500u64 {
            let m = [0x02, 0, 0, 0, (i >> 8) as u8, i as u8];
            if lim.should_program(key, m, true, T0 + i) {
                fired += 1;
            }
        }
        assert_eq!(
            fired, 1,
            "a MAC-cycling flood on one IP within a single interval must be \
             capped to one kernel program (#5288)"
        );
    }

    /// The aggregate per-worker netlink rate under a many-distinct-IP flood is
    /// bounded by the fixed slot count: within one interval, no more than
    /// SLOTS programs fire even for far more distinct IPs.
    #[test]
    fn many_ip_flood_bounded_by_slot_count_5288() {
        let mut lim = KernelNeighborProgramLimiter::new();
        let mut fired = 0usize;
        // 4096 distinct /16 hosts, one advert each, all within one interval.
        for i in 0..4096u32 {
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, (i >> 8) as u8, i as u8));
            if lim.should_program((11, ip), mac(0x11), true, T0 + i as u64) {
                fired += 1;
            }
        }
        assert!(
            fired <= KERNEL_NEIGH_LIMITER_SLOTS,
            "aggregate programs within one interval ({fired}) must be bounded \
             by the fixed slot count ({KERNEL_NEIGH_LIMITER_SLOTS}) (#5288)"
        );
    }

    /// A genuine MAC change after a steady-state period longer than one
    /// interval is programmed IMMEDIATELY — it is never rate-limited, because
    /// steady-state same-binding re-adverts do not touch the slot timestamp
    /// (they return early via the exact-repeat gate). This is the "don't drop
    /// legitimate updates" guarantee: only the last ACTUAL program gates the
    /// rate, and in real deployments a neighbor sits stable for far longer than
    /// one interval between MAC changes.
    #[test]
    fn genuine_change_after_steady_state_programs_immediately() {
        let mut lim = KernelNeighborProgramLimiter::new();
        let key = v4(5);
        // Learn MAC A at T0 (the last ACTUAL program).
        assert!(lim.should_program(key, mac(0xAA), true, T0));
        // A run of same-binding re-adverts spread over well more than one
        // interval (1 ms apart, ~2×MIN total) — all skipped, none touch the
        // slot timestamp.
        let step = 1_000_000u64; // 1 ms
        let count = (2 * MIN / step) + 10;
        for i in 1..=count {
            assert!(!lim.should_program(key, mac(0xAA), false, T0 + i * step));
        }
        // A real failover to MAC B, one interval past the LAST re-advert but
        // ~2×MIN past the last PROGRAM (at T0) — must program now.
        let change_at = T0 + (count + 1) * step;
        assert!(
            change_at.saturating_sub(T0) >= MIN,
            "test setup: change must land more than one interval past the \
             last program"
        );
        assert!(
            lim.should_program(key, mac(0xBB), true, change_at),
            "a genuine MAC change must program immediately; steady-state \
             re-adverts must not have consumed the rate budget"
        );
    }

    /// A change that IS rate-limited (only possible amid a flood) is not lost:
    /// the owed binding is retried on the next advert once the interval
    /// elapses, EVEN when that advert reports `map_changed == false` (the
    /// userspace map already absorbed the new MAC).
    #[test]
    fn rate_limited_change_is_retried_not_lost() {
        let mut lim = KernelNeighborProgramLimiter::new();
        let key = v4(7);
        // Program MAC A at T0 (consumes the slot's rate budget).
        assert!(lim.should_program(key, mac(0xAA), true, T0));
        // A change to MAC B arrives within the interval → rate-limited (skip),
        // but the userspace map moved to B (`map_changed == true`).
        assert!(!lim.should_program(key, mac(0xBB), true, T0 + 1));
        // Subsequent B re-adverts within the interval report the map as
        // unchanged — still skipped, but the binding stays owed.
        assert!(!lim.should_program(key, mac(0xBB), false, T0 + 2));
        // Once the interval elapses, the owed B is programmed even though the
        // map is unchanged — the latest desired state is retried, not dropped.
        assert!(
            lim.should_program(key, mac(0xBB), false, T0 + MIN),
            "a rate-limited genuine change must be retried after the interval, \
             not silently lost (#5288 no-loss guarantee)"
        );
    }

    /// After programming, a periodic refresh of the SAME binding fires again
    /// only once the interval has elapsed (bounded refresh), and same-binding
    /// adverts in between are free (no netlink, no rate consumption).
    #[test]
    fn same_binding_refresh_is_bounded() {
        let mut lim = KernelNeighborProgramLimiter::new();
        let key = v4(3);
        let m = mac(0x33);
        assert!(lim.should_program(key, m, true, T0));
        // In-interval repeats: skipped.
        assert!(!lim.should_program(key, m, false, T0 + 1));
        assert!(!lim.should_program(key, m, false, T0 + MIN - 1));
        // A same-MAC advert after the interval whose map read is UNCHANGED is
        // still an exact repeat the kernel already holds — skipped (the
        // `map_changed == false` proof), so a slow trickle of gratuitous ARPs
        // never re-programs.
        assert!(!lim.should_program(key, m, false, T0 + MIN));
    }

    /// IPv6 (NDP NA) keys work the same way.
    #[test]
    fn ipv6_repeat_flood_programs_once() {
        let mut lim = KernelNeighborProgramLimiter::new();
        let key = (24, IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x42)));
        let m = mac(0x42);
        assert!(lim.should_program(key, m, true, T0));
        for i in 1..64u64 {
            assert!(!lim.should_program(key, m, false, T0 + i));
        }
    }

    /// Raw keyed hash of a key (same keying scheme the limiter indexes with).
    fn full_hash(key: &(i32, IpAddr)) -> u64 {
        HotPathSeededState::new(crate::hot_hash_seed::hot_path_hash_seed()).hash_one(key)
    }

    /// Two distinct keys whose keyed hash agrees in the low 8 bits. Such a pair
    /// collides in the limiter's bucket placement, reproducing the contention.
    fn find_colliding_keys() -> ((i32, IpAddr), (i32, IpAddr)) {
        let base = v4(1);
        let base_slot = full_hash(&base) & 0xff;
        for c in 0..=255u8 {
            for last in 0..=255u8 {
                let cand = (11, IpAddr::V4(Ipv4Addr::new(172, 16, c, last)));
                if cand != base && full_hash(&cand) & 0xff == base_slot {
                    return (base, cand);
                }
            }
        }
        panic!("no colliding key pair found in the searched space");
    }

    /// #6129 FAIL-ON-REVERT. Under a SUSTAINED colliding-key flood — a foreign
    /// key A repeatedly occupying victim B's bucket and keeping a way warm — a
    /// GENUINE neighbor change for B must still be programmed to the kernel
    /// within a bounded number of ticks, NOT starved.
    ///
    /// Pre-fix, the direct-mapped table shares ONE slot per bucket: A owns it,
    /// B's genuine change is rate-limited and — owning no slot — is never
    /// owed-retried, so B's later `map_changed == false` re-adverts are skipped
    /// forever (`b_fired == 0`). The set-associative fix lands B in a DIFFERENT
    /// way, so B programs (`b_fired >= 1`). Reverting the fix makes the
    /// `b_fired >= 1` assertion RED.
    #[test]
    fn colliding_key_flood_does_not_starve_victim_genuine_change_6129() {
        let (a, b) = find_colliding_keys();
        assert_ne!(a, b, "test setup: A and B must be distinct keys");

        let mut lim = KernelNeighborProgramLimiter::new();
        let b_mac = mac(0xBB);
        let mut a_fired = 0usize;
        let mut b_fired = 0usize;

        // Sustained flood over many intervals. Each interval the flood key A
        // performs a GENUINE mac change (`map_changed == true`) at the START of
        // the interval, so it programs and refreshes its way's timestamp — the
        // "keep the slot warm" behavior that starves B in the direct-mapped
        // design. Immediately after (worst case for the rate cap) B's genuine
        // change arrives: `map_changed == true` once, then `map_changed ==
        // false` repeats because the userspace neighbor map already absorbed
        // B's new mac. In the reverted code every B advert is skipped.
        for iv in 0..16u64 {
            let t = T0 + iv * MIN;
            let a_mac = [0x02, 0xAA, 0, 0, (iv >> 8) as u8, iv as u8];
            if lim.should_program(a, a_mac, true, t) {
                a_fired += 1;
            }
            if lim.should_program(b, b_mac, true, t + 1) {
                b_fired += 1;
            }
            if lim.should_program(b, b_mac, false, t + 2) {
                b_fired += 1;
            }
            if lim.should_program(b, b_mac, false, t + 3) {
                b_fired += 1;
            }
        }

        assert!(
            a_fired >= 1,
            "sanity: the flood key A must program at least once"
        );
        assert!(
            b_fired >= 1,
            "victim B's genuine neighbor change must reach the kernel under a \
             colliding-key flood within bounded ticks (#6129); the pre-fix \
             direct-mapped table starves it (b_fired == 0)"
        );
    }

    /// #6129 companion — the fix must NOT reopen the #5288 DoS. A flood of
    /// colliding keys with NO genuine change (every advert `map_changed ==
    /// false` after each key's first learn) must still program O(1) per key,
    /// not O(adverts): the aggregate stays bounded by the fixed slot count even
    /// though many distinct keys hammer the same bucket.
    #[test]
    fn colliding_no_change_flood_stays_bounded_6129() {
        let mut lim = KernelNeighborProgramLimiter::new();
        // Reuse the low-8-bit collision search to pack many keys into one
        // bucket, then flood each with repeated no-change adverts.
        let base = v4(1);
        let base_slot = full_hash(&base) & 0xff;
        let mut colliding = Vec::new();
        'outer: for c in 0..=255u8 {
            for last in 0..=255u8 {
                let cand = (11, IpAddr::V4(Ipv4Addr::new(172, 16, c, last)));
                if full_hash(&cand) & 0xff == base_slot {
                    colliding.push(cand);
                    if colliding.len() == 32 {
                        break 'outer;
                    }
                }
            }
        }
        assert!(
            colliding.len() >= 8,
            "need several colliding keys to exercise the bucket"
        );

        let mut fired = 0usize;
        // First learn per key (genuine), then a long no-change repeat flood all
        // within one interval. The repeats must never program.
        for (i, &k) in colliding.iter().enumerate() {
            let m = mac(i as u8);
            if lim.should_program(k, m, true, T0 + i as u64) {
                fired += 1;
            }
            for r in 0..200u64 {
                if lim.should_program(k, m, false, T0 + i as u64 + r) {
                    fired += 1;
                }
            }
        }
        assert!(
            fired <= colliding.len(),
            "a no-genuine-change colliding flood must program at most once per \
             key ({} keys), got {fired} — #5288 bound preserved",
            colliding.len()
        );
    }

    #[test]
    fn keyed_siphash_spreads_neighbor_limiter_buckets_12778() {
        let placement = |seed| {
            (0..256u16)
                .map(|i| {
                    bucket_index_with(
                        &(
                            24,
                            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, i, 0, 0, 0, 1)),
                        ),
                        HotPathSeededState::new(seed),
                    )
                })
                .collect::<Vec<_>>()
        };
        for seed in [1, 42, 0x0123_4567_89ab_cdef, u64::MAX] {
            let buckets = placement(seed);
            let distinct: std::collections::HashSet<_> = buckets.iter().copied().collect();
            assert!(
                distinct.len() > 32,
                "seed {seed:#x} spread to only {} buckets",
                distinct.len()
            );
        }
        assert_ne!(
            placement(42),
            placement(43),
            "seed must change bucket layout"
        );
    }
}
