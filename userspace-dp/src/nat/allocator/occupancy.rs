//! #16135: per-address lock-free port occupancy, split out of
//! nat/allocator.rs at b0ff071c29 (2026-10-22) as pure code motion
//! (deterministic -> occupancy, per the issue order). This module
//! owns the atomic bitmap, the monotonic keyed fresh-port probe
//! (#16011) and the FIFO recycle ring; it holds NO live-state
//! (flow map / persistent leases) and never touches the global allocator
//! mutex — the only mutex here is the per-address recycle mutex, which
//! stays innermost (allocator.rs header: global -> recycle lock order).
//! No atomic ordering, lock order or FIFO behaviour changed in that move.
//!
//! Visibility bill for this move (25 widenings, all
//! private -> pub(in crate::nat::allocator)): the absolute spelling
//! names exactly the pre-split visibility. A private item in the old
//! allocator.rs was visible to that whole file (now allocator/mod.rs
//! plus its children). Plain pub(super) in this file would mean
//! pub(in crate::nat::allocator) — pub(super) always names the
//! parent module, and this file's parent is crate::nat::allocator —
//! which is the same visibility, so it would NOT narrow here; the
//! explicit pub(in crate::nat::allocator) spelling is used anyway
//! so the intended scope is self-documenting and stays correct if
//! this file is ever moved deeper (where pub(super) WOULD then
//! silently narrow to the new parent — the nat/mod.rs:28-33 trap
//! #6988 paid for). AddressOccupancy and RecycleRing get the same
//! spelling, so nothing outside nat::allocator can name them:
//!   AddressOccupancy (struct); RecycleRing (struct)
//!   AddressOccupancy::new, offset_of, port_of, is_occupied, claim,
//!     free_recycle, free_no_recycle, reserve, claim_in_block,
//!     occupied_count
//!   AddressOccupancy fields: words, recycle, occupied,
//!     recycle_scan_pops, recycle_scan_walks, port_low, range
//!   RecycleRing::new, RecycleRing::push, RecycleRing::queue (field)
//! #[cfg(test)]-only, same spelling:
//!   AddressOccupancy::probe_word_loads, probe_claim_rmws (fields)
//! Everything else (claim_offset, free_offset, RecycleRing::is_queued /
//! mark / unmark, all FIFO/atomic internals) stays fully private to
//! this file. The motion was verified at the split commit by
//! scripts/verify-nat-allocator-split-16135.py (pinned --base/--split
//! refs; it checks that commit, not the current tree). This file has
//! since been edited (#16011, #16035), so the verbatim claim now
//! covers only the split commit.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// #16011: per-boot PAT secret for RFC 6056 randomized port selection.
/// Drawn once per process via the audited OS-entropy path
/// (`hot_hash_seed::os_random_seed_u64`, never zero); stable for the
/// process lifetime so concurrent workers share one mapping. Node-local
/// only: never synced, never on the wire. HA peers draw independently —
/// synced sessions carry their explicit translated tuple, so a peer
/// never needs to reproduce another node's fresh-port choice.
static PAT_SECRET: std::sync::LazyLock<u64> =
    std::sync::LazyLock::new(crate::hot_hash_seed::os_random_seed_u64);

pub(in crate::nat::allocator) fn pat_secret() -> u64 {
    *PAT_SECRET
}

/// splitmix64 finalizer (same shape as `hot_hash_seed`): full avalanche
/// so every key/secret bit can move the selected offset.
#[inline]
pub(in crate::nat) fn pat_mix(mut x: u64) -> u64 {
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// RFC 6056 Algorithm 3/5 keyed offset: hash the flow tuple under the
/// per-boot secret, reduced modulo `range`. An observer who sees one
/// translated port learns nothing about the next flow's port without
/// the secret. `range == 0` yields 0 (callers guard range first).
#[inline]
/// FOLD (#16350 fold-2): probe-advance mixer. Attempt `n` folds into
/// the claim key so a rejection/exclusion advances to an unrelated
/// keyed start instead of retrying the same port. Attempt 0 is the
/// identity (callers XOR with 0-equivalent? see note) — callers pass
/// `attempt` and this returns the XOR delta; attempt 0 returns 0.
#[inline]
pub(in crate::nat::allocator) fn occupancy_next_probe(attempt: u64) -> u64 {
    if attempt == 0 { 0 } else { pat_mix(attempt.wrapping_mul(0x9e37_79b9_7f4a_7c15)) }
}

#[inline]
pub(in crate::nat) fn pat_keyed_offset(secret: u64, key: u64, range: u32) -> u32 {
    if range == 0 {
        return 0;
    }
    (pat_mix(secret ^ pat_mix(key ^ 0x1601_1601_1601_1601)) % u64::from(range)) as u32
}

/// #16035: minimum reuse delay for freed PAT ports on SMALL ranges.
///
/// A freed port's bit clears immediately, but on a small range its
/// recycle token is not claimable until this long after the free. A
/// delayed UDP reply for the old flow reusing (translated_ip, port,
/// remote) during the window therefore cannot land on a new owner of
/// the same port, because no new owner exists yet. TCP needs no such
/// delay (the endpoint validates ISN/seq), and neither do large pools:
/// their FIFO is drained only after the whole fresh range is spent, so
/// oldest-first reuse already exceeds any plausible segment lifetime.
/// The delay applies ONLY below [`SMALL_POOL_QUARANTINE_MAX_RANGE`],
/// formalizing for tiny / high-churn pools the de-facto quarantine
/// large pools already have — not a blanket 2MSL tax on every pool.
///
/// 60 s matches the default UDP session timeout: a reply delayed
/// longer than the session that produced it would be dropped as
/// sessionless anyway, so quarantining beyond it buys nothing.
pub(in crate::nat::allocator) const PAT_PORT_QUARANTINE_NS: u64 = 60_000_000_000;
/// #16035: ranges at or below this size get the quarantine. Above it,
/// FIFO-after-fresh-range reuse is already slower than the quarantine
/// at any churn rate the pool can sustain without exhausting.
pub(in crate::nat::allocator) const SMALL_POOL_QUARANTINE_MAX_RANGE: u32 = 256;

/// #7174 (M13): the FIFO recycle ring plus a per-offset "already queued" bitset,
/// held together under ONE mutex so a port can hold AT MOST ONE token.
///
/// Without the bitset the queue grows without bound across HA role churn, and
/// the growth is NOT the mechanism M13's title names. The retain policy
/// (`claim` re-queues a token whose bit was set at pop time, 062-10) is what
/// creates the duplicate: the port is occupied, so its token goes back; when the
/// occupant later releases through `free_recycle` the `1 -> 0` transition pushes
/// a SECOND token for the same port. Repeat per churn cycle and the queue
/// exceeds the address's whole port `range` — unbounded memory, and every
/// duplicate is one more pop the recycled phase has to walk.
///
/// With the bitset the queue length is bounded by `range` structurally: a push
/// for an already-queued offset is dropped, and the token that IS queued is
/// equally good (the FIFO holds ports, not identities).
#[derive(Debug)]
pub(in crate::nat::allocator) struct RecycleRing {
    /// FIFO tokens: `(port, freed_at_ns)`. `freed_at_ns` is the
    /// caller-supplied monotonic time of the free that queued the
    /// token (0 for tokens injected without a clock — test seams; the
    /// collision-retain re-queue preserves the ORIGINAL free time so a
    /// retained token does not restart its #16035 quarantine).
    pub(in crate::nat::allocator) queue: VecDeque<(u16, u64)>,
    /// One bit per in-range offset: set iff a token for that offset is in
    /// `queue`. Sized like `AddressOccupancy::words`, but allocated LAZILY on
    /// the first push: a pool may declare up to `MAX_POOL_PREFIX_HOSTS`
    /// addresses and every one of them already carries a `words` bitmap, so
    /// sizing this one eagerly would double a per-ADDRESS allocation for every
    /// address in the pool — including the ones that never recycle a port.
    /// Empty means "nothing has ever been queued here", which is exactly when
    /// no dedup state is needed.
    queued: Vec<u64>,
    /// `queued`'s length once allocated, kept because `push` is the only place
    /// that can allocate it and it has no other route to `range`.
    nwords: usize,
}

impl RecycleRing {
    pub(in crate::nat::allocator) fn new(range: u32) -> Self {
        Self {
            queue: VecDeque::new(),
            queued: Vec::new(),
            nwords: (range as usize).div_ceil(64),
        }
    }

    #[inline]
    fn is_queued(&self, offset: u32) -> bool {
        let w = (offset / 64) as usize;
        match self.queued.get(w) {
            Some(word) => word & (1u64 << (offset % 64)) != 0,
            // Not yet allocated: nothing has ever been queued, so nothing is.
            None => false,
        }
    }

    #[inline]
    fn mark(&mut self, offset: u32) {
        if self.queued.is_empty() {
            self.queued = vec![0u64; self.nwords];
        }
        let w = (offset / 64) as usize;
        debug_assert!(
            w < self.queued.len(),
            "recycle offset {offset} outside the ring's range"
        );
        if let Some(word) = self.queued.get_mut(w) {
            *word |= 1u64 << (offset % 64);
        }
    }

    #[inline]
    fn unmark(&mut self, offset: u32) {
        let w = (offset / 64) as usize;
        if let Some(word) = self.queued.get_mut(w) {
            *word &= !(1u64 << (offset % 64));
        }
    }

    /// Queue a token for `port`. `offset` is `offset_of(port)`: `None` means the
    /// port is out of this address's range (a stale token — `claim` drops it on
    /// pop), which is not deduped because it owns no bit. Returns true iff a
    /// token was actually queued. Stamps `freed_at_ns = 0` (no clock);
    /// production frees use [`Self::push_at`].
    pub(in crate::nat::allocator) fn push(&mut self, port: u16, offset: Option<u32>) -> bool {
        self.push_at(port, offset, 0)
    }

    /// Queue a token for `port` freed at monotonic `freed_at_ns` (#16035).
    /// Same dedup contract as [`Self::push`].
    pub(in crate::nat::allocator) fn push_at(
        &mut self,
        port: u16,
        offset: Option<u32>,
        freed_at_ns: u64,
    ) -> bool {
        if let Some(offset) = offset {
            if self.is_queued(offset) {
                // #16035 fold: a repeat free of an already-queued port
                // (its bit was re-claimed out-of-band via
                // `claim_in_block`/`reserve` while the old token sat
                // queued, then freed again) must move the token's
                // quarantine stamp to the LATEST free — keeping the
                // obsolete first-free stamp would let the port be
                // reused a full delay before the second free's window
                // ends. No second token is queued (dedup contract).
                if let Some(token) = self.queue.iter_mut().find(|t| t.0 == port) {
                    token.1 = token.1.max(freed_at_ns);
                }
                return false;
            }
            self.mark(offset);
        }
        self.queue.push_back((port, freed_at_ns));
        true
    }

    /// #16035: is a token freed at `freed_at_ns` still quarantined at
    /// `now_ns` for a pool of `range` ports? Only small ranges
    /// quarantine (see [`PAT_PORT_QUARANTINE_NS`]), and only tokens
    /// stamped with a real free time (see the `freed_at_ns != 0`
    /// guard in the body).
    pub(in crate::nat::allocator) fn quarantined(
        range: u32,
        freed_at_ns: u64,
        now_ns: u64,
    ) -> bool {
        // freed_at_ns == 0 is the "no clock" stamp (test seams and
        // clock-less internal frees via `push`/`free_recycle`): those
        // tokens carry no quarantine. Production small-pool frees go
        // through `free_recycle_at` with a real monotonic time (> 0),
        // so the delay binds exactly where a clock exists.
        freed_at_ns != 0
            && range <= SMALL_POOL_QUARANTINE_MAX_RANGE
            && now_ns.saturating_sub(freed_at_ns) < PAT_PORT_QUARANTINE_NS
    }

    /// Re-queue a token that was just popped by the claim walk
    /// (collision retain, exclusion, or #16035 quarantine). The pop
    /// unmarked the offset only on the collision path (where
    /// `claim_offset` then failed); the retain paths `continue`d
    /// before `unmark`, so the dedup bit may or may not still be set.
    /// `mark` is idempotent, so re-mark unconditionally: a requeue
    /// that left the bit unset would let a later `free_recycle_at`
    /// push a duplicate token for the same port (#16035 fold).
    pub(in crate::nat::allocator) fn requeue(
        &mut self,
        port: u16,
        offset: u32,
        freed_at_ns: u64,
    ) {
        self.mark(offset);
        self.queue.push_back((port, freed_at_ns));
    }
}

/// #2852 Phase 1: per-pool-address atomic occupancy for lock-free port claim.
///
/// `words` is the occupancy bitmap (bit set => that port offset is claimed);
/// a `fetch_or` CAS is the sole port-ownership arbiter and replaces the
/// pre-#2852 `owner_by_translated` map. #16011: the fresh-port probe start
/// is a per-flow keyed hash under the per-boot PAT secret (RFC 6056),
/// not a monotonic cursor. `recycle` is
/// the #3011 FIFO reuse ring — a [`RecycleRing`], which since #7174 M13 pairs
/// the queue with a per-offset "already queued" bitset so a port holds at most
/// one token — behind a per-ADDRESS mutex (never the global allocator mutex).
/// `port_low`/`range` map ports to bit offsets.
#[derive(Debug)]
pub(in crate::nat::allocator) struct AddressOccupancy {
    pub(in crate::nat::allocator) words: Vec<AtomicU64>,
    pub(in crate::nat::allocator) recycle: Mutex<RecycleRing>,
    /// #9902 F-098: test-only attempt accounting for `claim_in_block` (the
    /// deterministic block probe). `probe_word_loads` counts bitmap words
    /// loaded; `probe_claim_rmws` counts `claim_offset` attempts. The bound
    /// test pins loads ≈ words and RMWs ≈ 1 on a dense-prefix fixture — the
    /// architectural contract the word-skip exists to provide (per-port CAS
    /// would show RMWs ≈ occupied ports). Compiled out of production builds.
    #[cfg(test)]
    pub(in crate::nat::allocator) probe_word_loads: AtomicU64,
    #[cfg(test)]
    pub(in crate::nat::allocator) probe_claim_rmws: AtomicU64,
    /// #7174 (M13): live count of set bits in `words`, maintained by the two
    /// (and only two) sites that transition a bit — `claim_offset` (0 -> 1) and
    /// `free_offset` (1 -> 0). `Relaxed` is sufficient: the ONE consumer that
    /// makes a decision from it reads it while holding `recycle`, and every
    /// `free_recycle` decrements it while holding the same mutex, so the value
    /// a claimer sees is exact with respect to the FIFO contents it is about to
    /// walk. See `claim`.
    pub(in crate::nat::allocator) occupied: AtomicU32,
    /// #7174 (M13): tokens popped by the recycled phase of `claim`, cumulative.
    /// This is the quantity the row is about — "allocation cost spikes after HA
    /// role churn" is a statement about how many tokens a claim walks — and it
    /// is the ONLY externally visible difference between walking a full
    /// address's FIFO and short-circuiting it, because both return `None`. A
    /// test that asserted only the return value would be satisfied by no fix at
    /// all.
    ///
    /// #9392 PROMOTED THIS OUT OF `#[cfg(test)]`. #9327 measured that the
    /// recycled phase does NOT amortize: retained tokens go to the BACK, so K
    /// out-of-band-occupied tokens ahead of F free ones cost (K+F)/F pops per
    /// claim, degrading to K+1 per claim as F -> 1 — worst exactly as an address
    /// approaches exhaustion, i.e. when the pool is busiest. What #9327 could
    /// NOT establish is whether a production pool ever reaches K-large /
    /// F-small, because the counter that would answer it was a test seam. The
    /// fixture proves the mechanism; only a running firewall can answer the
    /// reachability, and it could not be asked.
    ///
    /// COST. The increment is NOT per pop: `claim` accumulates in a local and
    /// does ONE `Relaxed` `fetch_add` after the walk, so a healthy single-pop
    /// claim pays one relaxed RMW on a line it already owns (the walk runs
    /// under `recycle`), and the pathological walk pays the same one.
    pub(in crate::nat::allocator) recycle_scan_pops: AtomicU64,
    /// #9392: recycled-phase FIFO walks — the DENOMINATOR for
    /// [`Self::recycle_scan_pops`].
    ///
    /// Counted once per walk that is actually entered, i.e. after the
    /// `occupied >= range` short-circuit, so `pops / walks` is pops per walk:
    /// ~1 when a freed token is claimable at the head (healthy) and ~K+1 under
    /// the #9327 cliff. Without it the pop count answers nothing — a large
    /// cumulative number is equally consistent with a busy pool doing cheap
    /// walks and an idle one doing pathological ones, which is exactly the
    /// reading #9392 exists to make possible.
    pub(in crate::nat::allocator) recycle_scan_walks: AtomicU64,
    pub(in crate::nat::allocator) port_low: u16,
    pub(in crate::nat::allocator) range: u32,
}

impl AddressOccupancy {
    pub(in crate::nat::allocator) fn new(port_low: u16, range: u32) -> Self {
        let nwords = (range as usize).div_ceil(64);
        let mut words = Vec::with_capacity(nwords);
        for _ in 0..nwords {
            words.push(AtomicU64::new(0));
        }
        Self {
            words,
            recycle: Mutex::new(RecycleRing::new(range)),
            #[cfg(test)]
            probe_word_loads: AtomicU64::new(0),
            #[cfg(test)]
            probe_claim_rmws: AtomicU64::new(0),
            occupied: AtomicU32::new(0),
            recycle_scan_pops: AtomicU64::new(0),
            recycle_scan_walks: AtomicU64::new(0),
            port_low,
            range,
        }
    }

    #[inline]
    pub(in crate::nat::allocator) fn offset_of(&self, port: u16) -> Option<u32> {
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
    pub(in crate::nat::allocator) fn port_of(&self, offset: u32) -> Option<u16> {
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
        let won = self.words[w].fetch_or(mask, Ordering::AcqRel) & mask == 0;
        if won {
            // #7174 M13: exactly one increment per 0 -> 1 transition. The CAS
            // return value is what makes it exact — a losing racer does not
            // count the bit it did not win.
            self.occupied.fetch_add(1, Ordering::Relaxed);
        }
        won
    }

    /// Clear the bit at `offset`. Returns true iff it was set (1 -> 0).
    #[inline]
    fn free_offset(&self, offset: u32) -> bool {
        let w = (offset / 64) as usize;
        let mask = 1u64 << (offset % 64);
        let freed = self.words[w].fetch_and(!mask, Ordering::Release) & mask != 0;
        if freed {
            // #7174 M13: exactly one decrement per 1 -> 0 transition.
            self.occupied.fetch_sub(1, Ordering::Relaxed);
        }
        freed
    }

    #[inline]
    pub(in crate::nat::allocator) fn is_occupied(&self, offset: u32) -> bool {
        let w = (offset / 64) as usize;
        let mask = 1u64 << (offset % 64);
        self.words[w].load(Ordering::Acquire) & mask != 0
    }

    /// Claim a free port for `key` (the caller's flow tuple fold):
    /// RFC 6056 keyed start, then a bounded forward probe over at most
    /// `range` distinct offsets, then the FIFO recycle ring (#3011,
    /// retain-on-collision 062-10). Lock-free w.r.t. the global
    /// allocator mutex (it takes only the per-address recycle mutex,
    /// and only once the fresh probe is spent). Returns the claimed
    /// PORT, or None when this address is genuinely full.
    ///
    /// #16011: the pre-fix claim handed out fresh offsets in ascending
    /// CAS order from a shared monotonic cursor, so an observer of one
    /// translated port could predict the next. The keyed start makes
    /// each flow's first candidate unpredictable without the per-boot
    /// secret; the forward probe is bounded (`range` probes, each
    /// offset tried at most once) and fail-closed (None only after
    /// every offset was tried or the address is provably full).
    pub(in crate::nat::allocator) fn claim(&self, key: u64) -> Option<u16> {
        self.claim_at(key, 0)
    }

    /// [`Self::claim`] at monotonic `now_ns` (#16035 quarantine clock).
    pub(in crate::nat::allocator) fn claim_at(&self, key: u64, now_ns: u64) -> Option<u16> {
        self.claim_filtered_at(key, &|_| false, now_ns)
    }
    /// Claim with caller exclusions applied DURING the probe.
    ///
    /// FOLD (#16350 fold-3): `excluded` is consulted for every probed
    /// candidate *in probe order* before its bitmap CAS, so rejected
    /// offsets are never claimed at all. Total work is bounded by
    /// `range` probes plus at most `range` exclusion calls in order —
    /// independent of how many exclusions exist (no repeated scan per
    /// exclusion, so exclusion-heavy pools cannot go quadratic).
    /// Occupied and excluded offsets consume probe budget alike.
    pub(in crate::nat::allocator) fn claim_filtered(
        &self,
        key: u64,
        excluded: &dyn Fn(u32) -> bool,
    ) -> Option<u16> {
        self.claim_filtered_at(key, excluded, 0)
    }

    /// [`Self::claim_filtered`] at monotonic `now_ns` (#16035).
    pub(in crate::nat::allocator) fn claim_filtered_at(
        &self,
        key: u64,
        excluded: &dyn Fn(u32) -> bool,
        now_ns: u64,
    ) -> Option<u16> {
        self.claim_seeded_filtered_at(key, pat_secret(), excluded, now_ns)
    }

    /// Seed-pinned core of [`Self::claim`] for deterministic tests.
    pub(in crate::nat::allocator) fn claim_seeded(&self, key: u64, secret: u64) -> Option<u16> {
        self.claim_seeded_filtered(key, secret, &|_| false)
    }

    /// Seed-pinned core of [`Self::claim_filtered`] for deterministic tests.
    pub(in crate::nat::allocator) fn claim_seeded_filtered(
        &self,
        key: u64,
        secret: u64,
        excluded: &dyn Fn(u32) -> bool,
    ) -> Option<u16> {
        self.claim_seeded_filtered_at(key, secret, excluded, 0)
    }

    /// Seed-pinned core of [`Self::claim_filtered_at`] for deterministic tests.
    pub(in crate::nat::allocator) fn claim_seeded_filtered_at(
        &self,
        key: u64,
        secret: u64,
        excluded: &dyn Fn(u32) -> bool,
        now_ns: u64,
    ) -> Option<u16> {
        if self.range == 0 {
            return None;
        }
        if self.occupied.load(Ordering::Relaxed) >= self.range {
            return None;
        }
        let start = pat_keyed_offset(secret, key, self.range);
        // #16035: on a small range the keyed probe must not hand a
        // just-freed port straight back out — its bit is clear, so the
        // probe would claim it without ever consulting the ring. Read
        // the ring's free times and treat still-quarantined offsets as
        // excluded for this claim. Large ranges never quarantine, so
        // they skip the lock entirely.
        //
        // #16035 fold: the probe runs UNDER the recycle mutex (held in
        // `small_recycle` for the whole claim), so a concurrent free
        // cannot race the snapshot: a free either lands before the
        // guard was taken (its token and stamp are read here) or after
        // the probe finished (its bit was still set throughout, so
        // the probe could not claim that offset anyway). The previous
        // snapshot-then-drop shape let a free that landed mid-probe
        // be claimed at age ~0. Ranges <=256 bound the probe at 256
        // CAS attempts, so the innermost mutex is held only briefly;
        // lock order is unchanged (recycle stays innermost).
        let mut small_recycle = if self.range <= SMALL_POOL_QUARANTINE_MAX_RANGE {
            Some(self.recycle.lock().unwrap_or_else(|e| e.into_inner()))
        } else {
            None
        };
        let is_quarantined = |recycle: &RecycleRing, offset: u32| -> bool {
            recycle.queue.iter().any(|&(port, freed_at_ns)| {
                self.offset_of(port) == Some(offset)
                    && RecycleRing::quarantined(self.range, freed_at_ns, now_ns)
            })
        };
        for i in 0..self.range {
            let offset = start.wrapping_add(i) % self.range;
            if excluded(offset) {
                continue;
            }
            if let Some(recycle) = small_recycle.as_deref() {
                if is_quarantined(recycle, offset) {
                    continue;
                }
            }
            if self.claim_offset(offset) {
                return self.port_of(offset);
            }
            if self.occupied.load(Ordering::Relaxed) >= self.range {
                return None;
            }
        }
        // All offsets occupied/excluded at probe time. A concurrent free
        // may have queued a ring token meanwhile (or, on a small range,
        // is already queued in the guard held above); only a
        // non-excluded token can satisfy this claim in the recycled
        // phase below.

        // Recycled phase: FIFO drain (oldest-freed first). A popped port whose
        // bit is already set collided with an out-of-band occupant and is
        // RETAINED (re-queued at the back), never discarded (062-10). The
        // retain buffer allocates lazily only on an actual collision.
        let mut recycle = match small_recycle {
            Some(guard) => guard,
            None => self.recycle.lock().unwrap_or_else(|e| e.into_inner()),
        };

        // #7174 (M13): an address with EVERY port occupied cannot yield a claim,
        // so do not walk the FIFO to discover that.
        //
        // This is the pathology the row is actually about. Retained tokens go to
        // the BACK (`push` below), so K out-of-band-reserved tokens queued ahead
        // of F free ones migrate behind them.
        //
        // #9327 CORRECTS WHAT THIS PARAGRAPH USED TO CLAIM. It said the K cost
        // is paid "ONCE" and "the HA-churn spike amortizes itself". It is not
        // once. Pushing the retained tokens to the back buys exactly F cheap
        // claims before the K reserved tokens are at the head again, so a full
        // cycle costs K+F pops for F claims:
        //
        //	amortized pops per claim = (K + F) / F
        //
        // which is O(K/F), and at F=1 it does not amortize at all. Measured on
        // this tree (`recycle_amortization_9327`), pops per claim in steady
        // state:
        //
        //	K=15, F=1 -> [16, 16]                    <- every claim pays K+1
        //	K=12, F=4 -> [13, 1, 1, 1, 13, 1, 1, 1]  <- (12+4)/4 = 4, not 12-once
        //
        // F is the count of FREE tokens on the ring, so F shrinks toward 1 as
        // an address approaches exhaustion — the cost is worst exactly when the
        // pool is busiest. K is bounded by the range, so the near-exhaustion
        // worst case is O(range) pops per claim.
        //
        // The correction matters because this paragraph is the stated reason
        // the walk is unbounded, and it is the wrong reason. The RIGHT reason
        // to leave it unbounded is the next one, which is unaffected: a bare
        // scan budget cannot distinguish "scanned enough" from "genuinely
        // full", and answering `None` on budget exhaustion turns a slow
        // allocation into a spuriously dropped NAT translation. That argument
        // stands on its own and does not need the amortization claim.
        //
        // What DOES amortize away is only the fully EXHAUSTED address: with the
        // free tokens gone the FIFO is K reserved tokens and nothing else, so
        // every claim popped all K, retained all K, allocated a K-element
        // retain buffer, and returned None. `None` is the correct answer there,
        // so nothing self-corrected: O(K) per FAILED claim, for as long as
        // callers kept trying that address. That is what the short-circuit
        // below fixes, and it is a strictly narrower case than the one the old
        // wording implied was covered.
        //
        // The test is EXACT rather than a budget, which is what makes it safe.
        // The earlier analysis on #7174 rejected a bare scan budget because
        // `None` on budget exhaustion is read by callers as "this address is
        // full", turning a slow allocation into a spuriously dropped NAT
        // translation — a budget needs a way to tell "scanned enough" from
        // "genuinely full". `occupied == range` IS that discriminator: every
        // set bit is an offset < range, so the equality holds iff no port is
        // free. And it is exact with respect to the FIFO this claimer is about
        // to walk, not merely a hint, because `free_recycle` decrements the
        // counter and queues the token under THIS mutex: a free that has not
        // yet taken the lock has not pushed a token either, so a full scan
        // would miss it identically.
        if self.occupied.load(Ordering::Relaxed) >= self.range {
            return None;
        }

        let mut retained: Vec<(u16, u32, u64)> = Vec::new();
        let mut claimed = None;
        // #9392: one walk, counted once. This is the denominator, and it is
        // incremented AFTER the `occupied >= range` short-circuit above on
        // purpose — a short-circuited claim walks nothing, so folding it in
        // would drag the pops-per-walk ratio toward zero and hide the cliff the
        // ratio exists to expose.
        self.recycle_scan_walks.fetch_add(1, Ordering::Relaxed);
        let mut pops = 0u64;
        while let Some((port, freed_at_ns)) = recycle.queue.pop_front() {
            pops += 1;
            // FOLD (#16350 fold-3): an excluded recycled port is retained
            // (re-queued), never claimed for this flow.
            if let Some(off) = self.offset_of(port) {
                if excluded(off) {
                    retained.push((port, off, freed_at_ns));
                    continue;
                }
            }
            // An out-of-range (stale) port yields None and is DROPPED: it owns
            // no bit, so it was never marked and there is nothing to unmark.
            if let Some(offset) = self.offset_of(port) {
                // #16035: a small-pool token still inside its minimum
                // reuse delay is retained with its ORIGINAL free time
                // (re-queued below), never claimed and never dropped.
                if RecycleRing::quarantined(self.range, freed_at_ns, now_ns) {
                    retained.push((port, offset, freed_at_ns));
                    continue;
                }
                recycle.unmark(offset);
                if self.claim_offset(offset) {
                    claimed = Some(port);
                    break;
                }
                // Occupied: retained so a transient collision cannot shrink the
                // pool (062-10).
                retained.push((port, offset, freed_at_ns));
            }
        }
        // #9392: ONE relaxed RMW for the whole walk rather than one per pop.
        // `pops == 0` still stores, because the store is unconditional in the
        // walks counter above and a walk that popped nothing (an empty FIFO) is
        // a real observation — pops/walks == 0 says "the recycled phase ran and
        // found nothing to recycle", which is a different reading from a walk
        // that never happened.
        self.recycle_scan_pops.fetch_add(pops, Ordering::Relaxed);
        for (port, offset, freed_at_ns) in retained {
            recycle.requeue(port, offset, freed_at_ns);
        }
        claimed
    }

    /// Test-only: ONLY the recycled phase (FIFO drain with retain).
    /// #16011: production claims probe the bitmap first; fixtures that
    /// measure the ring's retain/scan cost drive this phase directly.
    #[cfg(test)]
    pub(in crate::nat::allocator) fn claim_recycled_only(&self) -> Option<u16> {
        self.claim_recycled_only_at(0)
    }

    /// Test-only recycled phase at monotonic `now_ns` (#16035).
    #[cfg(test)]
    pub(in crate::nat::allocator) fn claim_recycled_only_at(&self, now_ns: u64) -> Option<u16> {
        let mut recycle = self.recycle.lock().unwrap_or_else(|e| e.into_inner());
        if self.occupied.load(Ordering::Relaxed) >= self.range {
            return None;
        }
        let mut retained: Vec<(u16, u32, u64)> = Vec::new();
        let mut claimed = None;
        self.recycle_scan_walks.fetch_add(1, Ordering::Relaxed);
        let mut pops = 0u64;
        while let Some((port, freed_at_ns)) = recycle.queue.pop_front() {
            pops += 1;
            if let Some(offset) = self.offset_of(port) {
                if RecycleRing::quarantined(self.range, freed_at_ns, now_ns) {
                    retained.push((port, offset, freed_at_ns));
                    continue;
                }
                recycle.unmark(offset);
                if self.claim_offset(offset) {
                    claimed = Some(port);
                    break;
                }
                retained.push((port, offset, freed_at_ns));
            }
        }
        self.recycle_scan_pops.fetch_add(pops, Ordering::Relaxed);
        for (port, offset, freed_at_ns) in retained {
            recycle.requeue(port, offset, freed_at_ns);
        }
        claimed
    }

    /// Free `port`, pushing it onto the FIFO recycle ring (push_back) so it is
    /// reused oldest-first (#3011). Returns true iff the bit was set.
    /// Stamps the token at time 0; production frees use
    /// [`Self::free_recycle_at`] so #16035 can age the token.
    pub(in crate::nat::allocator) fn free_recycle(&self, port: u16) -> bool {
        self.free_recycle_at(port, 0)
    }

    /// Free `port` at monotonic `now_ns`, stamping its recycle token
    /// with the free time (#16035). Returns true iff the bit was set.
    pub(in crate::nat::allocator) fn free_recycle_at(&self, port: u16, now_ns: u64) -> bool {
        let Some(offset) = self.offset_of(port) else {
            return false;
        };
        // #7174 (M13): the bit clear and the token push happen under ONE
        // acquisition of the recycle mutex. That is what lets `claim`'s
        // exhausted-address test be exact rather than a hint: a claimer holding
        // this mutex cannot observe a decremented `occupied` whose token has not
        // been queued yet, nor a queued token whose decrement it has not seen.
        // The bit itself stays a lock-free atomic; the critical section grows by
        // one `fetch_and` on a path that already took this mutex to push.
        let mut recycle = self.recycle.lock().unwrap_or_else(|e| e.into_inner());
        if !self.free_offset(offset) {
            return false;
        }
        recycle.push_at(port, Some(offset), now_ns);
        true
    }

    /// Free `port` WITHOUT recycling it. Returns true iff the bit was set.
    ///
    /// Test-only out-of-band clear (`debug_clear_owner`): models an owner
    /// outside the flow table releasing its bit. Production frees go
    /// through `free_recycle` (#14625: deterministic ports included).
    pub(in crate::nat::allocator) fn free_no_recycle(&self, port: u16) -> bool {
        match self.offset_of(port) {
            Some(offset) => self.free_offset(offset),
            None => false,
        }
    }

    /// Reserve a SPECIFIC port (CAS-set its exact bit). Returns true iff the
    /// bit transitioned 0 -> 1 (the caller now owns it); false when the port
    /// is out of range or already owned (do-not-steal).
    pub(in crate::nat::allocator) fn reserve(&self, port: u16) -> bool {
        match self.offset_of(port) {
            Some(offset) => self.claim_offset(offset),
            None => false,
        }
    }

    /// Claim a free port in the CLOSED interval `[start_port, end_port]`
    /// (#9902 F-098): the word-skipping probe both deterministic-CGNAT arms use
    /// for a subscriber's block.
    ///
    /// The word-skip is preserved: one load per spanned word, all-ones
    /// words skipped, first zero bit named with `trailing_zeros` and
    /// claimed directly (lowest-free ascending).
    ///
    /// #16011 scope note: deterministic CGNAT is NOT randomized. Its
    /// ports are a documented pure function of the subscriber (block
    /// derivation / BIB reproducibility), so predictability there is the
    /// operator-configured contract, not the RFC 6056 defect. The keyed
    /// fix applies to round-robin PAT (`claim`), interface PAT and
    /// `try_next_port`, where no reproducibility contract exists.
    ///
    /// EDGES. Block sizes are arbitrary positive integers
    /// (compiler_nat_source.rs validates `> 0` and `<= range` only), so a block
    /// need not align to 64-bit words: out-of-block bits in the first and last
    /// word are masked as occupied (never claimed), including the both-edges-
    /// in-one-word case.
    ///
    /// FORWARD PROGRESS. Tried candidates are masked out of the LOCAL word copy
    /// and a word is never reloaded within one call, so each in-block bit is
    /// tried at most once per call — the finite forward scan the naive loop had.
    /// A lost CAS means a racer owns the bit now; move on.
    ///
    /// RACES. There is no coherent full-block snapshot: a bit freed concurrently
    /// inside a skipped all-ones word may be passed over (a later free port is
    /// claimed instead, or a full block is reported while a free exists). Still
    /// correct — every claimed port was free and is won by exactly one claimer.
    /// Lock-free w.r.t. the global allocator mutex (same as the naive loop).
    pub(in crate::nat::allocator) fn claim_in_block(
        &self,
        start_port: u16,
        end_port: u16,
    ) -> Option<u16> {
        // Unkeyed continuation probe (callers resuming past a rejected
        // candidate): ascending from `start_port`, no rotation.
        self.claim_in_block_from(start_port, end_port)
    }

    /// Ascending word-skip scan of `[seg_start_port, seg_end_port]`.
    fn claim_in_block_from(&self, seg_start_port: u16, seg_end_port: u16) -> Option<u16> {
        let start = self.offset_of(seg_start_port)?;
        let end = self.offset_of(seg_end_port)?;
        if start > end {
            return None;
        }
        let first_word = (start / 64) as usize;
        let last_word = (end / 64) as usize;
        for w in first_word..=last_word {
            let mut word = self.words[w].load(Ordering::Acquire);
            #[cfg(test)]
            self.probe_word_loads.fetch_add(1, Ordering::Relaxed);
            if w == first_word {
                let lead = start % 64;
                if lead != 0 {
                    word |= (1u64 << lead) - 1;
                }
            }
            if w == last_word {
                let tail = end % 64;
                if tail != 63 {
                    word |= !((1u64 << (tail + 1)) - 1);
                }
            }
            let mut pending = !word;
            while pending != 0 {
                let bit = pending.trailing_zeros();
                pending &= pending - 1;
                let offset = w as u32 * 64 + bit;
                #[cfg(test)]
                self.probe_claim_rmws.fetch_add(1, Ordering::Relaxed);
                if self.claim_offset(offset) {
                    return self.port_of(offset);
                }
            }
        }
        None
    }

    /// Count of currently-occupied ports on this address (popcount over the
    /// bitmap). Cold path (snapshot / tests only).
    ///
    /// Deliberately NOT read from the `occupied` counter (#7174 M13): the
    /// popcount is derived from the bitmap itself, so it stays an INDEPENDENT
    /// oracle for the counter rather than a second name for it. A test asserts
    /// the two agree after a workload; if they ever diverge, that assertion is
    /// the thing that can see it.
    pub(in crate::nat::allocator) fn occupied_count(&self) -> usize {
        self.words
            .iter()
            .map(|w| w.load(Ordering::Relaxed).count_ones() as usize)
            .sum()
    }

    /// #16035 fold: is `port`'s queued token still quarantined at
    /// `now_ns`? Used by the specific-port reserve path, which CASes a
    /// named port directly and would otherwise bypass the delay the
    /// claim paths enforce. No token (never freed / already claimed)
    /// is not quarantined.
    pub(in crate::nat::allocator) fn port_quarantined(&self, port: u16, now_ns: u64) -> bool {
        if self.range > SMALL_POOL_QUARANTINE_MAX_RANGE {
            return false;
        }
        let recycle = self.recycle.lock().unwrap_or_else(|e| e.into_inner());
        recycle
            .queue
            .iter()
            .any(|&(p, freed_at_ns)| {
                p == port && RecycleRing::quarantined(self.range, freed_at_ns, now_ns)
            })
    }
}
