// Per-boot secret seed for node-local hot-path hashes (#2364).
//
// Several forwarding-path structures hash attacker-controllable keys
// (5-tuples, ingress ifindex) for placement. FxHasher's seed is additive:
// a key-pair delta is seed-independent, and selected v6 address words let
// remote senders construct same-set families for every seed. This module
// supplies a per-process key to the keyed SipHash builder used for cache
// sets and session maps (#12603), plus independent per-process
// fragment-shard secrets (#12602). Each seed is drawn once and remains
// stable for the life of the process.
//
//   * Per-boot random  — defeats offline collision construction (the
//     attacker cannot know which keys collide without observing the
//     daemon, and the mapping reshuffles on every restart).
//   * Stable within a boot — cache indexes, session-map buckets, fabric-queue
//     selection, and fragment-map placement stay consistent for the lifetime
//     of their owning structures. LazyLock/OnceLock provide draw-once semantics.
//   * Node-local only — every site has private placement, not a value in a wire
//     protocol or HA-synced structure. Common hot-path sites use the shared seed;
//     fragment maps draw independent keys. HA session sync transmits the explicit
//     `SessionKey`, never a hash value, so peers re-derive their own buckets.
//     The fabric queue hash selects among THIS node's local egress bindings
//     (`all_by_if`, modulo the local count). NOTHING that requires cross-node or
//     cross-restart hash determinism uses these per-process secrets.
//
// ECMP flow-to-member selection deliberately does not use this seed: its
// mapping must survive restart/HA re-resolution when the live member set is
// unchanged, so it uses an ECMP-specific fixed domain seed instead. Unlike
// cache/map placement, predictable ECMP selection does not enable collision
// eviction or chain amplification.
//
// The draw reuses the exact OS-entropy mechanism vetted for the CoS seed
// (`getrandom(2)` with a CLOCK_MONOTONIC + pid + stack-address fallback
// and a never-zero invariant) via `os_random_seed_u64`, so there is one
// audited entropy path rather than two.

use std::sync::{LazyLock, OnceLock};

/// XorShift-style mix step shared by the OS-entropy fallback. File-private.
#[inline(always)]
fn mix(seed: &mut u64, value: u64) {
    *seed ^= value
        .wrapping_add(0x9e3779b97f4a7c15)
        .wrapping_add(*seed << 6)
        .wrapping_add(*seed >> 2);
}

/// Draw a fresh 64-bit seed from the kernel CSPRNG.
///
/// `getrandom(2)` with `flags=0` blocks only during very early boot
/// before the urandom pool is initialized, which is not a path this
/// daemon runs on (xpfd starts well after systemd-random-seed). Retries
/// on `EINTR` and partial reads. If the syscall fails for a real reason
/// we fall through to a CLOCK_MONOTONIC + pid + stack-address-mixed
/// fallback so the daemon does not abort. The fallback is strictly
/// weaker than `getrandom` but strictly stronger than the zero seed it
/// replaces. The result is never zero: a zero seed collapses the seeded
/// hash back into a pure (externally probeable) function of the key,
/// re-opening exactly the hole this module closes.
pub(crate) fn os_random_seed_u64() -> u64 {
    let mut buf = [0u8; 8];
    let mut filled = 0usize;
    while filled < buf.len() {
        // SAFETY: `buf[filled..]` is a valid mutable slice of length
        // `buf.len() - filled` for the duration of the call.
        let rc = unsafe {
            libc::getrandom(
                buf.as_mut_ptr().add(filled).cast::<libc::c_void>(),
                buf.len() - filled,
                0,
            )
        };
        if rc > 0 {
            filled += rc as usize;
            continue;
        }
        if rc < 0 {
            let err = std::io::Error::last_os_error().raw_os_error();
            if err == Some(libc::EINTR) {
                continue;
            }
        }
        // rc == 0 (should not happen for getrandom) or a real error: bail
        // to the fallback rather than spinning.
        break;
    }
    // Never-zero invariant (mirrors `cos_flow_hash_seed_from_os`): zero is
    // a valid getrandom output (2^-64 per call, but across a fleet it does
    // occur) and a zero seed turns the seeded hash into the unkeyed FxHash
    // it replaces. OR'ing 1 over a 2^-64 draw is indistinguishable from
    // raw entropy downstream and keeps the `assert_ne!(seed, 0)` tests
    // sound.
    let nonzero = |v: u64| if v == 0 { 1 } else { v };
    if filled == buf.len() {
        return nonzero(u64::from_ne_bytes(buf));
    }

    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid out-pointer for `clock_gettime`.
    let now = unsafe {
        if libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) == 0 {
            (ts.tv_sec as u64)
                .wrapping_mul(1_000_000_000)
                .wrapping_add(ts.tv_nsec as u64)
        } else {
            0
        }
    };
    let pid = std::process::id() as u64;
    let stack_addr = (&buf as *const [u8; 8]) as usize as u64;
    let mut fallback = now ^ pid.wrapping_mul(0x9e3779b97f4a7c15);
    mix(&mut fallback, now.rotate_left(17));
    mix(&mut fallback, stack_addr.rotate_left(31));
    nonzero(fallback)
}

static HOT_PATH_SEED: OnceLock<u64> = OnceLock::new();

/// Per-process seeded SipHash builder for attacker-keyed table placement.
/// FxHasher's seed is additive and therefore cannot prevent key-pair
/// cancellations in its polynomial hash.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HotPathSeededState {
    seed: u64,
}

impl HotPathSeededState {
    #[inline]
    pub(crate) const fn new(seed: u64) -> Self {
        Self { seed }
    }
}

#[allow(deprecated)]
impl std::hash::BuildHasher for HotPathSeededState {
    type Hasher = std::hash::SipHasher;

    #[inline]
    fn build_hasher(&self) -> Self::Hasher {
        std::hash::SipHasher::new_with_keys(
            self.seed,
            self.seed.rotate_left(29) ^ 0x9e37_79b9_7f4a_7c15,
        )
    }
}

/// The process-global hot-path seed. Stable for the life of the process.
/// Tests pin seeds through `HotPathSeededState::new` or each `*_seeded`
/// helper rather than mutating this global.

/// The common per-process secret for node-local hot-path hashes. Stable for the
/// process lifetime and never zero. Fragment maps use separate keys below.
///
/// Reproducibility for tests is provided not by mutating this global (which
/// would race across the parallel test runner) but by parameterized seeded
/// cores at each hash site. Production reads this common seed only where sites
/// intentionally share the key.

#[inline]
pub(crate) fn hot_path_hash_seed() -> u64 {
    *HOT_PATH_SEED.get_or_init(os_random_seed_u64)
}
/// Independent per-process keys for fragment shard maps. Separate draws ensure
/// disclosure of another hot-path site's shared seed does not expose these
/// placements. Both remain stable for the process lifetime.
static FRAG_ASSOC_SHARD_SEED: LazyLock<u64> = LazyLock::new(os_random_seed_u64);
static FRAG_OVERLAP_SHARD_SEED: LazyLock<u64> = LazyLock::new(os_random_seed_u64);

#[inline]
pub(crate) fn frag_assoc_shard_seed() -> u64 {
    *FRAG_ASSOC_SHARD_SEED
}

#[inline]
pub(crate) fn frag_overlap_shard_seed() -> u64 {
    *FRAG_OVERLAP_SHARD_SEED
}

/// Keyed, domain-separated high-bit shard selection. The seed is applied
/// after the caller's key fold so changes to any seed byte avalanche through
/// the selected bits rather than merely rotating a seeded FNV state.
#[inline]
pub(crate) fn keyed_shard_index(hash: u64, seed: u64, domain: u64, shards: usize) -> usize {
    debug_assert!(shards >= 2 && shards.is_power_of_two());
    let mut h = hash ^ seed ^ domain;
    h = (h ^ (h >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    h = (h ^ (h >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    h ^= h >> 31;
    (h >> (u64::BITS - shards.trailing_zeros())) as usize
}

#[cfg(test)]
#[path = "hot_hash_seed_tests.rs"]
mod tests;
