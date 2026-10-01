// Per-boot secret seed for node-local hot-path hashes (#2364).
//
// Several forwarding-path structures hash attacker-controllable keys
// (5-tuples, ingress ifindex) with an UNKEYED, deterministic mixer
// (`rustc_hash::FxHasher::default()`). An off-box attacker who controls
// the 5-tuple can precompute keys whose masked low bits collide, forcing
// flow-cache set thrash, fabric-queue skew, or session-map collision
// chains (algorithmic-complexity DoS). This is the same class of hazard
// the CoS SFQ flow hash already defends against with a per-queue random
// seed (`afxdp::cos::flow_hash::cos_flow_hash_seed_from_os`).
//
// This module provides a SINGLE per-process secret seed, drawn once at
// first use and stable for the life of the process, that the node-local
// hot-path hashes fold in. The seed is:
//
//   * Per-boot random  — defeats offline collision construction (the
//     attacker cannot know which keys collide without observing the
//     daemon, and the mapping reshuffles on every restart).
//   * Stable within a boot — the flow-cache set index, session-map
//     bucket, and fabric-queue selection for a given flow MUST be
//     consistent across that flow's lifetime, or the caches/maps break.
//     A `OnceLock` gives "draw once, then constant" semantics.
//   * Node-local only — every site that uses this seed is private to
//     one worker/process and is NOT part of any wire protocol or
//     HA-synced structure. HA session sync transmits the explicit
//     `SessionKey`, never a hash value, so peers re-derive their own
//     buckets under their own seed. The fabric queue hash selects
//     among THIS node's local fabric egress bindings (`all_by_if`,
//     modulo the local count) — the peer does not need to agree, so a
//     per-node seed is correct there too. NOTHING that requires
//     cross-node or cross-restart hash determinism uses this seed.
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

use std::sync::OnceLock;

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

/// Process-global per-boot seed. Drawn once at first use, then constant.
static HOT_PATH_SEED: OnceLock<u64> = OnceLock::new();

/// The per-process secret seed for node-local hot-path hashes. Stable for
/// the life of the process. Never zero.
///
/// Reproducibility for tests is provided not by mutating this global (which
/// would race across the parallel test runner) but by the seed-parameterized
/// `*_seeded` cores at each call site (`FlowCache::set_index_seeded`,
/// `worker::fabric_queue_hash_seeded`, and the `FxSeededState` the session
/// indices are built from). Those let a test pin a seed locally and assert
/// both intra-seed stability and cross-seed reshuffling — the same pattern
/// the CoS SFQ hash uses. Production always reads this process-global value.
#[inline]
pub(crate) fn hot_path_hash_seed() -> u64 {
    *HOT_PATH_SEED.get_or_init(os_random_seed_u64)
}

#[cfg(test)]
#[path = "hot_hash_seed_tests.rs"]
mod tests;
