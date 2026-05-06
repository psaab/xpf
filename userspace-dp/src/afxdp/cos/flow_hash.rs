// Per-queue flow-hash machinery for SFQ admission + promotion.
//
// `COS_FLOW_FAIR_BUCKETS` / `COS_FLOW_FAIR_BUCKET_MASK` live in
// `afxdp::types` because they size other types there (`FlowRrRing`,
// `CoSQueueRuntime` arrays); flow_hash imports them rather than
// owning them.

use crate::afxdp::types::{CoSPendingTxItem, CoSQueueRuntime, COS_FLOW_FAIR_BUCKET_MASK};
use crate::session::SessionKey;
use std::net::IpAddr;

/// XorShift-style mix step used by both the per-queue salt fallback
/// and the 5-tuple bucket hash. File-private — no callers outside
/// flow_hash.
#[inline(always)]
fn mix_cos_flow_bucket(seed: &mut u64, value: u64) {
    *seed ^= value
        .wrapping_add(0x9e3779b97f4a7c15)
        .wrapping_add(*seed << 6)
        .wrapping_add(*seed >> 2);
}

/// Draw a fresh per-queue hash salt from the kernel.
///
/// `getrandom(2)` with `flags=0` blocks only during early boot before the
/// urandom pool is initialized, which is not a path this daemon runs on
/// (xpfd starts well after systemd-random-seed). Retries on `EINTR` and
/// partial reads (the kernel is allowed to return fewer bytes than
/// requested; 8 bytes is well below any documented per-call limit so a
/// partial is pathological, but still explicitly handled rather than
/// silently degrading). If the syscall ever fails for a real reason we
/// fall through to a CLOCK_MONOTONIC + pid + stack-address-mixed
/// fallback so the daemon does not abort on queue construction. The
/// fallback is strictly weaker than `getrandom` — predictable enough
/// that it must not be the production path — but strictly stronger
/// than the zero-seed it replaces, and stays per-call-distinct because
/// each call mixes in a live clock read and the stack address of the
/// return buffer.
pub(in crate::afxdp) fn cos_flow_hash_seed_from_os() -> u64 {
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
    // Production invariant (#785 Copilot review): never return 0.
    // Zero is a valid getrandom output (probability 2^-64 per call,
    // but across a fleet of daemons × per-binding promotions it DOES
    // occur), and a zero seed turns the SFQ hash mapping into a pure
    // function of the 5-tuple — externally probeable, and identical
    // across all bindings on all nodes, which collapses SFQ bucket
    // diversity to zero. The `assert_ne!(flow_hash_seed, 0)` test
    // downstream depends on this invariant and would otherwise be
    // theoretically flaky. One in 2^64 getrandom reads gets OR'd
    // with 1 — indistinguishable from the raw entropy for any
    // downstream use.
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
    mix_cos_flow_bucket(&mut fallback, now.rotate_left(17));
    mix_cos_flow_bucket(&mut fallback, stack_addr.rotate_left(31));
    nonzero(fallback)
}

// #711: returns `u16` (was `u8`). With `COS_FLOW_FAIR_BUCKETS = 4096`
// the mask in `cos_flow_bucket_index` is 12 bits wide; a `u8` return
// would silently re-collapse the hash into 256 buckets and give no
// benefit from the bucket grow. Returning `u16` preserves the full
// hash width through the mask step.
#[inline(always)]
fn exact_cos_flow_bucket(queue_seed: u64, flow_key: Option<&SessionKey>) -> u16 {
    let Some(flow_key) = flow_key else {
        return 0;
    };
    let mut seed = queue_seed ^ (flow_key.protocol as u64) ^ ((flow_key.addr_family as u64) << 8);
    match flow_key.src_ip {
        IpAddr::V4(ip) => mix_cos_flow_bucket(&mut seed, u32::from(ip) as u64),
        IpAddr::V6(ip) => {
            for chunk in ip.octets().chunks_exact(8) {
                mix_cos_flow_bucket(&mut seed, u64::from_be_bytes(chunk.try_into().unwrap()));
            }
        }
    }
    match flow_key.dst_ip {
        IpAddr::V4(ip) => mix_cos_flow_bucket(&mut seed, u32::from(ip) as u64),
        IpAddr::V6(ip) => {
            for chunk in ip.octets().chunks_exact(8) {
                mix_cos_flow_bucket(&mut seed, u64::from_be_bytes(chunk.try_into().unwrap()));
            }
        }
    }
    mix_cos_flow_bucket(&mut seed, flow_key.src_port as u64);
    mix_cos_flow_bucket(&mut seed, flow_key.dst_port as u64);
    seed as u16
}

#[inline]
pub(in crate::afxdp) fn cos_item_flow_key(item: &CoSPendingTxItem) -> Option<&SessionKey> {
    match item {
        CoSPendingTxItem::Local(req) => req.flow_key.as_ref(),
        CoSPendingTxItem::Prepared(req) => req.flow_key.as_ref(),
    }
}

#[inline(always)]
pub(in crate::afxdp) fn cos_flow_bucket_index(
    queue_seed: u64,
    flow_key: Option<&SessionKey>,
) -> usize {
    usize::from(exact_cos_flow_bucket(queue_seed, flow_key)) & COS_FLOW_FAIR_BUCKET_MASK
}

/// Prospective distinct-flow count: current `active_flow_buckets` plus
/// one when the target bucket is currently empty (i.e. we are admitting
/// the first packet of a newly arriving flow). Both admission gates —
/// the per-flow clamp and the aggregate cap — must use this value so
/// they stay in lockstep. The original #704 bug was exactly this
/// denominator drifting: one gate bumped for the new flow, the other
/// did not, and the new flow's first packet got rejected at the
/// boundary. Keeping the formula in one place removes that class of
/// reintroduction risk.
#[inline]
pub(in crate::afxdp) fn cos_queue_prospective_active_flows(
    queue: &CoSQueueRuntime,
    flow_bucket: usize,
) -> u64 {
    u64::from(queue.active_flow_buckets)
        .saturating_add(u64::from(queue.flow_bucket_bytes[flow_bucket] == 0))
        .max(1)
}

#[cfg(test)]
#[path = "flow_hash_tests.rs"]
mod tests;

