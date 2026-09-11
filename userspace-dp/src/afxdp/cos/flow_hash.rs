// Per-queue flow-hash machinery for SFQ admission + promotion.
//
// `COS_FLOW_FAIR_BUCKETS` / `COS_FLOW_FAIR_BUCKET_MASK` live in
// `afxdp::types` because they size other types there (`FlowRrRing`,
// `CoSQueueRuntime` arrays); flow_hash imports them rather than
// owning them.

use crate::afxdp::types::{CoSPendingTxItem, CoSQueueRuntime, COS_FLOW_FAIR_BUCKET_MASK};
use crate::session::{SessionKey, TunnelDiscriminator};
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

/// #9645: mix a u32 as its low and high 16-bit halves. The mix step carries
/// only upward and the bucket index keeps the low bits, so a single mix of a
/// u32 whose two values differ only above bit 15 cannot move the bucket.
#[inline(always)]
fn mix_u32_halves_for_cos_bucket(seed: &mut u64, value: u32) {
    mix_cos_flow_bucket(seed, u64::from(value & 0xffff));
    mix_cos_flow_bucket(seed, u64::from(value >> 16));
}

/// Draw a fresh per-queue hash salt from the kernel.
///
/// #2364: the OS-entropy draw (`getrandom(2)` with a CLOCK_MONOTONIC +
/// pid + stack-address fallback and a never-zero invariant) was hoisted
/// into `crate::hot_hash_seed::os_random_seed_u64` so the CoS SFQ seed
/// and the node-local hot-path hash seed share ONE audited entropy path
/// instead of two byte-identical copies. The never-zero contract that
/// `cos_flow_hash_seed_from_os_never_returns_zero` (and the downstream
/// `assert_ne!(flow_hash_seed, 0)`) depend on is enforced there.
pub(in crate::afxdp) fn cos_flow_hash_seed_from_os() -> u64 {
    crate::hot_hash_seed::os_random_seed_u64()
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
    // #9645: the routing domain and the tunnel discriminator are part of
    // `SessionKey` identity, so identical 5-tuples in two routing instances,
    // or in two GRE tunnels that differ only by key, are different flows.
    // Hashing only the 5-tuple put them in the SAME bucket for every seed,
    // so overlapping tenant address space split one fair share by
    // construction rather than by chance. Each field is mixed only when it is
    // not the default, so a flow in the default routing instance with no
    // discriminator keeps exactly the pre-#9645 bucket mapping (the seed-0
    // pins and the 5201 fairness baseline stay valid).
    //
    // Tags are small values and every u32 is mixed as two 16-bit halves:
    // `mix_cos_flow_bucket` only carries UPWARD and the bucket keeps the low
    // bits, so a difference that lives only above bit 15 (a tag placed at
    // bit 32, or two GRE keys that differ only in their upper half) would
    // otherwise never reach the bucket.
    if flow_key.routing_domain != 0 {
        mix_cos_flow_bucket(&mut seed, 1);
        mix_u32_halves_for_cos_bucket(&mut seed, flow_key.routing_domain);
    }
    // Exhaustive with no `_` arm, as in `session/key.rs`: a new discriminator
    // class has to decide here whether it separates fair shares.
    match flow_key.discriminator {
        TunnelDiscriminator::None => {}
        TunnelDiscriminator::Unkeyed => mix_cos_flow_bucket(&mut seed, 2),
        TunnelDiscriminator::Keyed(key) => {
            mix_cos_flow_bucket(&mut seed, 3);
            mix_u32_halves_for_cos_bucket(&mut seed, key);
        }
        TunnelDiscriminator::Pptp(handle) => {
            mix_cos_flow_bucket(&mut seed, 4);
            mix_u32_halves_for_cos_bucket(&mut seed, handle);
        }
        TunnelDiscriminator::Unparseable => mix_cos_flow_bucket(&mut seed, 5),
    }
    seed as u16
}

#[inline]
pub(in crate::afxdp) fn cos_item_flow_key(item: &CoSPendingTxItem) -> Option<&SessionKey> {
    match item {
        CoSPendingTxItem::Local(req) => req.flow_key.as_ref(),
        CoSPendingTxItem::Prepared(req) => req.flow_key.as_ref(),
    }
}

/// #hb166 T-7: dedicated SFQ lane for keyless / flowless traffic
/// (non-TCP/UDP frames, pre-session packets — anything with no
/// `SessionKey`). Reserving a fixed bucket keeps all such items in ONE
/// lane (the anti-splay intent of #693, so they don't inflate
/// `active_flow_buckets`) WITHOUT sharing that lane with a real 5-tuple
/// flow that happens to hash to the same slot. The pre-fix code routed
/// BOTH keyless AND any real flow whose salted hash masked onto bucket 0
/// into bucket 0, so one unlucky victim flow contended for SFQ
/// virtual-finish time against ALL keyless traffic.
pub(in crate::afxdp) const COS_FLOW_FAIR_KEYLESS_BUCKET: usize = 0;

/// Fallback lane for the rare real flow whose salted hash masks onto the
/// reserved keyless bucket. Steering it to bucket 1 adds at most a
/// 1-in-`COS_FLOW_FAIR_BUCKETS` skew to bucket 1's occupancy — negligible
/// for SFQ — and is strictly better than diluting the victim flow's share
/// with keyless traffic.
const COS_FLOW_FAIR_KEYLESS_REAL_FALLBACK: usize = 1;

#[inline(always)]
pub(in crate::afxdp) fn cos_flow_bucket_index(
    queue_seed: u64,
    flow_key: Option<&SessionKey>,
) -> usize {
    if flow_key.is_none() {
        return COS_FLOW_FAIR_KEYLESS_BUCKET;
    }
    let idx = usize::from(exact_cos_flow_bucket(queue_seed, flow_key)) & COS_FLOW_FAIR_BUCKET_MASK;
    // Reserve the keyless lane: a real flow that masks onto it is steered
    // to a dedicated fallback bucket instead of colliding with keyless.
    if idx == COS_FLOW_FAIR_KEYLESS_BUCKET {
        COS_FLOW_FAIR_KEYLESS_REAL_FALLBACK
    } else {
        idx
    }
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
    // Non-flow-fair queues have effectively 1 flow (the whole queue is
    // a single FIFO from the per-flow share denominator's perspective).
    // This is the correct semantic, not an invariant escape — the gate
    // distinguishes it from the next branch below.
    if !queue.flow_fair() {
        return 1;
    }
    let ff = queue
        .flow_fair_state
        .as_ref()
        .expect("cos_queue_prospective_active_flows: flow_fair queue without flow_fair_state");
    u64::from(ff.active_flow_buckets)
        .saturating_add(u64::from(ff.flow_bucket_bytes[flow_bucket] == 0))
        .max(1)
}

#[cfg(test)]
#[path = "flow_hash_tests.rs"]
mod tests;
