// #2472: per-reason token-bucket rate limiter for LOCALLY-GENERATED ICMP /
// RST error replies.
//
// The three locally-originated error-reply generators —
//   - TTL/Hop-Limit Exceeded (`icmp::build_local_time_exceeded_request`),
//   - Packet-Too-Big / Frag-Needed PMTUD (`icmp_ptb`),
//   - policy/filter `reject` RST or ICMP-unreachable
//     (`poll_descriptor::reject_reply`),
// each build + enqueue an error frame after the RFC-suppression and (since
// #2238/#2328) output-classification gates. None of them had a token bucket:
// an attacker that drives a flood of TTL-1 packets, oversized DF=1 packets, or
// rejected flows can make the box emit one generated error PER trigger packet,
// unbounded. That is a CPU / TX amplification sink and a reflection vector (the
// generated errors are addressed to the trigger's source, which an attacker can
// spoof). The pre-existing SYN-cookie TX-frame budget gate on the reject path
// is a queue-protection gate (it stops the reply ring from starving transit
// TX), NOT a per-reason cap — under a sustained flood it refills as fast as TX
// drains, so it does not bound the generated-error RATE.
//
// This adds the missing limiter, modelled on Linux's ICMP rate limiting
// (`net.ipv4.icmp_msgs_per_sec` — a GLOBAL per-host burst, default 1000/s —
// plus `net.ipv4.icmp_ratelimit`). We use the simple, bounded-state half of
// that model: a per-reason token bucket (no per-source / per-destination map,
// so there is no attacker-driven map growth). Each reason has its own bucket so
// a TTL-exceeded flood cannot starve the PTB or reject reasons (and vice-versa)
// — per-reason isolation.
//
// #3618 / #5856: ALL THREE reasons are split PER INGRESS (from) ZONE — one
// bucket per configured zone, held in `ForwardingState::{reject_buckets,
// time_exceeded_buckets, packet_too_big_buckets}` and resolved at each
// generator call site from the ingress ifindex, with a process-global
// per-reason fallback limiter (`{REJECT,TIME_EXCEEDED,PACKET_TOO_BIG}_
// FALLBACK_LIMITER`) for an unzoned/unknown zone. This removes the cross-zone
// starvation the single global buckets had: a flood ingressing one zone can
// no longer drain the bucket and suppress a legitimate generated error in
// another zone.
//
// #3618 split ONLY Reject (the reject call site carried `from_zone_id`);
// #5856 extends the IDENTICAL per-zone mechanism to TimeExceeded (resolved
// from `ingress_ident.ifindex` in `icmp::build_local_time_exceeded_request`)
// and PacketTooBig (resolved from `ingress_ident.ifindex` in the TX dispatch
// PTB path) — closing the cross-zone denial that let one zone flood
// TTL=1/hop-limit=1 or oversized-DF traffic and suppress legitimate
// traceroute / PMTUD replies for every OTHER zone. The generator sites always
// carried ingress identity; the missing zone key was an API omission, not
// absence of attribution (see `docs/generated-reply-rate-limit.md`).
//
// The observable aggregate `*_rate_limited_total` stays a SINGLE atomic per
// reason (`{REJECT,TIME_EXCEEDED,PACKET_TOO_BIG}_RATE_LIMITED_TOTAL`) bumped on
// any per-zone deny, so the coordinator status / Prometheus metric format is
// unchanged. Cardinality is config-bounded for every reason (configured zones,
// Go-capped ≤ 65533), so there is still no attacker-driven map growth.
//
// Hot-path: the check is a single CAS loop over ONE atomic word (a GCRA
// theoretical-arrival-time; #2955 collapsed the prior split token-count +
// timestamp pair into this single CAS so refill and consume commit together
// and concurrent workers cannot double-credit / over-admit). It runs ONLY on
// the cold generated-error path (per TTL-exceeded / PTB / reject decision),
// never per forwarded packet, and never allocates. On bucket-empty the
// generated reply is DROPPED and a per-reason
// `*_rate_limited` counter (a global `AtomicU64`, surfaced via the coordinator
// status the same way as `GRE_ENCAP_DF_OVERSIZE_DROPS`) is bumped so the
// suppression is observable.
//
// #9901 (F-074): each per-zone bucket above is now a per-source-fair
// HIERARCHICAL limiter (`ZoneLimiter`): a per-source tier (64 fixed slots,
// 100/s + burst 100 each) in front of the zone aggregate (1000/1000). Before,
// one source flooding a zone drained that zone's whole budget and starved
// every OTHER source in the same zone — the same starvation shape #3618/#5856
// removed between zones, one level down. The source tier is keyed by the
// trigger's source address (META addrs, never frame bytes); a source-denied
// reply consumes NOTHING shared (source-FIRST gate order, the #5567
// build-before-consume principle applied to the tier order), so a flooder
// spends only its own slot. Slot collisions share the slot's sustained rate
// (tag is hint-only, no bucket reset on takeover); cardinality stays
// config-bounded (~1.5KB per zone limiter, no attacker-growable map).

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;

use super::neighbor::monotonic_nanos;
use crate::afxdp::types::ForwardingState;

/// The locally-generated error reasons that share this limiter. Each variant
/// indexes an independent token bucket, so exhausting one reason never blocks
/// another (per-reason isolation, #2472).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) enum GeneratedErrorReason {
    /// ICMPv4 Time Exceeded / ICMPv6 Hop-Limit Exceeded
    /// (`build_local_time_exceeded_request`).
    TimeExceeded,
    /// ICMPv4 Frag-Needed (type 3 code 4) / ICMPv6 Packet Too Big
    /// (the #2301/#2330 PMTUD generators).
    PacketTooBig,
    /// Policy / firewall-filter `reject` reply (TCP RST or ICMP/ICMPv6
    /// administratively-prohibited unreachable).
    Reject,
}

/// Default sustained refill rate, in tokens (= permitted generated errors) per
/// second, applied PER reason. 1000/s mirrors Linux's `icmp_msgs_per_sec`
/// default. A legitimate router emits these errors at a trickle (a real
/// PMTUD/traceroute path is a handful per flow); 1000/s per reason is far above
/// any benign rate yet caps a flood at three orders of magnitude below
/// line-rate amplification.
pub(in crate::afxdp) const DEFAULT_RATE_PER_SEC: u64 = 1000;

/// Default burst depth (bucket capacity), PER reason. Allows a short legitimate
/// burst (e.g. a traceroute fan-out or an MTU-change storm at the start of many
/// flows) to pass without being clipped, while still bounding the steady-state
/// rate to `DEFAULT_RATE_PER_SEC`.
pub(in crate::afxdp) const DEFAULT_BURST: u64 = 1000;

const NANOS_PER_SEC: u64 = 1_000_000_000;

/// A lock-free GCRA (Generic Cell Rate Algorithm) token bucket. #2955: the
/// state is a SINGLE atomic word — the "theoretical arrival time" (TAT) in
/// monotonic nanos — so refill and consume commit together in one CAS. The
/// previous implementation split the state into two independent atomics
/// (`millitokens` + `last_ns`) and CAS-committed only `millitokens`, then
/// published `last_ns` as a separate relaxed store. Two workers could observe
/// the new (lower) token count with the OLD timestamp and credit the same
/// refill interval twice (double-credit), or both observe the `last_ns == 0`
/// first-use branch and each refill to full burst — over-admitting generated
/// error replies past the configured rate and corrupting the
/// `rate_limited_total` counters on the DoS boundary.
///
/// GCRA encodes the bucket as one number: as long as `tat - burst_horizon <=
/// now`, a token is available, and a successful consume advances `tat` by one
/// `interval`. Because `tat` is the entire state, there is no second field to
/// tear against — the single CAS atomically refills AND consumes. This is the
/// same single-TAT pattern used by `event_stream/producer.rs`.
/// #3618/#5856: exposed as `pub(in crate::afxdp)` so `ZoneLimiter` (held in
/// `ForwardingState` per-zone maps: `reject_buckets`,
/// `time_exceeded_buckets`, `packet_too_big_buckets`) can compose its tiers
/// from these. The fields stay private to this module; the only cross-module
/// entry points are `TokenBucket::new()` (to build a fresh tier) and the
/// `allow_generated_*` gates below (which do the tiered `try_take` + counter
/// bump). Held behind an `Arc` in `ForwardingState` so the shared atomics
/// survive `ForwardingState::clone()` (fabric refresh re-stores a clone at
/// runtime cadence — see `forwarding.rs`).
#[derive(Debug)]
pub(in crate::afxdp) struct TokenBucket {
    /// Theoretical arrival time (monotonic nanos). The whole limiter state.
    /// Initialised to 0 so the first `burst` calls after boot pass (an
    /// effectively-full bucket: `0 - horizon` saturates to 0 <= any `now`).
    theoretical_arrival_ns: AtomicU64,
    /// Count of generated errors dropped because the bucket was empty.
    rate_limited: AtomicU64,
}

impl TokenBucket {
    /// #7174 M04 test observable. `theoretical_arrival_ns` IS the limiter state:
    /// consuming a token advances it, declining to consume leaves it alone. So
    /// "did this path spend a token?" is exactly "did this value move?", which
    /// is a precise question a burst-exhaustion probe can only approximate.
    #[cfg(test)]
    pub(in crate::afxdp) fn arrival_ns(&self) -> u64 {
        self.theoretical_arrival_ns.load(Ordering::Relaxed)
    }

    pub(in crate::afxdp) const fn new() -> Self {
        TokenBucket {
            theoretical_arrival_ns: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
        }
    }

    /// Try to consume one token. Returns true when a token was available (the
    /// generated reply MAY be sent) and false when the bucket is empty (the
    /// reply MUST be dropped + the per-reason counter bumped by the caller).
    ///
    /// GCRA: `interval_ns = 1e9 / rate_per_sec` is the steady-state spacing
    /// between admitted replies; `burst_horizon_ns = (burst - 1) * interval`
    /// is how far ahead of `now` the TAT may run while still admitting a
    /// burst. The refill (advancing the admissible window as `now` grows) and
    /// the consume (advancing `tat` by one interval) are committed TOGETHER in
    /// a single `compare_exchange` over the one state word, so concurrent
    /// workers can never double-credit or over-admit (#2955).
    fn try_take(&self, now_ns: u64, rate_per_sec: u64, burst: u64) -> bool {
        // A zero rate disables the bucket (unlimited) — never rate-limit. This
        // keeps the limiter opt-out-able via config without a branch at the
        // call site.
        if rate_per_sec == 0 {
            return true;
        }
        // interval = nanos between admitted tokens at the steady rate. Round up
        // so a high rate never collapses to a zero interval (which would admit
        // unboundedly). A burst of 0 is treated as 1 (no negative horizon).
        let interval_ns = (NANOS_PER_SEC.saturating_add(rate_per_sec - 1) / rate_per_sec).max(1);
        let burst_horizon_ns = interval_ns.saturating_mul(burst.saturating_sub(1));

        let mut tat = self.theoretical_arrival_ns.load(Ordering::Relaxed);
        loop {
            // Bucket empty: the next admission would push the TAT more than the
            // burst horizon ahead of the current time. Deny WITHOUT mutating
            // state (a denied call must not advance the epoch — sibling tests
            // and the far-future-drain pattern in reject_reply.rs rely on this).
            if tat.saturating_sub(burst_horizon_ns) > now_ns {
                return false;
            }
            // Refill + consume in ONE value: clamp the TAT forward to `now`
            // (this is the lazy refill — never let the bucket accrue more than
            // `burst` worth of credit) and add one interval (the consume).
            let next_tat = tat.max(now_ns).saturating_add(interval_ns);
            match self.theoretical_arrival_ns.compare_exchange_weak(
                tat,
                next_tat,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                // Single CAS committed refill AND consume atomically.
                Ok(_) => return true,
                // CAS lost: another worker advanced the TAT concurrently. Retry
                // with the observed value — never with stale split state.
                Err(actual) => tat = actual,
            }
        }
    }
}
/// #9901 (F-074): number of fixed per-source slots in a `ZoneLimiter`. A
/// power of two so the slot is one modulo over the seeded mix; 64 bounds the
/// limiter to ~1.5KB (64 tags + 66 buckets) while keeping incidental
/// collisions rare for the handful of concurrent error sources a zone sees.
const SRC_SLOT_COUNT: usize = 64;

/// #9901 (F-074): the per-source sustained rate (tokens/sec) and burst depth
/// EVERY per-source slot and the `None`-source overflow bucket enforce. Fixed
/// constants, not gate parameters: a legitimate source emits generated errors
/// at a trickle (traceroute / PMTUD are a handful per flow), so 100/s + burst
/// 100 is far above any benign source rate while bounding one flooder to a
/// tenth of the zone aggregate.
const SRC_RATE_PER_SEC: u64 = 100;
const SRC_BURST: u64 = 100;

/// #9901 (F-074): the NEVER-claimed `src_tags` sentinel. Tags are claimed
/// with `| 1`, so no live tag is ever 0; a zero-initialized slot reads EMPTY
/// until the first source claims it. Hint-only either way — see `ZoneLimiter`.
const TAG_EMPTY: u64 = 0;

/// #9901 (F-074): a per-source-fair hierarchical generated-error limiter —
/// the per-zone budget that used to be a single `TokenBucket`.
///
/// Structure: one zone `aggregate` bucket (the #3618/#5856 budget, still
/// parameterized by the gate's rate/burst) fronted by a per-source tier: 64
/// fixed `src_slots` (each 100/s + burst 100) selected by
/// `(seed ^ addr_mix) % 64`, plus one `overflow` bucket (same 100/100 budget)
/// for a `None` source. Gate order is source-FIRST then aggregate: a
/// source-deny consumes NOTHING shared (the #5567 build-before-consume
/// principle applied to the tier order), so one flooder cannot starve another
/// source in the same zone — only the zone aggregate can still deny, exactly
/// as before.
///
/// `src_tags` records the current claimant of each slot (best-effort CAS,
/// result ignored). The tag is HINT-ONLY: on takeover the slot's bucket is
/// NOT reset — colliders share the slot's sustained rate. There is no
/// attacker-growable map (fixed 64 slots) and no lock (one atomic word per
/// tier consult). The per-boot seed (`hot_path_hash_seed`) keeps the
/// source→slot mapping unpredictable off-box, so an attacker cannot
/// precompute a colliding source set.
///
/// Memory: ~1.5KB per limiter (64 × u64 tags + 66 buckets × 2 × u64), held
/// behind `Arc` in `ForwardingState` exactly as the old per-zone buckets
/// were. Wire-maximum cardinality (65533 zones × 3 reasons) is ~300MB in the
/// absurd all-zones-configured case; realistic zone counts cost KBs. Accepted
/// and documented — the alternative (lazy per-zone build) would admit a
/// fail-open window or a config-path lock.
#[derive(Debug)]
pub(in crate::afxdp) struct ZoneLimiter {
    /// The zone aggregate budget — the former per-zone `TokenBucket`.
    aggregate: TokenBucket,
    /// Current-claimant hint per source slot (`TAG_EMPTY` = never claimed).
    src_tags: [AtomicU64; SRC_SLOT_COUNT],
    /// Fixed per-source buckets, 100/s + burst 100 each.
    src_slots: [TokenBucket; SRC_SLOT_COUNT],
    /// The `None`-source budget (100/s + burst 100), shared by all sourceless
    /// errors. A real bucket, never a fail-open skip.
    overflow: TokenBucket,
}

/// Mix a source address into 64 bits. Sequential addresses differ in low
/// bits; the multiplicative spread keeps neighboring sources in different
/// slots. Unpredictability comes from the per-boot seed XORed at the call
/// site, not from this mix.
fn addr_mix(addr: &IpAddr) -> u64 {
    let x = match addr {
        IpAddr::V4(v4) => u32::from(*v4) as u64,
        IpAddr::V6(v6) => {
            let x = u128::from(*v6);
            (x as u64) ^ ((x >> 64) as u64)
        }
    };
    x.wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

/// The source slot and claimant tag for `addr` under `seed`. The tag folds
/// the bits above the slot index and is forced non-zero so it never reads
/// `TAG_EMPTY`.
fn slot_and_tag(seed: u64, addr: &IpAddr) -> (usize, u64) {
    let h = seed ^ addr_mix(addr);
    let slot = (h % SRC_SLOT_COUNT as u64) as usize;
    let tag = (h >> 6) | 1;
    (slot, tag)
}

impl ZoneLimiter {
    /// A fresh limiter: every tier full (TAT 0), every slot unclaimed.
    pub(in crate::afxdp) fn new() -> Self {
        ZoneLimiter {
            aggregate: TokenBucket::new(),
            src_tags: std::array::from_fn(|_| AtomicU64::new(TAG_EMPTY)),
            src_slots: std::array::from_fn(|_| TokenBucket::new()),
            overflow: TokenBucket::new(),
        }
    }

    /// Source-FIRST, aggregate-second admission. Returns true when the reply
    /// MAY be sent (both tiers had a token). A source-deny bumps the
    /// reason's aggregate `*_RATE_LIMITED_TOTAL` (the observable metric)
    /// WITHOUT touching the aggregate bucket; an aggregate-deny is accounted
    /// by the shared `take_and_account` site. `rate_per_sec == 0` disables
    /// the limiter (both tiers), preserving the `TokenBucket` opt-out.
    fn allow(
        &self,
        reason: GeneratedErrorReason,
        src: Option<IpAddr>,
        now_ns: u64,
        rate_per_sec: u64,
        burst: u64,
    ) -> bool {
        if rate_per_sec == 0 {
            return true;
        }
        let src_bucket = match src {
            Some(addr) => {
                let (slot, tag) =
                    slot_and_tag(crate::hot_hash_seed::hot_path_hash_seed(), &addr);
                let observed = self.src_tags[slot].load(Ordering::Relaxed);
                if observed != tag {
                    // Best-effort claim; the result is ignored — on a race
                    // the loser still shares the slot (hint-only, never a
                    // gate), and no bucket is reset on takeover.
                    let _ = self.src_tags[slot].compare_exchange_weak(
                        observed,
                        tag,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    );
                }
                &self.src_slots[slot]
            }
            None => &self.overflow,
        };
        if !src_bucket.try_take(now_ns, SRC_RATE_PER_SEC, SRC_BURST) {
            src_bucket.rate_limited.fetch_add(1, Ordering::Relaxed);
            rate_limited_total(reason).fetch_add(1, Ordering::Relaxed);
            return false;
        }
        take_and_account(&self.aggregate, reason, now_ns, rate_per_sec, burst)
    }

    /// #9901 (F-074) test observable: the aggregate tier's TAT. "Did this
    /// path spend a token on the SHARED budget?" is exactly "did this value
    /// move?" — the same question `TokenBucket::arrival_ns` answers for one
    /// bucket. Mirrors the M04 arrival pattern the TE tests pin.
    #[cfg(test)]
    pub(in crate::afxdp) fn aggregate_arrival_ns(&self) -> u64 {
        self.aggregate.arrival_ns()
    }

    /// Reset EVERY tier (aggregate, overflow, all source slots + tags) to
    /// full at epoch `now_ns`, mirroring the single-bucket reset. GCRA: a
    /// full bucket at `now_ns` is `tat == now_ns`.
    #[cfg(test)]
    fn reset_for_test(&self, now_ns: u64) {
        for bucket in [&self.aggregate, &self.overflow]
            .into_iter()
            .chain(self.src_slots.iter())
        {
            bucket
                .theoretical_arrival_ns
                .store(now_ns, Ordering::Relaxed);
            bucket.rate_limited.store(0, Ordering::Relaxed);
        }
        for tag in self.src_tags.iter() {
            tag.store(TAG_EMPTY, Ordering::Relaxed);
        }
    }

    /// Drain ONLY the aggregate tier at (`now_ns`, rate, burst) — the
    /// hierarchy-aware form of the far-future-drain pattern. Drains through
    /// the gate would stop at the source tier's smaller budget and leave the
    /// aggregate half-full; this empties exactly the tier the old
    /// single-bucket drains emptied. No accounting (the caller's `before`
    /// read follows the drain, as before).
    #[cfg(test)]
    pub(in crate::afxdp) fn drain_aggregate_for_test(
        &self,
        now_ns: u64,
        rate_per_sec: u64,
        burst: u64,
    ) {
        while self.aggregate.try_take(now_ns, rate_per_sec, burst) {}
    }

    /// The source slot `addr` maps to under the live seed. Test-only: lets
    /// cells pick same-slot (collision) vs distinct-slot sources without
    /// hardcoding a seed-dependent layout.
    #[cfg(test)]
    pub(in crate::afxdp) fn slot_for_test(addr: &IpAddr) -> usize {
        slot_and_tag(crate::hot_hash_seed::hot_path_hash_seed(), addr).0
    }
}

/// #3618/#5856: shared per-reason fallback limiter used when a generated
/// error's ingress (from) zone has NO per-zone limiter — an unzoned (id 0) or
/// otherwise-unknown zone id. Each is a REAL limiter (never a fail-open
/// skip), so an unzoned/unknown error is still rate-limited; such errors all
/// share the reason's one fallback budget (the rare/degenerate case, not a
/// per-zone diagnostic). The per-zone limiters now live in `ForwardingState`
/// (`reject_buckets` #3618; `time_exceeded_buckets` / `packet_too_big_buckets`
/// #5856), built from the configured zone set, so a flood on one zone can no
/// longer drain a single global limiter and starve error-generation in another
/// zone. #9901 (F-074): full `ZoneLimiter`s (not bare buckets), so the
/// fallback path keeps per-source fairness; `LazyLock` because a 64-slot
/// limiter is not `const`-constructible (precedent:
/// `nat::source::match_rules`).
static REJECT_FALLBACK_LIMITER: LazyLock<ZoneLimiter> = LazyLock::new(ZoneLimiter::new);
static TIME_EXCEEDED_FALLBACK_LIMITER: LazyLock<ZoneLimiter> = LazyLock::new(ZoneLimiter::new);
static PACKET_TOO_BIG_FALLBACK_LIMITER: LazyLock<ZoneLimiter> = LazyLock::new(ZoneLimiter::new);

/// #3618/#5856: process-global aggregate count, PER reason, of generated error
/// replies dropped because the (per-zone OR fallback) bucket was empty. A
/// SINGLE atomic per reason bumped on ANY per-zone deny — NOT a sum over the
/// per-zone buckets' `rate_limited` fields — so `rate_limited_count(reason)`
/// stays an O(1) atomic load and the coordinator status / Prometheus
/// `*_rate_limited_total` wire contract is UNCHANGED by the per-zone split.
/// Each per-zone `TokenBucket` keeps its own `rate_limited` field for OPTIONAL
/// future per-zone attribution; the aggregate metric never reads those fields.
static REJECT_RATE_LIMITED_TOTAL: AtomicU64 = AtomicU64::new(0);
static TIME_EXCEEDED_RATE_LIMITED_TOTAL: AtomicU64 = AtomicU64::new(0);
static PACKET_TOO_BIG_RATE_LIMITED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// The reason's shared fallback limiter: the limiter the non-zone-keyed
/// `allow_generated_error_at` test entry point (aggregate tier only) and the
/// test reset helper operate on. The zone-keyed gates
/// (`allow_generated_error_zoned*`) resolve a per-zone limiter first and fall
/// back to this same static, so both stay consistent.
fn limiter_for(reason: GeneratedErrorReason) -> &'static ZoneLimiter {
    match reason {
        GeneratedErrorReason::TimeExceeded => &TIME_EXCEEDED_FALLBACK_LIMITER,
        GeneratedErrorReason::PacketTooBig => &PACKET_TOO_BIG_FALLBACK_LIMITER,
        GeneratedErrorReason::Reject => &REJECT_FALLBACK_LIMITER,
    }
}

/// The reason's process-global aggregate rate-limited counter. A SINGLE atomic
/// per reason, bumped on every per-zone (and fallback) deny, read O(1) by
/// `rate_limited_count`. This is what keeps the observable `*_rate_limited_total`
/// wire contract unchanged across the per-zone split (#3618/#5856).
fn rate_limited_total(reason: GeneratedErrorReason) -> &'static AtomicU64 {
    match reason {
        GeneratedErrorReason::TimeExceeded => &TIME_EXCEEDED_RATE_LIMITED_TOTAL,
        GeneratedErrorReason::PacketTooBig => &PACKET_TOO_BIG_RATE_LIMITED_TOTAL,
        GeneratedErrorReason::Reject => &REJECT_RATE_LIMITED_TOTAL,
    }
}

/// Non-zone-keyed testable core: try one token against `reason`'s fallback
/// limiter AGGREGATE tier with an injected clock + rate / burst, so the unit
/// tests can drive a deterministic burst-then-refill sequence without
/// sleeping. Bypasses the per-source/overflow tiers: this is the GCRA-math
/// and far-future-drain entry point, and routing it through the smaller
/// source budget would cap every drain at 100 tokens. On a deny it bumps BOTH
/// the aggregate bucket's own `rate_limited` field and the reason's aggregate
/// `*_RATE_LIMITED_TOTAL`, so `rate_limited_count(reason)` (which reads the
/// aggregate) stays authoritative regardless of entry point.
///
/// Test-only: production TE/PTB/Reject gates all go through the zone-keyed
/// [`allow_generated_error_zoned_at`] (which itself falls back to this
/// reason's fallback limiter for an unzoned/unknown zone), so the pure
/// aggregate path is exercised directly only by the unit tests.
#[cfg(test)]
pub(in crate::afxdp) fn allow_generated_error_at(
    reason: GeneratedErrorReason,
    now_ns: u64,
    rate_per_sec: u64,
    burst: u64,
) -> bool {
    take_and_account(
        &limiter_for(reason).aggregate,
        reason,
        now_ns,
        rate_per_sec,
        burst,
    )
}

/// #3618/#5856: zone-scoped generated-error gate. Returns true when a
/// locally-generated error reply for `reason` whose ingress (from) zone is
/// `from_zone_id` MAY be sent (its per-zone limiter admitted it), false when
/// it MUST be dropped. #9901 (F-074): `src` is the trigger's source address
/// (META addrs, never frame bytes); `Some` keys the limiter's per-source
/// tier, `None` the shared overflow tier. The per-zone limiter comes from
/// `ForwardingState` (`reject_buckets` / `time_exceeded_buckets` /
/// `packet_too_big_buckets`, built from the configured zone set at config
/// apply); an unzoned (id 0) or otherwise-unknown zone id falls back to the
/// reason's shared process-global `*_FALLBACK_LIMITER` — a real limiter, so
/// the gate is NEVER fail-open and never panics on a missing key. On a deny
/// the reason's single aggregate `*_RATE_LIMITED_TOTAL` is bumped (metric
/// unchanged) alongside the denying tier's own `rate_limited` field (optional
/// attribution).
pub(in crate::afxdp) fn allow_generated_error_zoned(
    forwarding: &ForwardingState,
    reason: GeneratedErrorReason,
    from_zone_id: u16,
    src: Option<IpAddr>,
) -> bool {
    allow_generated_error_zoned_at(
        forwarding,
        reason,
        from_zone_id,
        src,
        monotonic_nanos(),
        DEFAULT_RATE_PER_SEC,
        DEFAULT_BURST,
    )
}

/// Testable core of [`allow_generated_error_zoned`] with an injected clock +
/// rate / burst (which parameterize the zone AGGREGATE tier; the per-source
/// tier is fixed 100/s + burst 100), so the unit tests can drive a
/// deterministic per-zone burst-then-drain sequence without sleeping.
pub(in crate::afxdp) fn allow_generated_error_zoned_at(
    forwarding: &ForwardingState,
    reason: GeneratedErrorReason,
    from_zone_id: u16,
    src: Option<IpAddr>,
    now_ns: u64,
    rate_per_sec: u64,
    burst: u64,
) -> bool {
    let limiter = forwarding
        .generated_error_bucket(reason, from_zone_id)
        .unwrap_or_else(|| limiter_for(reason));
    limiter.allow(reason, src, now_ns, rate_per_sec, burst)
}

/// #3618: reject-reason convenience wrapper over the generic zone-keyed gate.
/// Kept as a named entry point for `poll_descriptor::reject_reply` and the
/// existing reject unit tests; behaviour is identical to
/// `allow_generated_error_zoned(_, Reject, _, _)`.
pub(in crate::afxdp) fn allow_generated_reject(
    forwarding: &ForwardingState,
    from_zone_id: u16,
    src: Option<IpAddr>,
) -> bool {
    allow_generated_reject_at(
        forwarding,
        from_zone_id,
        src,
        monotonic_nanos(),
        DEFAULT_RATE_PER_SEC,
        DEFAULT_BURST,
    )
}

/// Testable core of [`allow_generated_reject`] — delegates to the generic
/// zone-keyed gate with the Reject reason.
pub(in crate::afxdp) fn allow_generated_reject_at(
    forwarding: &ForwardingState,
    from_zone_id: u16,
    src: Option<IpAddr>,
    now_ns: u64,
    rate_per_sec: u64,
    burst: u64,
) -> bool {
    allow_generated_error_zoned_at(
        forwarding,
        GeneratedErrorReason::Reject,
        from_zone_id,
        src,
        now_ns,
        rate_per_sec,
        burst,
    )
}

/// Consume one token from `bucket` and, on a deny, bump BOTH the bucket's own
/// per-zone/fallback `rate_limited` field (optional attribution) and the
/// reason's single aggregate `*_RATE_LIMITED_TOTAL` (the observable metric).
/// This is the ONE accounting site shared by the zone-keyed and fallback gates,
/// so every deny — per-zone or fallback — advances the aggregate exactly once.
fn take_and_account(
    bucket: &TokenBucket,
    reason: GeneratedErrorReason,
    now_ns: u64,
    rate_per_sec: u64,
    burst: u64,
) -> bool {
    let allowed = bucket.try_take(now_ns, rate_per_sec, burst);
    if !allowed {
        bucket.rate_limited.fetch_add(1, Ordering::Relaxed);
        rate_limited_total(reason).fetch_add(1, Ordering::Relaxed);
    }
    allowed
}

/// Observable per-reason count of generated error replies dropped because the
/// reason's token bucket was empty. Surfaced via the coordinator status
/// (`*_rate_limited_total`). #3618/#5856: EVERY reason now reads its dedicated
/// process-global aggregate (`{REJECT,TIME_EXCEEDED,PACKET_TOO_BIG}_RATE_
/// LIMITED_TOTAL`), which is bumped on every per-zone (and fallback) deny — an
/// O(1) atomic load, never a sum over the per-zone buckets, so the wire/metric
/// format is unchanged by the per-zone split.
pub(in crate::afxdp) fn rate_limited_count(reason: GeneratedErrorReason) -> u64 {
    rate_limited_total(reason).load(Ordering::Relaxed)
}

/// #2955: serialises every test that drives the GLOBAL per-reason buckets.
/// The buckets are process-wide statics shared across modules (this module's
/// unit tests AND `poll_descriptor::reject_reply`'s tests), and the GCRA TAT
/// advances monotonically and never travels backwards. So a
/// `reset_bucket_for_test` from one test interleaved with a TAT advance / drain
/// from another can starve a sibling (e.g. a drain-to-far-future leaves the
/// Reject bucket denied for a concurrent success-path test). The old
/// millitoken reset-to-full was order-independent and hid this; the
/// race-immune single-word limiter is order-SENSITIVE under the cargo parallel
/// runner, so the *tests* must serialise their reset→drive→assert window over
/// the shared statics. Every global-bucket test holds this guard for its whole
/// body. (Tests using a LOCAL `TokenBucket` — the #2955 concurrency guards —
/// touch no shared state and do not take the lock.)
#[cfg(test)]
pub(in crate::afxdp) fn global_bucket_test_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
pub(in crate::afxdp) fn reset_bucket_for_test(reason: GeneratedErrorReason, now_ns: u64) {
    let limiter = limiter_for(reason);
    // GCRA: a full bucket at epoch `now_ns` is `tat == now_ns` (the next
    // `burst` admissions all satisfy `tat - horizon <= now`). Tests that pin a
    // FAR-FUTURE epoch then drain rely on this: after draining at `now_ns`,
    // `tat` runs `burst * interval` ahead, and a later call at a SMALLER clock
    // value stays denied (the GCRA window never travels backwards).
    // #9901 (F-074): reset EVERY tier (aggregate, overflow, all source slots
    // + tags), mirroring the single-bucket reset — a leftover source-slot TAT
    // would otherwise deny a sibling's first post-reset admission.
    limiter.reset_for_test(now_ns);
    // #3618/#5856: also clear the reason's dedicated aggregate so a test that
    // asserts an exact `rate_limited_count(reason)` starts from a clean slate
    // (the aggregate is a separate atomic from the fallback limiter's fields).
    rate_limited_total(reason).store(0, Ordering::Relaxed);
}

#[cfg(test)]
#[path = "icmp_ratelimit_tests.rs"]
mod tests;
