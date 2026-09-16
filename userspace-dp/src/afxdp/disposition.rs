// Disposition / telemetry recording extracted from afxdp.rs (Issue 67.3).
//
// `record_exception` (52 LOC) — emits an ExceptionStatus to the
// per-binding live counters when a packet hits an exception path
// (drop, kernel handoff, fabric redirect).
//
// `record_disposition` (68 LOC) — feeds the per-disposition
// PacketDisposition counters used by status queries.
//
// `record_forwarding_disposition` (99 LOC) — overlay used when
// the forwarding outcome itself (ForwardCandidate / FabricRedirect /
// LocalDelivery / etc.) is the dimension being recorded.
//
// `update_last_resolution` (~30 LOC) — caches the most recent
// ForwardingResolution / disposition per session for the inspect
// CLI / gRPC.
//
// Pure relocation. `use super::*;` brings every type and helper
// from afxdp.rs into scope.

use super::*;
use chrono::DateTime;
use std::time::Instant;

// ---------------------------------------------------------------------------
// #5289: per-worker POD exception ring.
//
// The drop-disposition path used to lock a PROCESS-GLOBAL
// `Arc<Mutex<ExceptionEventRing>>` and heap-format an
// `ExceptionStatus` (interface/reason/IP/zone `String`s + `Utc::now()`)
// on EVERY terminal packet. Attacker-controlled denied traffic
// (policy-deny / no-route / missing-neighbor) therefore serialized
// forwarding latency across unrelated workers on one mutex and paid a
// per-packet allocation + wall-clock syscall — a cross-worker DoS /
// tail-latency side channel.
//
// The record path now writes a compact POD `ExceptionEvent` into a
// PER-WORKER ring (`ExceptionEventRing`, one `Arc<Mutex<..>>` per
// worker — locked only by its owning worker plus the ~1 Hz status
// thread, so there is NO cross-worker contention). The event carries:
//   * `reason` as a `&'static str` literal (Copy pointer, no alloc),
//   * `interface` as an `Arc<str>` refcount clone (atomic inc, no heap),
//   * `src_ip`/`dst_ip` as `Copy` `IpAddr`s (stack, no heap),
//   * zones as NUMERIC ids resolved to names on the control thread,
//   * a monotonic `Instant` instead of `Utc::now()`.
// A per-(reason,5-tuple) sampler suppresses a flood of identical
// terminal packets so the ring is not thrashed every packet. The
// `ExceptionStatus` (interface/reason/IP/zone strings + wall-clock)
// is reconstructed ONLY when the status is built/read on the control
// thread (`Coordinator::recent_exceptions`), via a single captured
// monotonic->wall-clock anchor. The batched per-binding counters
// (`BindingLiveState`) remain the lossless signal — the ring is a
// bounded diagnostic sample, exactly as the old deque was.
// ---------------------------------------------------------------------------

/// Ring depth: preserves the historical 32-deep semantics of the retired
/// process-global `recent_exceptions` deque, but PER WORKER.
pub(in crate::afxdp) const EXCEPTION_RING_CAPACITY: usize = MAX_RECENT_EXCEPTIONS;

/// Number of gate slots in the per-(reason,key) sampler. A power of two so
/// the slot index is a mask. Bounded, fixed-size, zero-allocation.
const EXCEPTION_GATE_SLOTS: usize = 16;

/// Suppression window for the sampler. A terminal packet whose
/// (reason, 5-tuple-hash) matches a recently-admitted event within this
/// monotonic window is COUNTED (`suppressed`) but not pushed, so an
/// attacker flood of identical denied packets cannot fill the ring — the
/// operator keeps seeing 32 DISTINCT recent exceptions, not 32 copies of
/// one flood packet.
const EXCEPTION_SAMPLE_WINDOW: Duration = Duration::from_millis(100);

/// #5289: compact POD-ish exception event recorded lock-free-of-global-locks
/// on the worker terminal-packet path. See the module note above for the
/// no-`String`-alloc / no-`Utc::now` invariants. Formatted to
/// `ExceptionStatus` on the control/status thread via [`ExceptionEvent::to_status`].
#[derive(Clone)]
pub(crate) struct ExceptionEvent {
    pub(in crate::afxdp) mono: Instant,
    /// Static reason literal (the hot-path case — Copy, no allocation).
    pub(in crate::afxdp) reason: &'static str,
    /// Optional `'static` reason SUFFIX (the hot-path variant case — Copy,
    /// no allocation). When non-empty the effective reason is
    /// `concat(reason, reason_suffix)`, reconstructed only on the control
    /// thread. This lets the slow-path reinject-failure sites (which pair a
    /// `&'static` base reason with one of a fixed set of `&'static` outcome
    /// suffixes — `_rate_limited` / `_queue_full` / …) record WITHOUT the
    /// per-event `format!`/`String` alloc the old owned path paid on a
    /// reinject-failure flood (#6101). `""` on every other path.
    pub(in crate::afxdp) reason_suffix: &'static str,
    /// Rare cold-path (spawn/tunnel-setup failure) DYNAMIC reason that
    /// cannot be a `'static` literal (`format!("...:{id}:{err}")`). When
    /// present it OVERRIDES `reason` in the rendered status. `None` on the
    /// worker hot path, so the hot path never allocates a reason.
    pub(in crate::afxdp) reason_owned: Option<Arc<str>>,
    pub(in crate::afxdp) interface: Arc<str>,
    pub(in crate::afxdp) slot: u32,
    pub(in crate::afxdp) queue_id: u32,
    pub(in crate::afxdp) worker_id: u32,
    pub(in crate::afxdp) ifindex: i32,
    pub(in crate::afxdp) ingress_ifindex: i32,
    pub(in crate::afxdp) packet_length: u32,
    pub(in crate::afxdp) addr_family: u8,
    pub(in crate::afxdp) protocol: u8,
    pub(in crate::afxdp) config_generation: u64,
    pub(in crate::afxdp) fib_generation: u32,
    pub(in crate::afxdp) src_ip: Option<IpAddr>,
    pub(in crate::afxdp) dst_ip: Option<IpAddr>,
    pub(in crate::afxdp) src_port: u16,
    pub(in crate::afxdp) dst_port: u16,
    /// #919: zone IDs — resolved to names on the control thread via
    /// `forwarding.zone_id_to_name`, exactly as the old inline path did.
    pub(in crate::afxdp) from_zone_id: Option<u16>,
    pub(in crate::afxdp) to_zone_id: Option<u16>,
    /// SNAT-failure only; `Arc<str>` clone on the (sampler-gated) SNAT path.
    pub(in crate::afxdp) rule_name: Option<Arc<str>>,
    pub(in crate::afxdp) pool_name: Option<Arc<str>>,
}

impl ExceptionEvent {
    /// The effective reason string. Precedence: a cold DYNAMIC
    /// `reason_owned` override wins; otherwise the `&'static` base `reason`
    /// with any `&'static` `reason_suffix` concatenated. Borrows (no
    /// allocation) for the common no-suffix case; allocates ONLY when a
    /// suffix must be joined, and ONLY on the control/status read path —
    /// never on the packet record path (#6101).
    pub(crate) fn reason(&self) -> std::borrow::Cow<'_, str> {
        if let Some(owned) = self.reason_owned.as_deref() {
            return std::borrow::Cow::Borrowed(owned);
        }
        if self.reason_suffix.is_empty() {
            std::borrow::Cow::Borrowed(self.reason)
        } else {
            std::borrow::Cow::Owned(format!("{}{}", self.reason, self.reason_suffix))
        }
    }

    /// Reconstruct the operator-visible `ExceptionStatus` on the control
    /// thread. This is where the `String`/IP formatting and monotonic->
    /// wall-clock conversion happen — NOT on the packet path.
    pub(in crate::afxdp) fn to_status(
        &self,
        anchor: MonoWallAnchor,
        forwarding: &ForwardingState,
    ) -> ExceptionStatus {
        // #919: zone IDs render as zone names; unknown IDs render as the
        // empty string (unchanged behaviour).
        let zone_name_for = |id: Option<u16>| -> String {
            id.and_then(|z| forwarding.zone_id_to_name.get(&z).cloned())
                .unwrap_or_default()
        };
        ExceptionStatus {
            timestamp: anchor.wall_clock(self.mono),
            slot: self.slot,
            queue_id: self.queue_id,
            worker_id: self.worker_id,
            interface: self.interface.to_string(),
            ifindex: self.ifindex,
            ingress_ifindex: self.ingress_ifindex,
            reason: self.reason().into_owned(),
            packet_length: self.packet_length,
            addr_family: self.addr_family,
            protocol: self.protocol,
            config_generation: self.config_generation,
            fib_generation: self.fib_generation,
            src_ip: self.src_ip.map(|ip| ip.to_string()).unwrap_or_default(),
            dst_ip: self.dst_ip.map(|ip| ip.to_string()).unwrap_or_default(),
            src_port: self.src_port,
            dst_port: self.dst_port,
            from_zone: zone_name_for(self.from_zone_id),
            to_zone: zone_name_for(self.to_zone_id),
            rule_name: self.rule_name.as_deref().unwrap_or_default().to_string(),
            pool_name: self.pool_name.as_deref().unwrap_or_default().to_string(),
        }
    }
}

/// #5289: compact POD last-forwarding-resolution slot. `ForwardingResolution`
/// is `Copy`; `ResolutionDebug` clones its POD fields (`Option<IpAddr>` /
/// `u16` / `i32` / `Option<u16>`) with no heap allocation. The
/// `PacketResolution` (with formatted `String`s) is rebuilt on the control
/// thread via [`ResolutionEvent::to_resolution`].
#[derive(Clone)]
pub(crate) struct ResolutionEvent {
    pub(in crate::afxdp) mono: Instant,
    pub(in crate::afxdp) resolution: ForwardingResolution,
    pub(in crate::afxdp) debug: Option<ResolutionDebug>,
}

impl ResolutionEvent {
    pub(in crate::afxdp) fn to_resolution(&self, forwarding: &ForwardingState) -> PacketResolution {
        self.resolution.status(self.debug.as_ref(), forwarding)
    }
}

/// #5289: single captured monotonic<->wall-clock anchor. Taken ONCE per
/// status read on the control thread; every ring event's monotonic
/// `Instant` is converted through it so all timestamps share one basis.
#[derive(Clone, Copy)]
pub(crate) struct MonoWallAnchor {
    now_mono: Instant,
    now_wall: DateTime<Utc>,
}

impl MonoWallAnchor {
    pub(crate) fn capture() -> Self {
        Self {
            now_mono: Instant::now(),
            now_wall: Utc::now(),
        }
    }

    /// Convert a monotonic sample to wall-clock: `wall = now_wall - (now_mono - mono)`.
    pub(crate) fn wall_clock(&self, mono: Instant) -> DateTime<Utc> {
        if mono <= self.now_mono {
            let elapsed = self.now_mono.duration_since(mono);
            self.now_wall - chrono::Duration::from_std(elapsed).unwrap_or_default()
        } else {
            // Event captured after the anchor (a worker pushed while we were
            // reading) — clamp forward rather than underflow.
            let ahead = mono.duration_since(self.now_mono);
            self.now_wall + chrono::Duration::from_std(ahead).unwrap_or_default()
        }
    }
}

/// #5289: per-worker exception ring with an embedded per-(reason,key)
/// sampler. Owned behind a PER-WORKER `Mutex` (no cross-worker contention).
pub(crate) struct ExceptionEventRing {
    events: VecDeque<ExceptionEvent>,
    gate_keys: [u64; EXCEPTION_GATE_SLOTS],
    gate_seen: [Option<Instant>; EXCEPTION_GATE_SLOTS],
    /// Count of sampler-suppressed terminal packets (diagnostic only).
    suppressed: u64,
}

impl Default for ExceptionEventRing {
    fn default() -> Self {
        Self {
            events: VecDeque::with_capacity(EXCEPTION_RING_CAPACITY),
            gate_keys: [0; EXCEPTION_GATE_SLOTS],
            gate_seen: [None; EXCEPTION_GATE_SLOTS],
            suppressed: 0,
        }
    }
}

impl ExceptionEventRing {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Sampler gate. Returns `true` if `(key, now)` is admitted; `false`
    /// (and bumps `suppressed`) when an identical `(reason, 5-tuple)` was
    /// admitted within `EXCEPTION_SAMPLE_WINDOW`. O(1), no allocation.
    /// On a slot collision (different key, same slot) it fails OPEN
    /// (admits) — the ring capacity still bounds memory.
    pub(in crate::afxdp) fn admit(&mut self, key: u64, now: Instant) -> bool {
        let slot = (key as usize) & (EXCEPTION_GATE_SLOTS - 1);
        if self.gate_keys[slot] == key
            && let Some(seen) = self.gate_seen[slot]
            && now.duration_since(seen) < EXCEPTION_SAMPLE_WINDOW
        {
            self.suppressed = self.suppressed.saturating_add(1);
            return false;
        }
        self.gate_keys[slot] = key;
        self.gate_seen[slot] = Some(now);
        true
    }

    /// Push an already-built event, evicting the oldest at capacity.
    pub(in crate::afxdp) fn push(&mut self, event: ExceptionEvent) {
        if self.events.len() >= EXCEPTION_RING_CAPACITY {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &ExceptionEvent> {
        self.events.iter()
    }

    // Read accessors used only by the ring's unit tests (the production drain
    // path goes through `iter()`); gated so release builds see no dead code.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.events.len()
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn back(&self) -> Option<&ExceptionEvent> {
        self.events.back()
    }

    #[cfg(test)]
    pub(crate) fn front(&self) -> Option<&ExceptionEvent> {
        self.events.front()
    }

    #[cfg(test)]
    pub(crate) fn suppressed(&self) -> u64 {
        self.suppressed
    }

    pub(crate) fn clear(&mut self) {
        self.events.clear();
        self.gate_keys = [0; EXCEPTION_GATE_SLOTS];
        self.gate_seen = [None; EXCEPTION_GATE_SLOTS];
        self.suppressed = 0;
    }
}

/// Cheap sampler key over (reason, 5-tuple). Hashes the reason bytes (so
/// repeats of the same reason string dedupe regardless of allocation) plus
/// the IP/port/protocol tuple.
fn exception_sample_key(
    reason: &str,
    meta: Option<UserspaceDpMeta>,
    debug: Option<&ResolutionDebug>,
) -> u64 {
    exception_sample_key_parts(reason, "", meta, debug)
}

/// Sampler key over (reason ++ suffix, 5-tuple). Hashing the base reason and
/// the `'static` suffix as two adjacent parts (rather than a joined `String`)
/// keeps the record path alloc-free while still giving each distinct
/// `(base, suffix)` its own dedup key — e.g. `slow_path` + `_rate_limited`
/// and `slow_path` + `_queue_full` sample independently, exactly as the old
/// `format!`-joined reasons did (#6101). Passing `suffix == ""` reproduces
/// the plain `exception_sample_key` hash byte-for-byte.
fn exception_sample_key_parts(
    reason: &str,
    suffix: &str,
    meta: Option<UserspaceDpMeta>,
    debug: Option<&ResolutionDebug>,
) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = rustc_hash::FxHasher::default();
    reason.hash(&mut h);
    if !suffix.is_empty() {
        suffix.hash(&mut h);
    }
    if let Some(d) = debug {
        match d.src_ip {
            Some(IpAddr::V4(a)) => a.octets().hash(&mut h),
            Some(IpAddr::V6(a)) => a.octets().hash(&mut h),
            None => 0u8.hash(&mut h),
        }
        match d.dst_ip {
            Some(IpAddr::V4(a)) => a.octets().hash(&mut h),
            Some(IpAddr::V6(a)) => a.octets().hash(&mut h),
            None => 0u8.hash(&mut h),
        }
        d.src_port.hash(&mut h);
        d.dst_port.hash(&mut h);
    }
    if let Some(m) = meta {
        m.protocol.hash(&mut h);
        m.addr_family.hash(&mut h);
    }
    h.finish()
}

/// #5289: build a control-thread NOTICE event with a fully dynamic reason
/// and interface name (spawn / tunnel-setup failures). All packet fields
/// default. Not on the packet path, so the `Arc<str>` allocations are fine.
/// Pushed directly (sampler bypassed) via [`push_recent_exception`].
pub(crate) fn control_notice_event(interface: &str, reason: String) -> ExceptionEvent {
    ExceptionEvent {
        mono: Instant::now(),
        reason: "",
        reason_suffix: "",
        reason_owned: Some(Arc::from(reason)),
        interface: Arc::from(interface),
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        ifindex: 0,
        ingress_ifindex: 0,
        packet_length: 0,
        addr_family: 0,
        protocol: 0,
        config_generation: 0,
        fib_generation: 0,
        src_ip: None,
        dst_ip: None,
        src_port: 0,
        dst_port: 0,
        from_zone_id: None,
        to_zone_id: None,
        rule_name: None,
        pool_name: None,
    }
}

/// Build the compact POD event. No `String` allocation, no `Utc::now()`.
fn build_exception_event(
    now: Instant,
    binding: &BindingIdentity,
    reason: &'static str,
    packet_length: u32,
    meta: Option<UserspaceDpMeta>,
    debug: Option<&ResolutionDebug>,
) -> ExceptionEvent {
    ExceptionEvent {
        mono: now,
        reason,
        reason_suffix: "",
        reason_owned: None,
        interface: binding.interface.clone(),
        slot: binding.slot,
        queue_id: binding.queue_id,
        worker_id: binding.worker_id,
        ifindex: binding.ifindex,
        ingress_ifindex: debug.map(|d| d.ingress_ifindex).unwrap_or_default(),
        packet_length,
        addr_family: meta.map(|m| m.addr_family).unwrap_or(0),
        protocol: meta.map(|m| m.protocol).unwrap_or(0),
        config_generation: meta.map(|m| m.config_generation).unwrap_or(0),
        fib_generation: meta.map(|m| m.fib_generation).unwrap_or(0),
        src_ip: debug.and_then(|d| d.src_ip),
        dst_ip: debug.and_then(|d| d.dst_ip),
        src_port: debug.map(|d| d.src_port).unwrap_or_default(),
        dst_port: debug.map(|d| d.dst_port).unwrap_or_default(),
        from_zone_id: debug.and_then(|d| d.from_zone),
        to_zone_id: debug.and_then(|d| d.to_zone),
        rule_name: None,
        pool_name: None,
    }
}

/// #4743: classify a NoRoute destination as a MARTIAN address — one that a
/// firewall must never forward and that has no legitimate route. Mirrors the
/// neighbor-warm never-warm predicate (`coordinator::mod`): IPv4
/// unspecified/loopback/multicast/broadcast, IPv6
/// unspecified/loopback/multicast. IPv6 has no broadcast. Used only to
/// sub-classify an already-decided NoRoute drop; it does not itself drop.
pub(in crate::afxdp) fn is_martian_dst(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_unspecified() || v4.is_loopback() || v4.is_multicast() || v4.is_broadcast()
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_unspecified() || v6.is_loopback() || v6.is_multicast()
        }
    }
}

/// #5289: record a terminal-packet exception into the (per-worker) POD
/// ring. NO `String` allocation and NO `Utc::now()` on this path — the
/// event carries a `&'static str` reason, an `Arc<str>` interface clone,
/// `Copy` IPs, numeric zone ids and a monotonic `Instant`. A
/// per-(reason,5-tuple) sampler suppresses a flood of identical packets.
/// `_forwarding` is retained in the signature (callers pass it) but no
/// longer read here — zone-id->name resolution moved to the control-thread
/// `ExceptionEvent::to_status`.
pub(super) fn record_exception(
    recent_exceptions: &Arc<Mutex<ExceptionEventRing>>,
    binding: &BindingIdentity,
    reason: &'static str,
    packet_length: u32,
    meta: Option<UserspaceDpMeta>,
    debug: Option<&ResolutionDebug>,
    _forwarding: &ForwardingState,
) {
    let now = Instant::now();
    let key = exception_sample_key(reason, meta, debug);
    if let Ok(mut ring) = recent_exceptions.lock()
        && ring.admit(key, now)
    {
        ring.push(build_exception_event(
            now,
            binding,
            reason,
            packet_length,
            meta,
            debug,
        ));
    }
}

/// #5289: record a terminal-packet exception whose reason is GENUINELY
/// DYNAMIC — a runtime-formatted string (`format!("...:{id}:{err}")`) that
/// cannot be expressed as a `&'static` base plus a fixed `&'static` suffix.
/// The only such caller is the `cfg!(feature = "debug-log")` forward-tuple
/// mismatch diagnostic in `tx/dispatch/mod.rs` (compiled in, but the reason
/// is built and this fn is reached only when that feature is enabled).
/// The reason is stored as an owned `Arc<str>` (one small allocation,
/// sampler-gated).
///
/// Do NOT use this for a `base + '_static_suffix'` reason: the slow-path
/// reinject-failure sites (`_rate_limited` / `_queue_full` /
/// `_slow_path_mtu_exceeded` / `_enqueue_failed`) use
/// [`record_exception_suffixed`], which records those alloc-free (#6101);
/// the plain `&'static` reason path uses [`record_exception`] and likewise
/// allocates nothing.
pub(super) fn record_exception_owned(
    recent_exceptions: &Arc<Mutex<ExceptionEventRing>>,
    binding: &BindingIdentity,
    reason: &str,
    packet_length: u32,
    meta: Option<UserspaceDpMeta>,
    debug: Option<&ResolutionDebug>,
) {
    let now = Instant::now();
    let key = exception_sample_key(reason, meta, debug);
    if let Ok(mut ring) = recent_exceptions.lock()
        && ring.admit(key, now)
    {
        let mut event = build_exception_event(now, binding, "", packet_length, meta, debug);
        event.reason_owned = Some(Arc::from(reason));
        ring.push(event);
    }
}

/// #6101: record a terminal-packet exception whose reason is a `&'static`
/// base joined with one of a fixed set of `&'static` outcome suffixes
/// (`_rate_limited` / `_queue_full` / `_slow_path_mtu_exceeded` /
/// `_enqueue_failed`). Both halves are `Copy` `&'static str`, so the record
/// path stores them WITHOUT the per-event `format!`/`String` allocation the
/// old `record_exception_owned(&format!("{reason}_rate_limited"))` sites paid
/// on a slow-path reinject-failure flood. The operator-visible reason text is
/// reconstructed identically on the control thread by
/// [`ExceptionEvent::reason`] (`concat(reason, reason_suffix)`).
pub(super) fn record_exception_suffixed(
    recent_exceptions: &Arc<Mutex<ExceptionEventRing>>,
    binding: &BindingIdentity,
    reason: &'static str,
    suffix: &'static str,
    packet_length: u32,
    meta: Option<UserspaceDpMeta>,
    debug: Option<&ResolutionDebug>,
) {
    let now = Instant::now();
    let key = exception_sample_key_parts(reason, suffix, meta, debug);
    if let Ok(mut ring) = recent_exceptions.lock()
        && ring.admit(key, now)
    {
        let mut event = build_exception_event(now, binding, reason, packet_length, meta, debug);
        event.reason_suffix = suffix;
        ring.push(event);
    }
}

pub(super) fn record_source_nat_exception(
    recent_exceptions: &Arc<Mutex<ExceptionEventRing>>,
    binding: &BindingIdentity,
    packet_length: u32,
    meta: Option<UserspaceDpMeta>,
    debug: Option<&ResolutionDebug>,
    _forwarding: &ForwardingState,
    failure: &SourceNatFailure,
) {
    let reason = failure.exception_reason();
    let now = Instant::now();
    let key = exception_sample_key(reason, meta, debug);
    if let Ok(mut ring) = recent_exceptions.lock()
        && ring.admit(key, now)
    {
        let mut event = build_exception_event(now, binding, reason, packet_length, meta, debug);
        // Only the SNAT-failure path carries rule/pool names. `Arc<str>`
        // clone (one small allocation) is gated by the sampler above, so a
        // flood cannot allocate per packet.
        if !failure.rule_name.is_empty() {
            event.rule_name = Some(Arc::from(failure.rule_name.as_str()));
        }
        if !failure.pool_name.is_empty() {
            event.pool_name = Some(Arc::from(failure.pool_name.as_str()));
        }
        ring.push(event);
    }
}

/// #1187: counter sink for `record_disposition` /
/// `record_forwarding_disposition`. Hot callers (worker poll path)
/// pass `Hot(&mut BatchCounters)` so per-packet increments land in
/// the per-poll-tick batch and flush via `BatchCounters::flush()`.
/// Cold callers (coordinator/inject.rs RPC injection) pass
/// `Cold(&BindingLiveState)` and write directly to atomics — they're
/// not on the worker per-packet hot path so MESI thrash is not a
/// concern there.
pub(super) enum DispositionCounters<'a> {
    Hot(&'a mut BatchCounters),
    Cold(&'a BindingLiveState),
}

impl DispositionCounters<'_> {
    /// #3651: true on the worker per-packet hot path (`Hot`), false for the
    /// cold RPC-inject path (`Cold`). Per-zone traffic accounting only runs on
    /// `Hot` because the coalescer's thread-local is folded into the shared
    /// store from the worker RX-batch flush — the control thread that drives
    /// `Cold` never reaches that flush, so its accumulation would be lost.
    #[inline]
    fn is_hot(&self) -> bool {
        matches!(self, Self::Hot(_))
    }

    #[inline]
    fn bump_validated(&mut self, packet_length: u32) {
        match self {
            Self::Hot(c) => {
                c.touched = true;
                c.validated_packets += 1;
                c.validated_bytes += packet_length as u64;
            }
            Self::Cold(live) => {
                live.validated_packets.fetch_add(1, Ordering::Relaxed);
                live.validated_bytes
                    .fetch_add(packet_length as u64, Ordering::Relaxed);
            }
        }
    }
    #[inline]
    fn bump_exception(&mut self) {
        match self {
            Self::Hot(c) => {
                c.touched = true;
                c.exception_packets += 1;
            }
            Self::Cold(live) => {
                live.exception_packets.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    #[inline]
    fn bump_local_delivery(&mut self) {
        match self {
            Self::Hot(c) => {
                c.touched = true;
                c.local_delivery_packets += 1;
            }
            Self::Cold(live) => {
                live.local_delivery_packets.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    #[inline]
    fn bump_forward_candidate(&mut self) {
        match self {
            Self::Hot(c) => {
                c.touched = true;
                c.forward_candidate_packets += 1;
            }
            // #9956 F-051 why-not: the Cold arm serves RPC-injected forwards
            // (coordinator/inject.rs, test-only paths) that never cross the
            // poll chokepoint, so an injected forward is globally counted but
            // never flowless-attributed. Reconciliation scope is
            // userspace-forwarded wire transit only, by design.
            Self::Cold(live) => {
                live.forward_candidate_packets
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    #[inline]
    fn bump_policy_denied(&mut self) {
        match self {
            Self::Hot(c) => {
                c.touched = true;
                c.policy_denied_packets += 1;
            }
            Self::Cold(live) => {
                live.policy_denied_packets.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    #[inline]
    fn bump_route_miss(&mut self) {
        match self {
            Self::Hot(c) => {
                c.touched = true;
                c.route_miss_packets += 1;
            }
            Self::Cold(live) => {
                live.route_miss_packets.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    /// #4743: a NoRoute drop whose destination is a martian address. A strict
    /// sub-breakout of `bump_route_miss` — the caller bumps BOTH, so
    /// `martian_dropped <= route_miss_packets` always holds (mirrors how
    /// `screen_reason_drops` break out `screen_drops`).
    #[inline]
    fn bump_martian(&mut self) {
        match self {
            Self::Hot(c) => {
                c.touched = true;
                c.martian_dropped += 1;
            }
            Self::Cold(live) => {
                live.martian_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    #[inline]
    fn bump_neighbor_miss(&mut self) {
        match self {
            Self::Hot(c) => {
                c.touched = true;
                c.neighbor_miss_packets += 1;
            }
            Self::Cold(live) => {
                live.neighbor_miss_packets.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    #[inline]
    fn bump_discard_route(&mut self) {
        match self {
            Self::Hot(c) => {
                c.touched = true;
                c.discard_route_packets += 1;
            }
            Self::Cold(live) => {
                live.discard_route_packets.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    #[inline]
    fn bump_next_table(&mut self) {
        match self {
            Self::Hot(c) => {
                c.touched = true;
                c.next_table_packets += 1;
            }
            Self::Cold(live) => {
                live.next_table_packets.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    #[inline]
    fn bump_table_unavailable(&mut self) {
        match self {
            Self::Hot(c) => {
                c.touched = true;
                c.table_unavailable_packets += 1;
            }
            Self::Cold(live) => {
                live.table_unavailable_packets.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

pub(super) fn record_disposition(
    binding: &BindingIdentity,
    live: &BindingLiveState,
    mut counters: DispositionCounters<'_>,
    disposition: PacketDisposition,
    packet_length: u32,
    meta: Option<UserspaceDpMeta>,
    recent_exceptions: &Arc<Mutex<ExceptionEventRing>>,
    forwarding: &ForwardingState,
) {
    match disposition {
        PacketDisposition::Valid => {
            counters.bump_validated(packet_length);
        }
        PacketDisposition::NoSnapshot => {
            counters.bump_exception();
            record_exception(
                recent_exceptions,
                binding,
                "no_snapshot",
                packet_length,
                meta,
                None,
                forwarding,
            );
        }
        PacketDisposition::ConfigGenerationMismatch => {
            counters.bump_exception();
            // config_gen_mismatches is reconcile-only; deferred from
            // batch per plan §2. Direct atomic on `live`.
            live.config_gen_mismatches.fetch_add(1, Ordering::Relaxed);
            record_exception(
                recent_exceptions,
                binding,
                "config_generation_mismatch",
                packet_length,
                meta,
                None,
                forwarding,
            );
        }
        PacketDisposition::FibGenerationMismatch => {
            counters.bump_exception();
            // fib_gen_mismatches is reconcile-only; deferred per plan §2.
            live.fib_gen_mismatches.fetch_add(1, Ordering::Relaxed);
            record_exception(
                recent_exceptions,
                binding,
                "fib_generation_mismatch",
                packet_length,
                meta,
                None,
                forwarding,
            );
        }
        PacketDisposition::UnsupportedPacket => {
            counters.bump_exception();
            // unsupported_packets is reconcile-/upgrade-window only;
            // deferred per plan §2.
            live.unsupported_packets.fetch_add(1, Ordering::Relaxed);
            record_exception(
                recent_exceptions,
                binding,
                "unsupported_packet",
                packet_length,
                meta,
                None,
                forwarding,
            );
        }
    }
}

pub(super) fn record_forwarding_disposition(
    binding: &BindingIdentity,
    mut counters: DispositionCounters<'_>,
    resolution: ForwardingResolution,
    packet_length: u32,
    meta: Option<UserspaceDpMeta>,
    debug: Option<&ResolutionDebug>,
    recent_exceptions: &Arc<Mutex<ExceptionEventRing>>,
    last_resolution: &Arc<Mutex<Option<ResolutionEvent>>>,
    forwarding: &ForwardingState,
) {
    match resolution.disposition {
        ForwardingDisposition::LocalDelivery => {
            counters.bump_local_delivery();
        }
        ForwardingDisposition::ForwardCandidate | ForwardingDisposition::FabricRedirect => {
            counters.bump_forward_candidate();
            // #3651: per-zone traffic volume for forward paths that resolve
            // through record_forwarding_disposition (tunnel decap, next-table,
            // fabric redirect). Hot-path only (the Cold RPC-inject path's
            // thread-local coalescer is never flushed); needs the shim meta for
            // the ingress zone.
            if counters.is_hot()
                && let Some(m) = meta
            {
                crate::afxdp::zone_counters::record_zone_traffic(
                    &forwarding.zone_counter_slot_map,
                    m.ingress_zone,
                    forwarding.egress_zone_id(resolution.egress_ifindex),
                    m.pkt_len as u64,
                );
            }
        }
        ForwardingDisposition::HAInactive => {
            update_last_resolution(last_resolution, resolution, debug, forwarding);
            counters.bump_exception();
            record_exception(
                recent_exceptions,
                binding,
                "ha_inactive",
                packet_length,
                meta,
                debug,
                forwarding,
            );
        }
        ForwardingDisposition::PolicyDenied => {
            update_last_resolution(last_resolution, resolution, debug, forwarding);
            counters.bump_policy_denied();
            record_exception(
                recent_exceptions,
                binding,
                "policy_denied",
                packet_length,
                meta,
                debug,
                forwarding,
            );
        }
        ForwardingDisposition::NoRoute => {
            update_last_resolution(last_resolution, resolution, debug, forwarding);
            counters.bump_route_miss();
            // #4743: a NoRoute drop whose destination is a martian address is
            // ALSO counted distinctly so an operator can tell it apart from an
            // ordinary route miss (and correlate it with the filter-`accept`
            // log). A martian dst simply misses the FIB and drops as NoRoute —
            // there is no separate martian rejection site — so this classifies
            // off the resolution's destination (from the debug tuple) and bumps
            // martian_dropped IN ADDITION to route_miss_packets.
            if debug
                .and_then(|d| d.dst_ip)
                .is_some_and(is_martian_dst)
            {
                counters.bump_martian();
            }
            record_exception(
                recent_exceptions,
                binding,
                "no_route",
                packet_length,
                meta,
                debug,
                forwarding,
            );
        }
        ForwardingDisposition::MissingNeighbor => {
            update_last_resolution(last_resolution, resolution, debug, forwarding);
            counters.bump_neighbor_miss();
            record_exception(
                recent_exceptions,
                binding,
                "missing_neighbor",
                packet_length,
                meta,
                debug,
                forwarding,
            );
        }
        ForwardingDisposition::DiscardRoute => {
            update_last_resolution(last_resolution, resolution, debug, forwarding);
            counters.bump_discard_route();
            record_exception(
                recent_exceptions,
                binding,
                "discard_route",
                packet_length,
                meta,
                debug,
                forwarding,
            );
        }
        ForwardingDisposition::NextTableUnsupported => {
            update_last_resolution(last_resolution, resolution, debug, forwarding);
            counters.bump_next_table();
            record_exception(
                recent_exceptions,
                binding,
                "next_table_unsupported",
                packet_length,
                meta,
                debug,
                forwarding,
            );
        }
        ForwardingDisposition::TableUnavailable => {
            update_last_resolution(last_resolution, resolution, debug, forwarding);
            counters.bump_table_unavailable();
            record_exception(
                recent_exceptions,
                binding,
                "table_unavailable",
                packet_length,
                meta,
                debug,
                forwarding,
            );
        }
    }
}

/// #5289: cache the most-recent forwarding resolution as a compact POD
/// `ResolutionEvent` (monotonic `Instant`, `Copy` `ForwardingResolution`,
/// cloned POD `ResolutionDebug`). No `String` formatting and no
/// `Utc::now()` on the packet path — the `PacketResolution` is rebuilt on
/// the control thread from the newest per-worker slot. `_forwarding` is
/// retained in the signature (callers pass it) but the zone/IP formatting
/// it fed now happens in `ResolutionEvent::to_resolution`.
pub(super) fn update_last_resolution(
    last_resolution: &Arc<Mutex<Option<ResolutionEvent>>>,
    resolution: ForwardingResolution,
    debug: Option<&ResolutionDebug>,
    _forwarding: &ForwardingState,
) {
    if let Ok(mut last) = last_resolution.lock() {
        *last = Some(ResolutionEvent {
            mono: Instant::now(),
            resolution,
            debug: debug.cloned(),
        });
    }
}

#[cfg(test)]
impl ExceptionEvent {
    /// Test-only constructor: a minimal POD event with a caller-controlled
    /// monotonic timestamp, `&'static` reason and interface tag. Used to
    /// exercise the cross-worker ring merge (`Coordinator::recent_exceptions`)
    /// deterministically without touching `Instant::now()` ordering. All
    /// packet/zone fields default; `reason_suffix`/`reason_owned` are empty.
    pub(in crate::afxdp) fn for_test(mono: Instant, reason: &'static str, interface: &str) -> Self {
        ExceptionEvent {
            mono,
            reason,
            reason_suffix: "",
            reason_owned: None,
            interface: Arc::from(interface),
            slot: 0,
            queue_id: 0,
            worker_id: 0,
            ifindex: 0,
            ingress_ifindex: 0,
            packet_length: 0,
            addr_family: 0,
            protocol: 0,
            config_generation: 0,
            fib_generation: 0,
            src_ip: None,
            dst_ip: None,
            src_port: 0,
            dst_port: 0,
            from_zone_id: None,
            to_zone_id: None,
            rule_name: None,
            pool_name: None,
        }
    }
}

#[cfg(test)]
impl ResolutionEvent {
    /// Test-only constructor: a resolution slot with a caller-controlled
    /// monotonic timestamp and a distinguishing `egress_ifindex` (surfaced in
    /// the reconstructed `PacketResolution.egress_ifindex`, so a merge test
    /// can assert which slot's event won the newest-by-`mono` selection).
    pub(in crate::afxdp) fn for_test(mono: Instant, egress_ifindex: i32) -> Self {
        ResolutionEvent {
            mono,
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex,
                tx_ifindex: egress_ifindex,
                tunnel_endpoint_id: 0,
                next_hop: None,
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
            },
            debug: None,
        }
    }
}

#[cfg(test)]
mod tests_5289_exception_ring {
    //! #5289 fail-on-revert coverage for the per-worker POD exception ring.
    //!
    //! These pin the two behavioural properties that distinguish the fix
    //! from the retired inline-global-format path:
    //!   * `record_exception` writes a compact POD event (static `reason`, no
    //!     owned reason String, `Copy` `IpAddr`s, NUMERIC zone ids) and a
    //!     per-(reason,5-tuple) sampler suppresses an identical flood so the
    //!     ring does NOT advance every packet; and
    //!   * the control/status thread reconstructs the exact operator-visible
    //!     `ExceptionStatus` (reason/IP/zone strings + wall-clock) from the
    //!     POD event + monotonic->wall anchor.
    //! Neutralising the sampler (admit-always) or the deferred formatting
    //! makes these ASSERTIONS fail (not merely a build break).
    use super::*;
    use std::net::Ipv4Addr;

    fn ident() -> BindingIdentity {
        BindingIdentity {
            slot: 2,
            queue_id: 3,
            worker_id: 4,
            interface: Arc::<str>::from("ge-0-0-2"),
            ifindex: 9,
        }
    }

    fn debug_tuple() -> ResolutionDebug {
        ResolutionDebug {
            ingress_ifindex: 7,
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            dst_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            src_port: 1111,
            dst_port: 2222,
            from_zone: Some(3),
            to_zone: Some(4),
        }
    }

    // (a) POD record path + sampler suppression.
    #[test]
    fn record_exception_writes_pod_event_and_samples_flood() {
        let ring = Arc::new(Mutex::new(ExceptionEventRing::new()));
        let binding = ident();
        let forwarding = ForwardingState::default();
        let debug = debug_tuple();

        // A flood of 8 identical terminal packets.
        for _ in 0..8 {
            record_exception(
                &ring,
                &binding,
                "policy_denied",
                128,
                None,
                Some(&debug),
                &forwarding,
            );
        }

        let g = ring.lock().expect("ring");
        assert_eq!(
            g.len(),
            1,
            "an identical (reason,5-tuple) flood must be sampled to a single ring entry \
             (the retired inline path pushed one per packet)"
        );
        assert_eq!(g.suppressed(), 7, "the other 7 packets are counted as suppressed");

        let ev = g.back().expect("event");
        // Compact POD invariants: no String/Utc on the record path.
        assert_eq!(ev.reason, "policy_denied");
        assert!(
            ev.reason_owned.is_none(),
            "the hot path stores a &'static reason, never an owned String"
        );
        assert_eq!(ev.src_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(ev.dst_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
        assert_eq!(ev.from_zone_id, Some(3), "zones stored as numeric ids, not names");
        assert_eq!(ev.to_zone_id, Some(4));
        assert_eq!(ev.ifindex, 9);
        assert_eq!(ev.ingress_ifindex, 7);
        assert_eq!(ev.packet_length, 128);
        assert_eq!(&*ev.interface, "ge-0-0-2");

        // A DISTINCT reason is not suppressed by the sampler.
        drop(g);
        record_exception(&ring, &binding, "no_route", 64, None, Some(&debug), &forwarding);
        assert_eq!(ring.lock().expect("ring").len(), 2);
    }

    // (b) Control-thread reconstruction round-trip vs the old formatted output.
    #[test]
    fn to_status_reconstructs_human_readable_exception() {
        let binding = ident();
        let mut forwarding = ForwardingState::default();
        forwarding.zone_id_to_name.insert(3, "trust".to_string());
        forwarding.zone_id_to_name.insert(4, "untrust".to_string());
        let debug = debug_tuple();

        let ring = Arc::new(Mutex::new(ExceptionEventRing::new()));
        record_exception(
            &ring,
            &binding,
            "policy_denied",
            128,
            None,
            Some(&debug),
            &forwarding,
        );

        let anchor = MonoWallAnchor::capture();
        let ev = ring.lock().expect("ring").back().expect("event").clone();
        let status = ev.to_status(anchor, &forwarding);

        // Exactly the strings the retired build_exception_status produced.
        assert_eq!(status.reason, "policy_denied");
        assert_eq!(status.interface, "ge-0-0-2");
        assert_eq!(status.ifindex, 9);
        assert_eq!(status.ingress_ifindex, 7);
        assert_eq!(status.src_ip, "10.0.0.1");
        assert_eq!(status.dst_ip, "10.0.0.2");
        assert_eq!(status.src_port, 1111);
        assert_eq!(status.dst_port, 2222);
        assert_eq!(status.from_zone, "trust", "numeric zone id resolves to name on the status thread");
        assert_eq!(status.to_zone, "untrust");
        assert_eq!(status.slot, 2);
        assert_eq!(status.queue_id, 3);
        assert_eq!(status.worker_id, 4);
        assert_eq!(status.packet_length, 128);

        // Monotonic->wall reconstruction lands within a second of "now".
        let now = Utc::now();
        let skew = (now - status.timestamp).num_milliseconds().abs();
        assert!(skew < 1000, "reconstructed wall-clock within 1s of now, got skew {skew}ms");
    }

    // SNAT-failure carries rule/pool names as Arc<str>, resolved on the status thread.
    #[test]
    fn source_nat_exception_round_trips_rule_and_pool() {
        let binding = ident();
        let forwarding = ForwardingState::default();
        let ring = Arc::new(Mutex::new(ExceptionEventRing::new()));
        let failure = crate::nat::SourceNatFailure {
            rule_name: "snat-rule-1".to_string(),
            pool_name: "pool-a".to_string(),
            reason: crate::nat::SourceNatFailureReason::AllocatorExhausted,
        };
        record_source_nat_exception(&ring, &binding, 96, None, None, &forwarding, &failure);
        let ev = ring.lock().expect("ring").back().expect("event").clone();
        assert_eq!(ev.reason, failure.exception_reason());
        assert_eq!(ev.rule_name.as_deref(), Some("snat-rule-1"));
        assert_eq!(ev.pool_name.as_deref(), Some("pool-a"));
        let status = ev.to_status(MonoWallAnchor::capture(), &forwarding);
        assert_eq!(status.rule_name, "snat-rule-1");
        assert_eq!(status.pool_name, "pool-a");
    }

    // #6101 (item 1) fail-on-revert: the slow-path reinject-failure sites
    // record a `&'static` base reason + a `&'static` suffix ALLOC-FREE (no
    // per-event `format!`/`String`), and the control thread reconstructs the
    // byte-identical `"{reason}{suffix}"` operator text. Reverting the record
    // path to `record_exception_owned(&format!("{reason}_rate_limited"))` sets
    // `reason_owned` (fails the alloc-free `reason_owned.is_none()` assertion)
    // and empties `reason`/`reason_suffix` (fails the static-part assertions);
    // dropping the suffix from the joined string fails the reconstruction.
    #[test]
    fn record_exception_suffixed_is_alloc_free_and_reconstructs_reason() {
        let forwarding = ForwardingState::default();
        let binding = ident();

        // The (base, suffix) pairs the `slow_path.rs` reinject-failure sites
        // emit (both slow-path bases × the four outcome suffixes), each paired
        // with the historical `format!` output they MUST stay byte-identical to.
        let cases = [
            ("slow_path", "_rate_limited", "slow_path_rate_limited"),
            ("slow_path", "_queue_full", "slow_path_queue_full"),
            (
                "slow_path",
                "_slow_path_mtu_exceeded",
                "slow_path_slow_path_mtu_exceeded",
            ),
            ("slow_path", "_enqueue_failed", "slow_path_enqueue_failed"),
            (
                "forward_build_slow_path",
                "_rate_limited",
                "forward_build_slow_path_rate_limited",
            ),
        ];

        for (base, suffix, expected) in cases {
            let ring = Arc::new(Mutex::new(ExceptionEventRing::new()));
            record_exception_suffixed(&ring, &binding, base, suffix, 128, None, None);

            let g = ring.lock().expect("ring");
            let ev = g.back().expect("event");
            // Alloc-free record path: base + suffix are stored as the two
            // `&'static` parts, NOT joined into an owned String.
            assert_eq!(ev.reason, base, "base reason stored as the static literal");
            assert_eq!(
                ev.reason_suffix, suffix,
                "suffix stored as the static literal"
            );
            assert!(
                ev.reason_owned.is_none(),
                "the record path must NOT allocate a per-event String \
                 (reason_owned stays None) for {expected}"
            );
            // Byte-identical operator-visible reconstruction, both via the
            // `reason()` accessor and the fully rendered `ExceptionStatus`.
            assert_eq!(
                ev.reason(),
                expected,
                "reconstructed reason == the retired format! output"
            );
            let status = ev.to_status(MonoWallAnchor::capture(), &forwarding);
            assert_eq!(
                status.reason, expected,
                "ExceptionStatus.reason byte-identical to the old formatted text"
            );
        }
    }

    // #6101 (item 1): the sampler key folds in the suffix, so an identical
    // (base,suffix) flood collapses to one entry while a DISTINCT suffix on
    // the same base is admitted as its own event — matching the pre-fix
    // `format!`-joined reasons, which the sampler keyed on in full.
    #[test]
    fn record_exception_suffixed_samples_flood_but_keys_include_suffix() {
        let binding = ident();
        let ring = Arc::new(Mutex::new(ExceptionEventRing::new()));

        // An identical (base,suffix) flood is sampled down to one entry.
        for _ in 0..5 {
            record_exception_suffixed(&ring, &binding, "slow_path", "_rate_limited", 64, None, None);
        }
        assert_eq!(
            ring.lock().expect("ring").len(),
            1,
            "an identical suffixed flood is sampled to a single ring entry"
        );

        // A DISTINCT suffix on the same base is a DISTINCT sampler key.
        record_exception_suffixed(&ring, &binding, "slow_path", "_queue_full", 64, None, None);
        let g = ring.lock().expect("ring");
        assert_eq!(
            g.len(),
            2,
            "a distinct suffix is not collapsed into the prior key"
        );
        let reasons: Vec<String> = g.iter().map(|e| e.reason().into_owned()).collect();
        assert_eq!(
            reasons,
            vec!["slow_path_rate_limited", "slow_path_queue_full"]
        );
    }
}
