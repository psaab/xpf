use super::{
    BindingStatus, ConfigSnapshot, ExceptionStatus, HAGroupStatus, InjectPacketRequest,
    InterfaceSnapshot, PacketResolution, SessionDeltaInfo, ZoneSnapshot,
};
use crate::nat::{
    DnatTable, NatDecision, SourceNatFailure, SourceNatLookup, SourceNatRule, StaticNatTable,
    match_source_nat, parse_source_nat_rules_with_previous,
    release_source_nat_allocation_for_worker, reserve_synced_source_nat_allocation_for_worker,
    rollback_source_nat_allocation_for_worker,
};
use crate::nat64::{Nat64ReverseInfo, Nat64State};
use crate::nptv6::Nptv6State;
use crate::policy::{
    AppCatalog, PolicyAction, PolicyCounterStore, PolicyState, evaluate_policy,
    parse_policy_state_with_counters,
};
use crate::prefix::{PrefixV4, PrefixV6};
use crate::screen::{ScreenProfile, ScreenState, ScreenVerdict, extract_screen_info};
use crate::session::{
    ForwardSessionMatch, SessionCounters, SessionDecision, SessionDelta, SessionDeltaKind,
    SessionInstall, SessionKey, SessionLookup, SessionMetadata, SessionOrigin, SessionTable,
    SessionUpdate, forward_wire_key, reverse_canonical_key, reverse_session_key,
};
use crate::slowpath::{EnqueueOutcome, SlowPathReinjector, SlowPathStatus, open_tun};
use crate::xsk_ffi::xdp::XdpDesc;
use crate::xsk_ffi::{BufIdx, SocketConfig, Umem, UmemConfig, User};
use arc_swap::ArcSwap;
use chrono::Utc;
use core::ffi::{c_int, c_void};
use core::ptr::NonNull;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::{BTreeMap, VecDeque};
use std::ffi::CString;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::rc::Rc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{
    AtomicBool, AtomicI32, AtomicI64, AtomicU8, AtomicU32, AtomicU64, Ordering,
};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;

const USERSPACE_SESSION_ACTION_REDIRECT: u8 = 1;
const USERSPACE_SESSION_ACTION_PASS_TO_KERNEL: u8 = 2;

/// Hot-path debug logging — compiled out unless `debug-log` feature is enabled.
#[allow(unused_macros)]
macro_rules! debug_log {
    ($($arg:tt)*) => {
        #[cfg(feature = "debug-log")]
        eprintln!($($arg)*);
    };
}

#[path = "bind.rs"]
mod bind;
#[path = "binding_state/mod.rs"]
mod binding_state;
#[path = "bpf_map/mod.rs"]
mod bpf_map;
#[path = "checksum.rs"]
mod checksum;
// #4800: test-only exclusion between readers and movers of the process-global
// new-flow contention counters. The mover side is taken inside the moving
// functions, so the mover set is derived rather than inventoried.
#[cfg(test)]
#[path = "counter_test_lock.rs"]
mod counter_test_lock;
#[path = "ethernet.rs"]
mod ethernet;
#[path = "event_emit.rs"]
mod event_emit;
#[path = "flow_cache.rs"]
mod flow_cache;
#[path = "forwarding/mod.rs"]
mod forwarding;
mod forwarding_build;
#[path = "frame/mod.rs"]
mod frame;
#[path = "gre.rs"]
mod gre;
mod ha;
// #6785: the control handler needs the synced-import outcome type and its
// refusal-token prefix.
pub use ha::{SyncedImportOutcome, SYNCED_IMPORT_REFUSED_PREFIX};
#[path = "icmp.rs"]
mod icmp;
mod icmp_embed;
mod icmp_ptb;
mod icmp_ratelimit;
mod mirror;
#[path = "mpsc_inbox.rs"]
mod mpsc_inbox;
#[path = "neighbor.rs"]
mod neighbor;
#[path = "parser.rs"]
mod parser;
#[path = "rst.rs"]
mod rst;
#[path = "sharded_neighbor.rs"]
mod sharded_neighbor;
// session_glue is a directory module (afxdp/session_glue/{mod.rs, tests.rs}),
// so the explicit `#[path]` is unnecessary — auto-resolution finds mod.rs.
#[path = "cos/mod.rs"]
mod cos;
mod session_glue;
// #2442: re-export the owner-RG export walk + its chunkable candidate collector
// so the worker loop's loss-of-sync resync path and the session-module resync
// test can reach them without naming the private `session_glue` module.
pub(crate) use session_glue::forward_export_candidates_for_owner_rgs;
// #2653: the unbounded "emit all at once" helper is now a test-only fixture
// (the production paths use the chunked drain-as-you-export in worker::loop_body).
#[cfg(test)]
pub(crate) use session_glue::export_forward_sessions_for_owner_rgs;
#[path = "shared_ops.rs"]
mod shared_ops;
#[path = "shared_umem.rs"]
mod shared_umem;
#[cfg(test)]
#[path = "test_fixtures.rs"]
mod test_fixtures;
#[path = "tunnel.rs"]
mod tunnel;
#[path = "tx/mod.rs"]
mod tx;
#[path = "types/mod.rs"]
mod types;
#[path = "umem/mod.rs"]
mod umem;
// #1612 step-3 STAGED scaffolding: cold-path latency histogram
// primitives. Module-level `#[allow(dead_code)]` because every export
// is intentionally unused at this PR — integration into BindingWorker,
// the poll_descriptor hot path, and the wire protocol is deferred to
// follow-up issues #1620, #1621, #1622 per
// docs/pr/1612-scale-target-measurement/plan.md STAGED form. The
// scaffolding lives in tree to (a) make the 11-finding plan-review
// audit chain reviewable as compiled code and (b) provide the math
// primitives the follow-ups will consume.
#[allow(dead_code)]
#[path = "cold_path_hist.rs"]
mod cold_path_hist;
// #3651: per-zone ingress/egress traffic counters (POPULATE half of #3643).
mod zone_counters;
// #3651: per-zone SYN/ICMP/UDP flood-event counters — the flood half of the
// same POPULATE, accounted on the screen-drop path rather than the forward path.
mod flood_counters;
// Clean-room WireGuard tunnel termination — see
// docs/pr/wireguard-clean/plan.md. Engine + tests only in this PR;
// hot-path activation lands in a follow-up.
#[path = "wg/mod.rs"]
mod wg;

#[cfg(test)]
use self::bind::bind_flag_candidates_for_driver;
use self::bind::{
    AfXdpBindStrategy, XskSocketRole, binding_frame_count_for_driver, ifinfo_from_binding,
    interface_driver_name, open_binding_worker_rings, preferred_bind_strategy,
    reserved_tx_frames_for_driver, umem_ring_size,
};
#[cfg(test)]
use self::bind::{
    AfXdpBinder, alternate_bind_strategy, bind_flag_candidates_for_socket_role,
    bind_strategy_for_driver, binder_for_strategy, describe_bind_flags,
    shared_umem_group_key_for_device,
};
use self::binding_state::*;
use self::bpf_map::*;
use self::checksum::*;
use self::event_emit::*;
use self::flow_cache::*;
use self::forwarding::*;
use self::forwarding_build::*;
use self::frame::*;
use self::gre::{encapsulate_native_gre_frame, try_native_gre_decap_from_frame};
use self::icmp::{
    FABRIC_INGRESS_FLAG, GRE_DECAP_INGRESS_FLAG, build_local_time_exceeded_request, is_icmp_error,
    packet_ttl_would_expire,
};
use self::icmp_ptb::{
    EgressMtuDecision, build_frag_needed_v4, build_packet_too_big_v6,
    forwarded_egress_mtu_decision, post_transform_inner_mtu, ptb_reply_suppressed,
};
use self::icmp_ratelimit::{GeneratedErrorReason, allow_generated_error_zoned};
#[cfg(test)]
use self::icmp::{
    build_local_time_exceeded_v4, build_local_time_exceeded_v6, build_reject_icmp_unreachable,
    can_generate_icmp_error_reply, reject_icmp_reply_suppressed,
};
#[cfg(test)]
use self::icmp_embed::{
    EmbeddedIcmpMatch, try_embedded_icmp_nat_match_from_frame,
    try_embedded_icmp_session_match_from_frame,
};
use self::icmp_embed::{
    Nat64IcmpErrorMatch, build_nat_reversed_icmp_error_v4, build_nat_reversed_icmp_error_v6,
    build_snat_outbound_icmp_error_v4, build_snat_outbound_icmp_error_v6,
    finalize_embedded_icmp_resolution, finalize_embedded_icmp_resolution_parts,
    try_embedded_icmp_nat_match, try_nat64_icmp_error_match_from_frame,
};
use self::mirror::*;
use self::mpsc_inbox::MpscInbox;
use self::neighbor::*;
pub use self::neighbor::{neighbor_state_usable_str, parse_mac_str};
pub(crate) use self::rst::remove_kernel_rst_suppression;
use self::rst::*;
use self::session_glue::*;
use self::sharded_neighbor::ShardedNeighborMap;
use self::shared_ops::*;
use self::shared_umem::*;
use self::tunnel::*;
use self::tx::dispatch::*;
use self::tx::*;
use self::types::*;
pub(crate) use self::types::{ForwardingDisposition, ForwardingResolution, NeighborEntry};
// #2844: expose the SSOT in-place Ethernet-header writer to the
// top-level `crate::nat64` module. NAT64 lives outside `crate::afxdp`
// (it is `mod nat64;` at the crate root), so it cannot reach the
// `pub(in crate::afxdp)` writer in `frame::headers` directly. This
// `pub(crate)` re-export lets the NAT64 frame builders use the one
// shared writer instead of a private hardcoded copy, so any future
// VLAN/TPID/PCP/DEI/ethertype change in the shared module propagates
// to NAT64 automatically.
pub(crate) use self::frame::write_eth_header_slice;
// #4435: same rationale as the writer above — expose the canonical
// IPv6 ext-header loop bound so `crate::nat64`'s private walkers stay
// in lockstep with the forwarding/screen paths (one const, no skew).
pub(crate) use self::frame::MAX_IPV6_EXT_HEADERS;
// #6435: and now the canonical WALK itself — `crate::nat64`'s
// L4-offset / non-first-fragment / fragment-header resolvers fold this
// one shared walker (declared in `frame/inspect.rs`) instead of
// hand-mirroring the loop, retiring the last private copies the #4435
// bound-share left behind. `afxdp/icmp_embed/parse.rs` reaches the same
// items through this re-export + its `use super::*` chain. Only the two
// items NAT64/icmp_embed NAME are re-exported here — the `ExtChainWalk`
// / `ExtChainFragment` field access needs no import.
pub(crate) use self::frame::{ExtChainOutcome, walk_ipv6_ext_chain};
// #4555/#6923: the walk's own type classification, re-exported on the same
// channel so the HA session-sync IMPORT path (`crate::server::helpers`, outside
// `crate::afxdp`) rejects a peer-supplied key whose protocol is one the walk
// traverses. The shim's over-limit refusal is an invariant about the session
// map, and the map has two writers — the packet path and this import.
pub(crate) use self::frame::ipv6_ext_header_is_traversable;
use self::umem::*;

// #4435 (test-only): a thin `pub(crate)` wrapper over the canonical
// `pub(in crate::afxdp)` L4/ext-header walker so the NAT64 parity test in
// `crate::nat64` can assert nat64's private walker and the canonical
// forwarding walker agree at the exact-`MAX_IPV6_EXT_HEADERS` boundary
// (both fail closed). A `pub(crate) use` re-export cannot widen the
// walker's `pub(in crate::afxdp)` visibility, and the walker stays
// afxdp-private in production — this wrapper exists only under `cfg(test)`.
#[cfg(test)]
pub(crate) fn packet_rel_l4_offset_and_protocol_for_test(
    packet: &[u8],
    addr_family: u8,
) -> Option<(usize, u8)> {
    self::frame::packet_rel_l4_offset_and_protocol(packet, addr_family)
}

const USERSPACE_META_MAGIC: u32 = 0x4250_5553;
const USERSPACE_META_VERSION: u16 = 4;
const UMEM_FRAME_SIZE: u32 = 4096;
/// #812: log2 of `UMEM_FRAME_SIZE`, used to index the per-binding
/// submit-timestamp sidecar (`BindingWorker::tx_submit_ns`). Paired
/// const-assert below keeps this wired to the frame size so a future
/// resize (e.g. 2 KiB frames) fails the build instead of silently
/// indexing the wrong slot.
const UMEM_FRAME_SHIFT: u32 = 12;
const _: () = assert!(1u32 << UMEM_FRAME_SHIFT == UMEM_FRAME_SIZE);
/// #2443: upper bound on the operator/API-supplied `inject-packet`
/// length. An injected packet is emitted as a single unfragmented frame
/// that must fit in one UMEM frame on the TX path, so the egress
/// single-frame ceiling (`UMEM_FRAME_SIZE`) is the binding constraint.
/// It is also well within the u16 range of the IPv4 total-length / IPv6
/// payload-length wire fields, so the on-wire length can never wrap. A
/// request above this is REJECTED (not clamped) — see
/// `Coordinator::inject_test_packet` and the frame builders.
const MAX_INJECT_PACKET_LENGTH: u32 = UMEM_FRAME_SIZE;
const UMEM_HEADROOM: u32 = 256;
// #920: batch sizes lowered from 256 to 64 to keep the per-batch
// working set within typical 32 KB L1d (~10-14 KB at 64 packets:
// 64 × 96 B `UserspaceDpMeta` + 64 × 64-128 B headers + scratch
// state) and reduce the worst-case head-of-line latency for a
// mouse packet trailing an elephant burst by 4× — at 25 Gb/s and
// 1500-byte MTU each packet is ~480 ns, so 63 packets ahead = 30 µs
// vs 122 µs at the prior batch of 256. Also caps the kernel-side
// NAPI busy-poll budget via SO_BUSY_POLL_BUDGET in bind.rs at 64.
//
// Tradeoff: per-poll throughput drops from
// `MAX_RX_BATCHES_PER_POLL × <pre-#920 RX_BATCH_SIZE = 256>`
// to `MAX_RX_BATCHES_PER_POLL × RX_BATCH_SIZE` packets per binding
// poll cycle (4 × 256 = 1024 → 4 × 64 = 256 at the current
// constants). Kept `MAX_RX_BATCHES_PER_POLL = 4` (rather than
// raising to 16) because the latency goal of #920 directly
// benefits from more frequent yields. Throughput
// regression-checked in cluster smoke.
//
// Future bumps require re-validating: (a) L1d footprint vs
// per-batch allocation; (b) per-poll budget interaction with
// `MAX_RX_BATCHES_PER_POLL`; (c) the guarantee-phase per-visit budget
// tests in `cos/queue_service/tests.rs` (#1630 P2 ties the per-visit
// send cap `cos_guarantee_visit_cap_bytes` to `TX_BATCH_SIZE × frame`).
// The const_asserts below force the change to fail compilation rather
// than silently regress the validation surface.
const RX_BATCH_SIZE: u32 = 64;
const _: () = assert!(
    RX_BATCH_SIZE == 64,
    "changing RX_BATCH_SIZE requires re-validating L1d footprint and per-poll budget"
);
const MIN_RESERVED_TX_FRAMES: u32 = 256;
const MAX_RESERVED_TX_FRAMES: u32 = 8192;
/// #2524: independent backstop ceiling for the AF_XDP `ring-entries` knob.
/// The Go schema rejects out-of-range / non-power-of-two values at commit
/// (pkg/config ValidateRingEntries, MaxRingEntries = 16384); this constant
/// is the helper-side fail-safe so a config or `--ring-entries` flag that
/// bypassed the Go gate still cannot drive an enormous per-binding UMEM
/// preallocation (binding_frame_count_for_driver sizes ~3×ring_entries
/// frames per binding). Bring-up clamps to this ceiling. Must match the
/// Go MaxRingEntries.
pub(crate) const MAX_RING_ENTRIES: u32 = 16384;
const TX_BATCH_SIZE: usize = 64;
const _: () = assert!(
    TX_BATCH_SIZE == 64,
    "changing TX_BATCH_SIZE requires re-validating COS guarantee quantum + snapshot stack bound"
);
const PENDING_TX_LIMIT_MULTIPLIER: usize = 2;
const FILL_BATCH_SIZE: usize = 1024;
const MAX_RX_BATCHES_PER_POLL: usize = 4;

/// #1630 (P1): exact-queue token-bucket burst bank.
///
/// The per-queue token bucket for a hard-cap exact guarantee class was
/// previously watermarked at `lease_bytes` (= `rate × 200 µs`, floored
/// at one frame). For a low-rate class (e.g. 100 Mbps → ~2.5 KB target,
/// floored to 4 KB) the bucket could bank only ~1-2 frames and lost the
/// unspent per-epoch lease cap at every rotation, pinning the class well
/// below its configured rate independent of competition (the
/// small-four-alone SOLO A/B measured 100m/1g far under shape). Banking N
/// frames lets a small class accrue enough to send whole frames at its
/// full average rate and ride out drain-visit cadence jitter.
///
/// The long-run RATE is unchanged: the v8 `acquire_v8` per-epoch grant is
/// still rate-metered (now `rate × elapsed` with the #1630 cause-1 carry)
/// and `consume(sent_bytes)` debits actual bytes
/// (token_bucket.rs / tx_completion.rs). The watermark only widens the
/// burst/accumulation window — it never raises the refill rate, so the
/// hard-cap (Gate 4) holds.
///
/// `COS_EXACT_QUEUE_LEASE_BANK_BYTES` is consumed by
/// `maybe_top_up_cos_queue_lease` (the bucket watermark) AND by
/// `compute_shared_cos_lease_config` (the `max_total_leased`
/// outstanding-credit cap), which MUST rise in lock-step or the v8 lease
/// refuses grants past the old cap and defeats the watermark in low
/// `active_shards` configurations (at active_shards=6, 4096×6=24 KB <
/// the 32 KB bank).
const COS_EXACT_QUEUE_LEASE_BANK_FRAMES: u64 = 8;
const COS_EXACT_QUEUE_LEASE_BANK_BYTES: u64 =
    COS_EXACT_QUEUE_LEASE_BANK_FRAMES * UMEM_FRAME_SIZE as u64;
/*
 * Force XDP_COPY mode for AF_XDP sockets. In zero-copy mode on mlx5, XDP_PASS
 * (used for ARP, host-bound management traffic, and fallback paths) permanently
 * consumes fill ring frames — the kernel holds the UMEM frame in an SKB and
 * never returns it to userspace's fill ring. This drains all 12K+ RX frames
 * within seconds of sustained traffic, causing permanent rx_xsk_buff_alloc_err.
 *
 * In copy mode, XDP_PASS operates on kernel DMA buffers, not UMEM frames, so
 * the fill ring is only consumed by XDP_REDIRECT→XSK (which userspace always
 * recycles). The cost is one memcpy per redirected packet.
 *
 * Zero-copy is now restored (#209): the XDP shim replaces all XDP_PASS paths
 * with cpumap redirect (USERSPACE_CPUMAP), which frees the XSK frame
 * immediately while still delivering the packet to the kernel stack.
 * The bind flags try zero-copy first and fall back to copy mode if the
 * driver doesn't support it.
 */
const XSK_BIND_FLAGS_ZEROCOPY: u16 =
    SocketConfig::XDP_BIND_NEED_WAKEUP | SocketConfig::XDP_BIND_ZEROCOPY;
const XSK_BIND_FLAGS_COPY: u16 = SocketConfig::XDP_BIND_NEED_WAKEUP | SocketConfig::XDP_BIND_COPY;
const IDLE_SPIN_ITERS: u32 = 256;
const IDLE_SLEEP_US: u64 = 1;
const INTERRUPT_POLL_TIMEOUT_MS: i32 = 1;
const RX_WAKE_IDLE_POLLS: u32 = 32;
const RX_WAKE_MIN_INTERVAL_NS: u64 = 200_000;
/// Safety-net interval for fill ring wakes when needs_wakeup is clear.
/// Prevents lost-wakeup stalls from the race: commit() → check needs_wakeup
/// (clear) → kernel exhausts cache → sets needs_wakeup → userspace doesn't see it.
const FILL_WAKE_SAFETY_INTERVAL_NS: u64 = 500_000; // 500µs
/// How often a bound worker stamps its heartbeat slot, from the worker loop
/// (`maybe_touch_heartbeat`, `afxdp/bpf_map/ha.rs`).
///
/// The shim reads that slot and treats it as STALE past
/// `USERSPACE_DEFAULT_HEARTBEAT_TIMEOUT_MS` (5 s, `userspace-xdp/src/lib.rs`),
/// so this cadence carries 20x headroom. A worker that stops stamping —
/// because the helper died, or because the loop is wedged — therefore has its
/// transit DROPPED by the shim within 5 s, not passed to the kernel.
const HEARTBEAT_UPDATE_INTERVAL_NS: u64 = 250_000_000;
const TX_WAKE_MIN_INTERVAL_NS: u64 = 50_000;
const HEARTBEAT_STALE_AFTER: Duration = Duration::from_secs(5);
/// #5468: upper bound on the worker-loop lossless session-delta send
/// (`flush_session_deltas` -> `EventStreamWorkerHandle::push_delta_lossless_within`).
///
/// `flush_session_deltas` runs on the packet worker loop, so a connected-but-
/// unread peer (a slow/stalled reader whose lossless queue is full) must not be
/// able to block the loop for the full 5 s `LOSSLESS_QUEUE_TIMEOUT`: that
/// exceeds `HEARTBEAT_STALE_AFTER`, so the loop stops stamping its heartbeat,
/// the peer marks this node stale, and a spurious failover fires. Bounding the
/// worker-side wait to one fifth of the stale threshold leaves 5x headroom for
/// the rest of the loop iteration plus the heartbeat map write, while still
/// tolerating realistic transient reader pauses (a healthy consumer drains the
/// channel in microseconds). On timeout the caller latches loss-of-sync (a full
/// owner-RG resync via `take_delta_loss`), so the #2874 losslessness contract is
/// preserved (deliver-or-resync, never a silent drop). The off-worker-loop bulk
/// export/purge paths keep the longer `LOSSLESS_QUEUE_TIMEOUT`.
const WORKER_LOSSLESS_QUEUE_BUDGET: Duration =
    Duration::from_nanos((HEARTBEAT_STALE_AFTER.as_nanos() / 5) as u64);
// Compile-time invariant: the worker-side lossless budget must stay well below
// the heartbeat-stale threshold, or the fix regresses into the #5468 stall.
const _: () = assert!(
    WORKER_LOSSLESS_QUEUE_BUDGET.as_nanos() * 2 <= HEARTBEAT_STALE_AFTER.as_nanos(),
    "WORKER_LOSSLESS_QUEUE_BUDGET must be well below HEARTBEAT_STALE_AFTER (#5468)"
);
const MAX_RECENT_EXCEPTIONS: usize = 32;
const MAX_RECENT_SESSION_DELTAS: usize = 64;
const MAX_PENDING_SESSION_DELTAS: usize = 4096;
const BIND_RETRY_ATTEMPTS: usize = 20;
const BIND_RETRY_DELAY: Duration = Duration::from_millis(250);
const DEFAULT_SLOW_PATH_TUN: &str = "xpf-usp0";
const LOCAL_TUNNEL_DELIVERY_QUEUE_DEPTH: usize = 4096;
const HA_WATCHDOG_STALE_AFTER_SECS: u64 = 10;
const FABRIC_ZONE_MAC_MAGIC: u8 = 0xfe;
use crate::ip_proto::{PROTO_AH, PROTO_ESP, PROTO_GRE, PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP};
// #2151: TCP flag bits now live in the shared crate::tcp_flags SSOT.
// Re-exported here under the historical TCP_FLAG_* spellings (and made
// visible to `super::*` consumers: event_emit, tx/tcp_segmentation,
// frame/tcp_segmentation, frame/*) so the move is value-identical.
use crate::tcp_flags::{
    TCP_CWR as TCP_FLAG_CWR, TCP_FIN as TCP_FLAG_FIN, TCP_PSH as TCP_FLAG_PSH,
    TCP_RST as TCP_FLAG_RST, TCP_SYN as TCP_FLAG_SYN, TCP_URG as TCP_FLAG_URG,
};
const TUNNEL_HA_STARTUP_GRACE_SECS: u64 = 10;
const SOL_XDP: c_int = 283;
const XDP_OPTIONS: c_int = 8;
const XDP_OPTIONS_ZEROCOPY: u32 = 1;

const PENDING_NEIGH_TIMEOUT_NS: u64 = 2_000_000_000; // 2 seconds
// #1771 §2.2: `pending_neigh` is a FastMap keyed by `(egress_ifindex,
// next_hop)` holding ONE representative packet per unresolved next-hop —
// not a packet FIFO. Admission keeps the OLDEST packet for a key (it
// drives the probe/dwell clock); later packets to the same hop are
// dropped + recycled and counted via `pending_neigh_duplicate_drops`
// (the #1782 H5 sibling-drop signal). This cap therefore bounds DISTINCT
// unresolved next-hops per binding, and pins at most one UMEM frame per
// hop — a SYN flood to one dead host holds 1 entry, not 4096.
// PendingNeighPacket is 264 B on x86_64 (XdpDesc + UserspaceDpMeta +
// SessionDecision + flow key + queued_ns + probe_attempts), so the
// worst case is ~1.0 MiB per binding — but reaching it now requires
// 4096 *distinct* unresolved hops (a scan-shaped workload), not a
// connect burst. The map is lazily allocated (`FastMap::default()` at
// worker init — see worker/mod.rs), keeping idle-binding RSS near zero.
// History: pre-#1771 this was a per-packet VecDeque whose cap was bumped
// 64 → 4096 (GEMINI-NEXT.md Section 3) so failback connect storms didn't
// drop frames; post-#1771 sibling drops are by design and counted.
const MAX_PENDING_NEIGH: usize = 4096;

// #1651 B3: dead-host negative neighbor cache (per binding). When a
// pending_neigh entry times out after best-effort ARP/NDP probes without
// resolving, its (egress_ifindex, next_hop) is recorded here so subsequent
// cold packets to the same dead host fast-fail immediately (recycle, no
// pending_neigh slot consumed) instead of each buffering a SYN for the full
// PENDING_NEIGH_TIMEOUT. This is the AGY-r1 HIGH starvation defense: a
// dead-host SYN storm can no longer saturate the bounded pending_neigh queue
// and drop LIVE cold connects at the full-queue gate.
//
// NEG_NEIGH_TTL_NS = 3 s: (a) > the 800 ms fast drop so each storm packet is
// suppressed across many connection attempts; (b) short enough that a
// recovered-but-silent host is penalized at most one TTL window. A host that
// actually recovers AND receives traffic is evicted immediately by the
// resolved-neighbor-wins check in poll_descriptor (RTM_NEWNEIGH populates the
// shared dynamic_neighbors), so the TTL only governs recovered-but-silent
// destinations.
const NEG_NEIGH_TTL_NS: u64 = 3_000_000_000; // 3 seconds
// Per-binding cap on the negative cache. A /24 scan touches 254 distinct
// dsts; 256 covers a full subnet sweep without unbounded growth.
//
// #6905: on overflow ONE entry is reclaimed — expired first, else the oldest —
// not the whole map. The previous wholesale `clear()` made the eviction victim
// set a function of the ARRIVING key: a host sweeping distinct next-hops chose
// when the clear fired and discarded unrelated suppression at will, partially
// undoing the defence this cache exists to provide. Note how little headroom
// the sizing leaves for that: 256 is deliberately one /24, so a single subnet
// sweep plus two other dead hosts reaches the overflow. Losing suppression is
// still never a correctness problem — it costs one more
// PENDING_NEIGH_TIMEOUT drop — but it should cost that for ONE dst, not for
// every dst on the box.
//
// Still allocation-free (retain/remove reuse the buckets) and still O(len) in
// the worst case, which is what `clear()` already was: clearing a map is
// O(capacity), not O(1). The work also lands on the COLD path —
// `neg_neigh_record` runs once per (ifindex, next_hop) per pending-neighbour
// timeout, while `neg_neigh_active` is the per-packet one. That asymmetry is
// why an LRU is the wrong instrument: it would pay bookkeeping on every hot
// -path HIT to improve a decision made only on the cold path.
const MAX_NEG_NEIGH_CACHE: usize = 256;

#[inline]
const fn tx_frame_capacity() -> usize {
    UMEM_FRAME_SIZE as usize
}

#[path = "coordinator/mod.rs"]
mod coordinator;
/// #7413: see `coordinator/mod.rs` — the `neigh-monitor` test serial guard,
/// re-exported so every spawner across both test modules takes the SAME lock.
#[cfg(test)]
pub(crate) use coordinator::neigh_monitor_test_serial;
// afxdp/tests.rs (14k-LOC catch-all) was split into cohesive per-subsystem
// sibling test modules plus a shared support module in #4840. Pure test
// code-motion; each file carries the union use-block and reaches production
// items through `super::*`, identical to the pre-split single module.
#[cfg(test)]
#[path = "tests_support.rs"]
mod tests_support;
#[cfg(test)]
#[path = "tests_bind_forward.rs"]
mod tests_bind_forward;
#[cfg(test)]
#[path = "tests_icmp_te.rs"]
mod tests_icmp_te;
#[cfg(test)]
#[path = "tests_icmp_reject_reversal.rs"]
mod tests_icmp_reject_reversal;
#[cfg(test)]
#[path = "tests_embedded_poll_filter.rs"]
mod tests_embedded_poll_filter;
#[cfg(test)]
#[path = "tests_fabric_zone_stamp.rs"]
mod tests_fabric_zone_stamp;
#[cfg(test)]
#[path = "tests_session_ingress_identity.rs"]
mod tests_session_ingress_identity;
#[cfg(test)]
#[path = "tests_slow_path_disposition.rs"]
mod tests_slow_path_disposition;
#[cfg(test)]
#[path = "tests_txn_flow_cache.rs"]
mod tests_txn_flow_cache;
#[cfg(test)]
#[path = "tests_nat64_tunnel.rs"]
mod tests_nat64_tunnel;
#[cfg(test)]
#[path = "tests_gre_local_delivery.rs"]
mod tests_gre_local_delivery;
#[cfg(test)]
mod tests_gre_outer_bound_6748;
#[cfg(test)]
mod pkt_len_fixture_drift_6883_tests;
#[cfg(test)]
#[path = "tests_gre_version_6842.rs"]
mod tests_gre_version_6842;
#[cfg(test)]
#[path = "tests_decap_dnat_table.rs"]
mod tests_decap_dnat_table;
#[cfg(test)]
#[path = "tests_policy_inbound_nat.rs"]
mod tests_policy_inbound_nat;
#[cfg(test)]
#[path = "tests_fragment.rs"]
mod tests_fragment;
#[cfg(test)]
#[path = "tests_session_delta_json.rs"]
mod tests_session_delta_json;
#[path = "worker/mod.rs"]
mod worker;
// #1807: shared poison-recovery helpers (lock_recover /
// try_lock_recover) for every Mutex<VecDeque<WorkerCommand>> access.
#[path = "worker_queue.rs"]
// #7053: `pub(crate)` so the shared source-scan helpers in its test module
// (blank_comments_and_strings / afxdp_rs_files / is_fixture) reach the
// routing-instance pairing guard in filter/tests.rs. Widening the module,
// not copying the helpers.
pub(crate) mod worker_queue;
#[path = "worker_runtime.rs"]
mod worker_runtime;
pub use self::coordinator::Coordinator;
// #3789: re-export the full-reconcile abort outcome into afxdp scope so
// the control-plane server (`server/helpers.rs` + `handlers/snapshot.rs`)
// can name `afxdp::ReconcileError` on `reconcile_status_bindings`.
pub(crate) use self::coordinator::ReconcileError;
// #6244: the typed reconcile progress / failure identity, named by the
// control-plane server tests and any consumer that inspects the stage.
pub(crate) use self::coordinator::{MandatoryPin, ReconcileStage, WorkerBindShortfall};
// #6242: the per-worker transactional runtime record, re-exported into afxdp
// scope so the HA modules' `#[path]`-included test child (`ha_tests.rs`, via
// `use super::*`) can seed `workers.records` — mirroring how `WorkerHandle`
// resolves for the same tests.
#[cfg(test)]
pub(in crate::afxdp) use self::coordinator::WorkerRuntimeRecord;
// #2962: the lock-free owner-RG export wait handle. The control-socket
// dispatcher (server/handlers) names this as the return type of
// kick_owner_rg_export so it can run the blocking ack-wait off the
// global ServerState lock.
pub(crate) use self::ha::OwnerRgExportWait;
// #4054: re-export the two-phase all-sessions bulk export handle so the
// control-socket dispatcher can run the lossless push loop off the global
// ServerState lock (mirrors the OwnerRgExportWait split, #2962).
pub(crate) use self::ha::AllSessionsExport;
// #1636: re-export the warmer types/consts into afxdp scope so the
// neighbor-warmer loop in neighbor.rs (which uses `use super::*`) and
// the unit tests can name them without a fully-qualified path.
pub(crate) use self::coordinator::WarmItem;
pub(in crate::afxdp) use self::coordinator::{
    WARM_GC_INTERVAL_NS, WARM_GC_MAX_AGE_NS, WARM_PER_KEY_RATE_LIMIT_NS, WARM_QUEUE_DEPTH,
};
pub(crate) use self::worker::{
    BindingLiveSnapshot, BindingWorker, SyncedSessionEntry, WorkerControlChannels, WorkerCoSState,
    WorkerLaunchPlan, WorkerPublishedTelemetry, WorkerSharedDataplane, XskBindMode,
    fabric_queue_hash, push_recent_exception, push_recent_session_delta, worker_loop,
};
#[cfg(test)]
pub(crate) use self::worker::fabric_queue_hash_seeded;

// Lifted from `poll_binding` so the per-descriptor batch function
// (`poll_binding_process_descriptor`) can take `&mut BatchCounters`.
// Originally byte-for-byte identical to the previous nested definition
// (#678 poll_binding split). #1187 adds 8 disposition-path counters.
#[derive(Default)]
pub(in crate::afxdp) struct BatchCounters {
    touched: bool,
    rx_packets: u64,
    rx_bytes: u64,
    rx_batches: u64,
    metadata_packets: u64,
    validated_packets: u64,
    validated_bytes: u64,
    forward_candidate_packets: u64,
    session_hits: u64,
    session_misses: u64,
    session_creates: u64,
    snat_packets: u64,
    dnat_packets: u64,
    // #2161: per-translation NAT64 (v6<->v4) tally, batched like snat/dnat
    // and flushed to BindingLiveState.nat64_translations.
    nat64_translations: u64,
    // #2291: fail-closed drop counter — a NAT64 prefix matched but no IPv4
    // source could be allocated (empty/exhausted pool), so the synthetic
    // IPv6 destination was DROPPED rather than route-looked-up as ordinary
    // IPv6 (the pre-fix fail-open). Flushed to
    // BindingLiveState.nat64_no_source_pool.
    //
    // #4520: this slot now covers ONLY the config/empty/missing pool case
    // (the classify-time `MatchUnavailable`, and any non-exhaustion
    // `allocate_source` error). Transient port exhaustion under load is
    // split out into `nat64_pool_exhausted` below so a full pool (add
    // capacity) is distinguishable from a misconfigured/empty pool (fix
    // config) — mirroring source-NAT's `pool_empty`/`pool_exhausted` split.
    nat64_no_source_pool: u64,
    // #4520: transient NAT64 pool-exhaustion drops — a NAT64 prefix matched
    // and its pool was non-empty, but `allocate_source` returned
    // `AllocatorExhausted` (no free translated port). Flushed to
    // BindingLiveState.nat64_pool_exhausted and surfaced as the
    // `NAT64 pool-exhausted drops` operator counter, the transient sibling
    // of `nat64_no_source_pool` (config/empty).
    nat64_pool_exhausted: u64,
    // #2562: fail-closed NAT64 FRAGMENT drops — a datagram was dropped because
    // it is a fragment NAT64 cannot safely translate: a non-first fragment
    // (offset > 0, any protocol — no L4 header to translate) or a real fragment
    // (MF=1 or offset > 0) carrying ICMP/ICMPv6 (the ICMP checksum covers the
    // whole datagram and cannot be recomputed from a single fragment). Bumped
    // from the TX dispatcher when `build_nat64_forwarded_frame` returns `None`
    // and `nat64::frame_is_nat64_fragment_drop` attributes it. Flushed to
    // BindingLiveState.nat64_frag_dropped and surfaced as the `NAT64 fragment
    // drops` operator counter. The stateful frag-association cache that would
    // let real fragments traverse end-to-end (#3291 stage 4) is deferred, so
    // this is the observable-drop half of #2562.
    nat64_frag_dropped: u64,
    // #5623: fail-closed NAT64 SOURCE-ineligibility drops — an incoming IPv6
    // packet whose SOURCE lies within a configured Pref64 (a looping/synthesized
    // "already-translated" source, the RFC 6146 §5 hairpin construction — plus
    // the lower/upper Pref64 boundary and any embedded non-global v4) is dropped
    // BEFORE route lookup, policy, or `allocate_source`, per RFC 6146 §3.5.
    // Distinct from the pool counters above (those are a config/capacity issue on
    // an ELIGIBLE flow; this is an input-validation reject). Flushed to
    // BindingLiveState.nat64_ineligible_source and surfaced as the `NAT64
    // ineligible-source drops` operator counter.
    nat64_ineligible_source: u64,
    // #6475: fail-closed NAT64 DESTINATION-ineligibility drops — an incoming
    // IPv6 packet whose NAT64-prefix-matched destination embeds a non-global
    // IPv4 per RFC 6052 §3.1 (0.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16,
    // 224.0.0.0/4, 240.0.0.0/4 — e.g. `64:ff9b::127.0.0.1`, which would
    // otherwise resolve LocalDelivery to the localhost-only control plane once
    // lo0 lands in `state.local_v4`) is dropped BEFORE route lookup, policy, or
    // `allocate_source`. Distinct from the source gate above and from the pool
    // counters (config/capacity on an ELIGIBLE flow) — this is a destination
    // input-validation reject. Flushed to BindingLiveState.nat64_ineligible_dest
    // and surfaced as the `NAT64 ineligible-destination drops` operator counter.
    nat64_ineligible_dest: u64,
    // #5625: fail-closed NAT64 EXTENSION-HEADER ineligibility drops — a v6→v4
    // forward translation was rejected BEFORE it proceeded because the IPv6
    // packet carried an Authentication Header (51), an ACTIVE Routing header
    // (43, Segments Left > 0), or a Mobility (135) / HIP (139) / Shim6 (140)
    // header, none of which a stateless NAT64 translation can carry to IPv4
    // (RFC 7915 §5.1 / §5.1.1) — translating would strip the active extension
    // semantics or break AH authentication. Bumped from the TX dispatcher when
    // `build_nat64_forwarded_frame` returns `None` and
    // `nat64::frame_is_nat64_exthdr_ineligible` attributes it. Flushed to
    // BindingLiveState.nat64_exthdr_ineligible and surfaced as the `NAT64
    // ext-header ineligible drops` operator counter. Distinct from the
    // source/pool/fragment counters — this is an ext-header input reject.
    nat64_exthdr_ineligible: u64,
    // #4477: source-NAT allocation failures — a source-NAT rule matched but no
    // translated mapping could be allocated (missing/empty/invalid pool,
    // exhausted port allocator, wrong family, or a non-first fragment on a
    // port-translating rule). The packet is dropped. Bumped at the cold
    // `record_source_nat_failure` site and flushed to
    // BindingLiveState.nat_alloc_fail; the Go control plane bridges it into the
    // `GlobalCtrNATAllocFail` counter that `show security flow statistics`
    // ("NAT allocation failures"), the REST/Prometheus surfaces, and the CLI
    // read — dead-counter fix for the observability lie.
    nat_alloc_fail: u64,
    // #6122: fail-closed drops of an ordinary same-family NAT'd (SNAT /
    // static-NAT / DNAT / NPTv6) NON-FIRST fragment that MISSED the
    // fragment-association cache. Forwarding it untranslated would leak the
    // internal source (SNAT / NPTv6) or the pre-NAT destination (DNAT); the
    // flow WOULD be translated (a matching NAT rule exists on its L3 identity)
    // but no association is present (reorder / eviction / TTL straddle /
    // config-generation bump / a first fragment that never forwarded), so the
    // fragment is DROPPED. The same-family sibling of `nat64_frag_dropped`.
    // Bumped at the flowless miss path (`record_nat_frag_untranslated_dropped`)
    // and flushed to BindingLiveState.nat_frag_untranslated_dropped.
    nat_frag_untranslated_dropped: u64,
    // #1187: 8 disposition-path counters added to eliminate per-packet
    // MESI thrash on BindingLiveState atomics during DDoS / config-
    // reload windows. See docs/pr/1187-telemetry-double-buffer/plan.md
    // (v7 PLAN-READY).
    screen_drops: u64,
    // #3343: per-screen-reason DROP tally, indexed by
    // `screen::screen_reason_drop_index`. Batched alongside the aggregate
    // `screen_drops` (same MESI-thrash rationale) and flushed element-wise into
    // `BindingLiveState.screen_reason_drops`. Reasons without a published
    // ordinal (SYN-cookie / icmp-fragment / ip-malformed) bump only the
    // aggregate above.
    screen_reason_drops: [u64; crate::screen::SCREEN_REASON_DROP_COUNT],
    syn_cookie_challenges: u64,
    syn_cookie_secret_unavailable: u64,
    syn_cookie_syn_ack_sent: u64,
    syn_cookie_ack_rst_sent: u64,
    syn_cookie_reply_budget_drops: u64,
    syn_cookie_ack_valid: u64,
    syn_cookie_ack_invalid: u64,
    syn_cookie_bypass: u64,
    // #2089: policy `reject` reply synthesis. policy_reject_sent counts
    // RST/ICMP-unreachable replies enqueued; policy_reject_reply_budget_drops
    // counts replies suppressed because the TX-frame budget was exhausted
    // (the packet is still dropped — fail-closed).
    policy_reject_sent: u64,
    // #2521: firewall-filter `then reject` reply synthesis. Counts the
    // RST/ICMP-unreachable replies enqueued for a filter (not policy)
    // reject; mirrors `policy_reject_sent`. The budget-exhaustion,
    // output-filter, and parse-error drop legs are SHARED with policy
    // reject (`policy_reject_reply_budget_drops`,
    // `policy_reject_output_filter_drops`,
    // `generated_reply_classify_parse_errors`) because both run the same
    // synthesis + #2238 output-classification path.
    filter_reject_sent: u64,
    policy_reject_reply_budget_drops: u64,
    // #3615 (L04): FILTER-`reject` reply TX-frame-budget suppression, split
    // from `policy_reject_reply_budget_drops` so filter-reject troubleshooting
    // is precise (both still share the same budget gate).
    filter_reject_reply_budget_drops: u64,
    // #3661: POLICY-`reject` replies dropped because the shared per-reason
    // REJECT_BUCKET rate-limit token bucket was empty. The aggregate
    // `reject_rate_limited_total` (bumped inside `allow_generated_error`) stays
    // source-neutral; this splits the SAME drop by reply source so
    // policy-reject starvation is distinguishable from filter-reject
    // starvation under a rejected-flow flood. Sibling of
    // `policy_reject_reply_budget_drops`.
    policy_reject_rate_limit_drops: u64,
    // #3661: FILTER-`reject` reply rate-limit drop — the source-split sibling
    // of `policy_reject_rate_limit_drops` (both share the one REJECT_BUCKET).
    filter_reject_rate_limit_drops: u64,
    // #2238: locally-generated reply output-classification drops. A reply
    // (Time Exceeded, policy-reject RST/ICMP-unreachable, SYN-cookie
    // SYN-ACK/ACK-RST) is now classified by its OWN egress 5-tuple +
    // egress interface, so an output firewall filter terminal
    // `discard`/`reject` (or a three-color policer) on the egress interface
    // drops it. Counted per-leg so the (intended, operator-installed) drop
    // is attributable. `generated_reply_classify_parse_errors` counts the
    // fail-CLOSED drops when the generated bytes could not be re-parsed
    // (§6.2) — a builder/parser logic bug, never silent.
    time_exceeded_output_filter_drops: u64,
    policy_reject_output_filter_drops: u64,
    // #3615 (L05): FILTER-`reject` reply egress-output-filter suppression,
    // split from `policy_reject_output_filter_drops`.
    filter_reject_output_filter_drops: u64,
    syn_cookie_output_filter_drops: u64,
    // #2328: egress-MTU PTB / Frag-Needed (the #2301 PMTUD generator) is now
    // classified by its OWN egress tuple like the siblings above, so an
    // output firewall filter terminal `discard`/`reject` on the egress
    // interface drops it. Counted per-leg.
    ptb_output_filter_drops: u64,
    generated_reply_classify_parse_errors: u64,
    policy_denied_packets: u64,
    // #3326: host-inbound admission denies on the LocalDelivery path. Bumped
    // in the two `host_inbound_gated_lo0_action == None` branches in
    // poll_descriptor and flushed into BindingLiveState below.
    host_inbound_denied_packets: u64,
    route_miss_packets: u64,
    // #4743: NoRoute drops whose dst is a martian address — a sub-breakout of
    // route_miss_packets, bumped alongside it in the NoRoute disposition arm.
    martian_dropped: u64,
    // #4743: fail-closed drops of an over-limit IPv6 extension-header chain
    // (still on an ext header after MAX_IPV6_EXT_HEADERS iterations). Bumped at
    // the flow-parse stage when the helper walkers fail closed.
    ipv6_ext_header_dropped: u64,
    neighbor_miss_packets: u64,
    discard_route_packets: u64,
    next_table_packets: u64,
    local_delivery_packets: u64,
    exception_packets: u64,
}

impl BatchCounters {
    /// #3343: record one screen/IDS DROP. Bumps the aggregate `screen_drops`
    /// and, when `reason` maps to a published per-reason ordinal, the matching
    /// `screen_reason_drops` slot. Reasons without an ordinal (e.g.
    /// "syn-cookie", "icmp-fragment", "ip-malformed") are surfaced only through
    /// the aggregate. Centralizing here keeps the aggregate and per-reason
    /// tallies from drifting at the many drop sites.
    ///
    /// #3651: also feeds the PER-ZONE flood tally (`flood_counters`) for the
    /// three flood checks, which is why `zone_id` and the flood slot map are
    /// parameters. Routing it through this one method rather than a second call
    /// at each drop site extends the same anti-drift property: a new screen drop
    /// site cannot bump the aggregate while forgetting the per-zone counters.
    /// `zone_id` is the packet's INGRESS zone (0 = unzoned, uncounted); a
    /// non-flood reason or a zone with no hot-path slot contributes nothing.
    #[inline]
    pub(in crate::afxdp) fn record_screen_drop(
        &mut self,
        reason: &str,
        zone_id: u16,
        flood_slots: &crate::afxdp::flood_counters::FloodCounterSlotMap,
    ) {
        self.touched = true;
        self.screen_drops += 1;
        if let Some(i) = crate::screen::screen_reason_drop_index(reason) {
            self.screen_reason_drops[i] += 1;
        }
        crate::afxdp::flood_counters::record_zone_flood_drop(flood_slots, zone_id, reason);
    }

    /// #4520: attribute a NAT64 forward-flow source-allocation failure to the
    /// right drop counter. Transient port exhaustion (`AllocatorExhausted` —
    /// the pool is full, add capacity) bumps `nat64_pool_exhausted`; every
    /// other reason (missing/empty/invalid pool, wrong family — fix config)
    /// bumps `nat64_no_source_pool`. Mirrors source-NAT's
    /// `pool_empty`/`pool_exhausted` split so a full pool under load is
    /// distinguishable on the dashboard from a misconfigured one — opposite
    /// remedies.
    #[inline]
    pub(in crate::afxdp) fn record_nat64_source_failure(
        &mut self,
        reason: crate::nat::SourceNatFailureReason,
    ) {
        self.touched = true;
        match reason {
            crate::nat::SourceNatFailureReason::AllocatorExhausted => {
                self.nat64_pool_exhausted += 1;
            }
            _ => {
                self.nat64_no_source_pool += 1;
            }
        }
    }

    /// #2562: record a fail-closed NAT64 fragment drop (a non-first fragment or
    /// a real ICMP/ICMPv6 fragment that cannot be safely translated). Bumped
    /// from the TX dispatcher when `build_nat64_forwarded_frame` returns `None`
    /// and `nat64::frame_is_nat64_fragment_drop` attributes the `None` to a
    /// fragment. Batched like the sibling nat64 drop counters and flushed to
    /// `BindingLiveState.nat64_frag_dropped`.
    #[inline]
    pub(in crate::afxdp) fn record_nat64_frag_dropped(&mut self) {
        self.touched = true;
        self.nat64_frag_dropped += 1;
    }

    /// #6122: record a fail-closed drop of an ordinary same-family NAT'd
    /// non-first fragment that missed the fragment-association cache. Bumped on
    /// the flowless miss path when `flowless_fragment_requires_nat_translation`
    /// confirms a matching SNAT / static-NAT / DNAT / NPTv6 rule for the
    /// fragment's L3 identity but no association is present, so forwarding it
    /// untranslated would leak the internal source / pre-NAT destination.
    /// Batched like the sibling NAT drop counters and flushed to
    /// `BindingLiveState.nat_frag_untranslated_dropped`.
    #[inline]
    pub(in crate::afxdp) fn record_nat_frag_untranslated_dropped(&mut self) {
        self.touched = true;
        self.nat_frag_untranslated_dropped += 1;
    }

    /// #5623: record a fail-closed NAT64 SOURCE-ineligibility drop — an incoming
    /// IPv6 packet whose source lies within a configured Pref64 (looping /
    /// synthesized, the RFC 6146 §3.5 mandatory drop). Bumped at the pre-routing
    /// NAT64 classification (`classify_ipv6_packet` → `Nat64Match::IneligibleSource`)
    /// before any route lookup, policy, or `allocate_source`, so no session/BIB/
    /// allocation state is minted. Batched like the sibling nat64 drop counters
    /// and flushed to `BindingLiveState.nat64_ineligible_source`.
    #[inline]
    pub(in crate::afxdp) fn record_nat64_ineligible_source(&mut self) {
        self.touched = true;
        self.nat64_ineligible_source += 1;
    }

    /// #6475: record a fail-closed NAT64 DESTINATION-ineligibility drop — an
    /// incoming IPv6 packet whose NAT64-prefix-matched destination embeds a
    /// non-global IPv4 per RFC 6052 §3.1 (e.g. `64:ff9b::127.0.0.1`, which
    /// would otherwise LocalDeliver to the localhost-only control plane).
    /// Bumped at the pre-routing NAT64 classification
    /// (`classify_ipv6_packet`/`classify_ipv6_dest` →
    /// `Nat64Match::IneligibleDestination`) before any route lookup, policy, or
    /// `allocate_source`, so no session/BIB/allocation state is minted. Batched
    /// like the sibling nat64 drop counters and flushed to
    /// `BindingLiveState.nat64_ineligible_dest`.
    #[inline]
    pub(in crate::afxdp) fn record_nat64_ineligible_dest(&mut self) {
        self.touched = true;
        self.nat64_ineligible_dest += 1;
    }

    /// #5625: record a fail-closed NAT64 extension-header ineligibility drop —
    /// a v6→v4 forward translation rejected because the IPv6 packet carried an
    /// Authentication Header, an active Routing header (Segments Left > 0), or a
    /// Mobility / HIP / Shim6 header (RFC 7915 §5.1 / §5.1.1). Bumped from the
    /// TX dispatcher when `build_nat64_forwarded_frame` returns `None` and
    /// `nat64::frame_is_nat64_exthdr_ineligible` attributes the `None`. Batched
    /// like the sibling nat64 drop counters and flushed to
    /// `BindingLiveState.nat64_exthdr_ineligible`.
    #[inline]
    pub(in crate::afxdp) fn record_nat64_exthdr_ineligible(&mut self) {
        self.touched = true;
        self.nat64_exthdr_ineligible += 1;
    }

    fn flush(&mut self, live: &BindingLiveState) {
        if !self.touched {
            return;
        }
        if self.rx_packets != 0 {
            live.rx_packets
                .fetch_add(self.rx_packets, Ordering::Relaxed);
            self.rx_packets = 0;
        }
        if self.rx_bytes != 0 {
            live.rx_bytes.fetch_add(self.rx_bytes, Ordering::Relaxed);
            self.rx_bytes = 0;
        }
        if self.rx_batches != 0 {
            live.rx_batches
                .fetch_add(self.rx_batches, Ordering::Relaxed);
            self.rx_batches = 0;
        }
        if self.metadata_packets != 0 {
            live.metadata_packets
                .fetch_add(self.metadata_packets, Ordering::Relaxed);
            self.metadata_packets = 0;
        }
        if self.validated_packets != 0 {
            live.validated_packets
                .fetch_add(self.validated_packets, Ordering::Relaxed);
            self.validated_packets = 0;
        }
        if self.validated_bytes != 0 {
            live.validated_bytes
                .fetch_add(self.validated_bytes, Ordering::Relaxed);
            self.validated_bytes = 0;
        }
        if self.forward_candidate_packets != 0 {
            live.forward_candidate_packets
                .fetch_add(self.forward_candidate_packets, Ordering::Relaxed);
            self.forward_candidate_packets = 0;
        }
        if self.session_hits != 0 {
            live.session_hits
                .fetch_add(self.session_hits, Ordering::Relaxed);
            self.session_hits = 0;
        }
        if self.session_misses != 0 {
            live.session_misses
                .fetch_add(self.session_misses, Ordering::Relaxed);
            self.session_misses = 0;
        }
        if self.session_creates != 0 {
            live.session_creates
                .fetch_add(self.session_creates, Ordering::Relaxed);
            self.session_creates = 0;
        }
        if self.snat_packets != 0 {
            live.snat_packets
                .fetch_add(self.snat_packets, Ordering::Relaxed);
            self.snat_packets = 0;
        }
        if self.dnat_packets != 0 {
            live.dnat_packets
                .fetch_add(self.dnat_packets, Ordering::Relaxed);
            self.dnat_packets = 0;
        }
        if self.nat64_translations != 0 {
            live.nat64_translations
                .fetch_add(self.nat64_translations, Ordering::Relaxed);
            self.nat64_translations = 0;
        }
        if self.nat64_no_source_pool != 0 {
            live.nat64_no_source_pool
                .fetch_add(self.nat64_no_source_pool, Ordering::Relaxed);
            self.nat64_no_source_pool = 0;
        }
        // #4520: transient NAT64 pool-exhaustion tally, batched like its
        // config/empty sibling above.
        if self.nat64_pool_exhausted != 0 {
            live.nat64_pool_exhausted
                .fetch_add(self.nat64_pool_exhausted, Ordering::Relaxed);
            self.nat64_pool_exhausted = 0;
        }
        // #2562: fail-closed NAT64 fragment-drop tally, batched like the sibling
        // nat64 drop counters above.
        if self.nat64_frag_dropped != 0 {
            live.nat64_frag_dropped
                .fetch_add(self.nat64_frag_dropped, Ordering::Relaxed);
            self.nat64_frag_dropped = 0;
        }
        // #5623: fail-closed NAT64 source-ineligibility tally, batched like the
        // sibling nat64 drop counters above.
        if self.nat64_ineligible_source != 0 {
            live.nat64_ineligible_source
                .fetch_add(self.nat64_ineligible_source, Ordering::Relaxed);
            self.nat64_ineligible_source = 0;
        }
        // #6475: fail-closed NAT64 destination-ineligibility tally, batched
        // like the sibling nat64 drop counters above.
        if self.nat64_ineligible_dest != 0 {
            live.nat64_ineligible_dest
                .fetch_add(self.nat64_ineligible_dest, Ordering::Relaxed);
            self.nat64_ineligible_dest = 0;
        }
        // #5625: fail-closed NAT64 ext-header-ineligibility tally, batched like
        // the sibling nat64 drop counters above.
        if self.nat64_exthdr_ineligible != 0 {
            live.nat64_exthdr_ineligible
                .fetch_add(self.nat64_exthdr_ineligible, Ordering::Relaxed);
            self.nat64_exthdr_ineligible = 0;
        }
        // #4477: source-NAT allocation-failure tally.
        if self.nat_alloc_fail != 0 {
            live.nat_alloc_fail
                .fetch_add(self.nat_alloc_fail, Ordering::Relaxed);
            self.nat_alloc_fail = 0;
        }
        // #6122: fail-closed NAT'd non-first-fragment miss-drop tally, batched
        // like the sibling NAT drop counters above.
        if self.nat_frag_untranslated_dropped != 0 {
            live.nat_frag_untranslated_dropped
                .fetch_add(self.nat_frag_untranslated_dropped, Ordering::Relaxed);
            self.nat_frag_untranslated_dropped = 0;
        }
        // #1187 disposition-path counters
        if self.screen_drops != 0 {
            live.screen_drops
                .fetch_add(self.screen_drops, Ordering::Relaxed);
            self.screen_drops = 0;
        }
        // #3343: flush each non-zero per-reason screen-drop slot.
        for i in 0..crate::screen::SCREEN_REASON_DROP_COUNT {
            if self.screen_reason_drops[i] != 0 {
                live.screen_reason_drops[i].fetch_add(self.screen_reason_drops[i], Ordering::Relaxed);
                self.screen_reason_drops[i] = 0;
            }
        }
        if self.syn_cookie_challenges != 0 {
            live.syn_cookie_challenges
                .fetch_add(self.syn_cookie_challenges, Ordering::Relaxed);
            self.syn_cookie_challenges = 0;
        }
        if self.syn_cookie_secret_unavailable != 0 {
            live.syn_cookie_secret_unavailable
                .fetch_add(self.syn_cookie_secret_unavailable, Ordering::Relaxed);
            self.syn_cookie_secret_unavailable = 0;
        }
        if self.syn_cookie_syn_ack_sent != 0 {
            live.syn_cookie_syn_ack_sent
                .fetch_add(self.syn_cookie_syn_ack_sent, Ordering::Relaxed);
            self.syn_cookie_syn_ack_sent = 0;
        }
        if self.syn_cookie_ack_rst_sent != 0 {
            live.syn_cookie_ack_rst_sent
                .fetch_add(self.syn_cookie_ack_rst_sent, Ordering::Relaxed);
            self.syn_cookie_ack_rst_sent = 0;
        }
        if self.syn_cookie_reply_budget_drops != 0 {
            live.syn_cookie_reply_budget_drops
                .fetch_add(self.syn_cookie_reply_budget_drops, Ordering::Relaxed);
            self.syn_cookie_reply_budget_drops = 0;
        }
        if self.syn_cookie_ack_valid != 0 {
            live.syn_cookie_ack_valid
                .fetch_add(self.syn_cookie_ack_valid, Ordering::Relaxed);
            self.syn_cookie_ack_valid = 0;
        }
        if self.syn_cookie_ack_invalid != 0 {
            live.syn_cookie_ack_invalid
                .fetch_add(self.syn_cookie_ack_invalid, Ordering::Relaxed);
            self.syn_cookie_ack_invalid = 0;
        }
        if self.syn_cookie_bypass != 0 {
            live.syn_cookie_bypass
                .fetch_add(self.syn_cookie_bypass, Ordering::Relaxed);
            self.syn_cookie_bypass = 0;
        }
        if self.policy_reject_sent != 0 {
            live.policy_reject_sent
                .fetch_add(self.policy_reject_sent, Ordering::Relaxed);
            self.policy_reject_sent = 0;
        }
        if self.filter_reject_sent != 0 {
            live.filter_reject_sent
                .fetch_add(self.filter_reject_sent, Ordering::Relaxed);
            self.filter_reject_sent = 0;
        }
        if self.policy_reject_reply_budget_drops != 0 {
            live.policy_reject_reply_budget_drops
                .fetch_add(self.policy_reject_reply_budget_drops, Ordering::Relaxed);
            self.policy_reject_reply_budget_drops = 0;
        }
        if self.filter_reject_reply_budget_drops != 0 {
            live.filter_reject_reply_budget_drops
                .fetch_add(self.filter_reject_reply_budget_drops, Ordering::Relaxed);
            self.filter_reject_reply_budget_drops = 0;
        }
        if self.policy_reject_rate_limit_drops != 0 {
            live.policy_reject_rate_limit_drops
                .fetch_add(self.policy_reject_rate_limit_drops, Ordering::Relaxed);
            self.policy_reject_rate_limit_drops = 0;
        }
        if self.filter_reject_rate_limit_drops != 0 {
            live.filter_reject_rate_limit_drops
                .fetch_add(self.filter_reject_rate_limit_drops, Ordering::Relaxed);
            self.filter_reject_rate_limit_drops = 0;
        }
        if self.time_exceeded_output_filter_drops != 0 {
            live.time_exceeded_output_filter_drops
                .fetch_add(self.time_exceeded_output_filter_drops, Ordering::Relaxed);
            self.time_exceeded_output_filter_drops = 0;
        }
        if self.policy_reject_output_filter_drops != 0 {
            live.policy_reject_output_filter_drops
                .fetch_add(self.policy_reject_output_filter_drops, Ordering::Relaxed);
            self.policy_reject_output_filter_drops = 0;
        }
        if self.filter_reject_output_filter_drops != 0 {
            live.filter_reject_output_filter_drops
                .fetch_add(self.filter_reject_output_filter_drops, Ordering::Relaxed);
            self.filter_reject_output_filter_drops = 0;
        }
        if self.syn_cookie_output_filter_drops != 0 {
            live.syn_cookie_output_filter_drops
                .fetch_add(self.syn_cookie_output_filter_drops, Ordering::Relaxed);
            self.syn_cookie_output_filter_drops = 0;
        }
        if self.ptb_output_filter_drops != 0 {
            live.ptb_output_filter_drops
                .fetch_add(self.ptb_output_filter_drops, Ordering::Relaxed);
            self.ptb_output_filter_drops = 0;
        }
        if self.generated_reply_classify_parse_errors != 0 {
            live.generated_reply_classify_parse_errors
                .fetch_add(self.generated_reply_classify_parse_errors, Ordering::Relaxed);
            self.generated_reply_classify_parse_errors = 0;
        }
        if self.policy_denied_packets != 0 {
            live.policy_denied_packets
                .fetch_add(self.policy_denied_packets, Ordering::Relaxed);
            self.policy_denied_packets = 0;
        }
        if self.host_inbound_denied_packets != 0 {
            live.host_inbound_denied_packets
                .fetch_add(self.host_inbound_denied_packets, Ordering::Relaxed);
            self.host_inbound_denied_packets = 0;
        }
        if self.route_miss_packets != 0 {
            live.route_miss_packets
                .fetch_add(self.route_miss_packets, Ordering::Relaxed);
            self.route_miss_packets = 0;
        }
        // #4743: martian-dst NoRoute sub-tally, batched like route_miss above.
        if self.martian_dropped != 0 {
            live.martian_dropped
                .fetch_add(self.martian_dropped, Ordering::Relaxed);
            self.martian_dropped = 0;
        }
        // #4743: over-limit IPv6 ext-header fail-closed-drop tally.
        if self.ipv6_ext_header_dropped != 0 {
            live.ipv6_ext_header_dropped
                .fetch_add(self.ipv6_ext_header_dropped, Ordering::Relaxed);
            self.ipv6_ext_header_dropped = 0;
        }
        if self.neighbor_miss_packets != 0 {
            live.neighbor_miss_packets
                .fetch_add(self.neighbor_miss_packets, Ordering::Relaxed);
            self.neighbor_miss_packets = 0;
        }
        if self.discard_route_packets != 0 {
            live.discard_route_packets
                .fetch_add(self.discard_route_packets, Ordering::Relaxed);
            self.discard_route_packets = 0;
        }
        if self.next_table_packets != 0 {
            live.next_table_packets
                .fetch_add(self.next_table_packets, Ordering::Relaxed);
            self.next_table_packets = 0;
        }
        if self.local_delivery_packets != 0 {
            live.local_delivery_packets
                .fetch_add(self.local_delivery_packets, Ordering::Relaxed);
            self.local_delivery_packets = 0;
        }
        if self.exception_packets != 0 {
            live.exception_packets
                .fetch_add(self.exception_packets, Ordering::Relaxed);
            self.exception_packets = 0;
        }
        self.touched = false;
    }
}

pub(in crate::afxdp) mod poll_descriptor;
use poll_descriptor::poll_binding_process_descriptor;

// #946 Phase 1: per-packet pipeline stages extracted from the
// while-let body in `poll_binding_process_descriptor`. See
// `docs/pr/946-pipeline-phase1/plan.md` for the full plan.
mod poll_stages;

// Issue 67.1: session-delta processing (flush_session_deltas et al.)
// extracted into afxdp/session_delta.rs.
mod session_delta;
use session_delta::{flush_session_deltas, purge_queued_flows_for_closed_deltas};

// #1651 B3: dead-host negative neighbor cache helpers.
mod neg_neigh;
use neg_neigh::{neg_neigh_gate, neg_neigh_record};

// #5288: bounded, per-worker rate limiter for kernel neighbor-table
// programming on the data-path ARP/NDP learn. Skips the netlink
// socket()/sendto()/close() + allocations for same-key/same-MAC repeats and
// rate-caps a changed-flood so an accepted-advert flood cannot starve the XSK
// worker.
mod neighbor_program_limiter;
use neighbor_program_limiter::KernelNeighborProgramLimiter;

// #1769: shared, per-key, rate-limited on-demand neighbor resolver. On a
// negative-cache fast-fail the worker enqueues the dst here; the resolver
// thread issues a single-key RTM_GETNEIGH, caches a confirmed lladdr
// (epoch-guarded) or probes to force kernel revalidation on a stale one.
mod neighbor_resolver;
use neighbor_resolver::{
    NeighborResolver, NeighborResolverCounters, RESOLVER_ENQUEUE_THROTTLE_NS, ResolveItem,
    neighbor_resolver_loop,
};

// #1772: neighbor/ARP resolution LATENCY histograms (observability-only).
// Cheap fixed-bucket aggregate histograms for pending-dwell + resolver
// GETNEIGH RTT, plus timeout-drop / max-depth counters.
mod neighbor_latency;
use neighbor_latency::NeighborLatencyTelemetry;

// Issue 67.2: neighbor-dispatch helpers extracted into
// afxdp/neighbor_dispatch.rs.
mod neighbor_dispatch;
use neighbor_dispatch::{
    PendingNeighAdmission, build_missing_neighbor_session_metadata,
    learn_dynamic_neighbor_from_packet, pending_neigh_admission, pending_neigh_flow_key,
    record_pending_neigh_admission_drop, retry_pending_neigh,
};
// `learn_dynamic_neighbor` / `pair_write_needed` are only referenced
// by tests in afxdp/forwarding/tests.rs and afxdp/tests.rs; gate the
// imports behind cfg(test) so non-test builds don't trip
// `unused_imports`.
#[cfg(test)]
use neighbor_dispatch::{learn_dynamic_neighbor, pair_write_needed};

// Issue 67.3: disposition / telemetry recording extracted into
// afxdp/disposition.rs.
mod disposition;
use disposition::{
    DispositionCounters, ExceptionEvent, ExceptionEventRing, ResolutionEvent, control_notice_event,
    record_disposition, record_exception, record_exception_owned, record_exception_suffixed,
    record_forwarding_disposition, record_source_nat_exception,
};

// Issue 67.4: forward-request builders extracted into
// afxdp/forward_request.rs.
mod forward_request;
use forward_request::{
    ForwardRejectReply, build_live_forward_request_from_frame, should_install_local_reverse_session,
};
// `build_live_forward_request` is only referenced by tests in
// afxdp/frame/tests.rs; gate its import behind cfg(test).
#[cfg(test)]
use forward_request::build_live_forward_request;

#[derive(Clone, Copy, Debug, Default)]
struct PendingForwardHints {
    expected_ports: Option<(u16, u16)>,
    target_binding_index: Option<usize>,
}

// Superseded by inline logic in build_live_forward_request() that reads ports
// from the live UMEM area before .to_vec() copy (fixes #199).  Retained for
// its unit test and potential future use.
#[allow(dead_code)]

fn binding_by_index_mut<'a>(
    left: &'a mut [BindingWorker],
    current_index: usize,
    current: &'a mut BindingWorker,
    right: &'a mut [BindingWorker],
    target_index: usize,
) -> Option<&'a mut BindingWorker> {
    if target_index == current_index {
        return Some(current);
    }
    if target_index < current_index {
        return left.get_mut(target_index);
    }
    right.get_mut(target_index.saturating_sub(current_index + 1))
}

fn find_target_binding_mut<'a>(
    left: &'a mut [BindingWorker],
    current_index: usize,
    ingress_binding: &'a mut BindingWorker,
    ingress_queue_id: u32,
    right: &'a mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    egress_ifindex: i32,
) -> Option<&'a mut BindingWorker> {
    let target_index = binding_lookup.target_index(
        current_index,
        ingress_binding.ifindex,
        ingress_queue_id,
        egress_ifindex,
    )?;
    binding_by_index_mut(left, current_index, ingress_binding, right, target_index)
}
