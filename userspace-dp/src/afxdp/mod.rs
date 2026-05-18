use super::{
    BindingStatus, ConfigSnapshot, ExceptionStatus, HAGroupStatus, InjectPacketRequest,
    InterfaceSnapshot, PacketResolution, SessionDeltaInfo,
};
use crate::nat::{
    DnatTable, NatDecision, SourceNatRule, StaticNatTable, match_source_nat, parse_source_nat_rules,
};
use crate::nat64::{Nat64ReverseInfo, Nat64State};
use crate::nptv6::Nptv6State;
use crate::policy::{
    PolicyAction, PolicyCounterStore, PolicyState, evaluate_policy, parse_policy_state_with_counters,
};
use crate::prefix::{PrefixV4, PrefixV6};
use crate::screen::{ScreenProfile, ScreenState, ScreenVerdict, extract_screen_info};
use crate::session::{
    ForwardSessionMatch, SessionDecision, SessionDelta, SessionDeltaKind, SessionKey,
    SessionLookup, SessionMetadata, SessionOrigin, SessionTable, forward_wire_key,
    reverse_canonical_key, reverse_session_key,
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
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicU32, AtomicU64, Ordering};
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
#[path = "bpf_map.rs"]
mod bpf_map;
#[path = "checksum.rs"]
mod checksum;
#[path = "flow_cache.rs"]
mod flow_cache;
#[path = "forwarding/mod.rs"]
mod forwarding;
#[path = "forwarding_build.rs"]
mod forwarding_build;
#[path = "frame/mod.rs"]
mod frame;
#[path = "mpsc_inbox.rs"]
mod mpsc_inbox;
#[path = "gre.rs"]
mod gre;
#[path = "ha.rs"]
mod ha;
#[path = "icmp.rs"]
mod icmp;
#[path = "icmp_embed.rs"]
mod icmp_embed;
#[path = "ethernet.rs"]
mod ethernet;
#[path = "mirror.rs"]
mod mirror;
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
mod session_glue;
#[path = "cos/mod.rs"]
mod cos;
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
use self::bpf_map::*;
use self::checksum::*;
use self::flow_cache::*;
use self::forwarding::*;
use self::forwarding_build::*;
use self::frame::*;
use self::tx::dispatch::*;
use self::gre::{encapsulate_native_gre_frame, try_native_gre_decap_from_frame};
use self::icmp::{FABRIC_INGRESS_FLAG, build_local_time_exceeded_request, is_icmp_error};
#[cfg(test)]
use self::icmp::{
    build_local_time_exceeded_v4, build_local_time_exceeded_v6, packet_ttl_would_expire,
};
#[cfg(test)]
use self::icmp_embed::{
    EmbeddedIcmpMatch, try_embedded_icmp_nat_match_from_frame,
    try_embedded_icmp_session_match_from_frame,
};
use self::icmp_embed::{
    build_nat_reversed_icmp_error_v4, build_nat_reversed_icmp_error_v6,
    finalize_embedded_icmp_resolution, try_embedded_icmp_nat_match,
};
use self::mirror::*;
use self::neighbor::*;
pub use self::neighbor::{neighbor_state_usable_str, parse_mac_str};
pub(crate) use self::rst::remove_kernel_rst_suppression;
use self::sharded_neighbor::ShardedNeighborMap;
use self::rst::*;
use self::session_glue::*;
use self::shared_ops::*;
use self::shared_umem::*;
use self::tunnel::*;
use self::mpsc_inbox::MpscInbox;
use self::tx::*;
use self::types::*;
pub(crate) use self::types::{ForwardingDisposition, ForwardingResolution, NeighborEntry};
use self::umem::*;

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
// `MAX_RX_BATCHES_PER_POLL`; (c) the rate-quantum test
// `guarantee_phase_*_visit_quantum` in tx.rs. The const_asserts
// below force the change to fail compilation rather than silently
// regress the validation surface.
const RX_BATCH_SIZE: u32 = 64;
const _: () = assert!(
    RX_BATCH_SIZE == 64,
    "changing RX_BATCH_SIZE requires re-validating L1d footprint and per-poll budget"
);
const MIN_RESERVED_TX_FRAMES: u32 = 256;
const MAX_RESERVED_TX_FRAMES: u32 = 8192;
const TX_BATCH_SIZE: usize = 64;
const _: () = assert!(
    TX_BATCH_SIZE == 64,
    "changing TX_BATCH_SIZE requires re-validating COS guarantee quantum + snapshot stack bound"
);
const PENDING_TX_LIMIT_MULTIPLIER: usize = 2;
const FILL_BATCH_SIZE: usize = 1024;
const MAX_RX_BATCHES_PER_POLL: usize = 4;
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
const HEARTBEAT_UPDATE_INTERVAL_NS: u64 = 250_000_000;
/// Grace period after binding before writing heartbeat. During this window
/// the XDP shim sees no heartbeat → XDP_PASS → kernel forwards packets AND
/// NAPI bootstraps the NIC's XSK receive queue from the fill ring. After
/// this period, heartbeat is written and the XDP shim redirects to XSK.
/// Must exceed the Go-side ctrl enable delay (3s) plus time for
/// NAPI to bootstrap the XSK RQ from the fill ring (~2-3 seconds).
#[allow(dead_code)] // reserved for heartbeat gating logic
const HEARTBEAT_GRACE_PERIOD_NS: u64 = 6_000_000_000; // 6 seconds
const TX_WAKE_MIN_INTERVAL_NS: u64 = 50_000;
const HEARTBEAT_STALE_AFTER: Duration = Duration::from_secs(5);
const MAX_RECENT_EXCEPTIONS: usize = 32;
const MAX_RECENT_SESSION_DELTAS: usize = 64;
const MAX_PENDING_SESSION_DELTAS: usize = 4096;
const BIND_RETRY_ATTEMPTS: usize = 20;
const BIND_RETRY_DELAY: Duration = Duration::from_millis(250);
const DEFAULT_SLOW_PATH_TUN: &str = "xpf-usp0";
const LOCAL_TUNNEL_DELIVERY_QUEUE_DEPTH: usize = 4096;
const HA_WATCHDOG_STALE_AFTER_SECS: u64 = 10;
const FABRIC_ZONE_MAC_MAGIC: u8 = 0xfe;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMP: u8 = 1;
const PROTO_ICMPV6: u8 = 58;
#[allow(dead_code)]
const PROTO_GRE: u8 = 47;
const PROTO_ESP: u8 = 50;
const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_PSH: u8 = 0x08;
const TCP_FLAG_SYN: u8 = 0x02;
const TUNNEL_HA_STARTUP_GRACE_SECS: u64 = 10;
const SOL_XDP: c_int = 283;
const XDP_OPTIONS: c_int = 8;
const XDP_OPTIONS_ZEROCOPY: u32 = 1;

const PENDING_NEIGH_TIMEOUT_NS: u64 = 2_000_000_000; // 2 seconds
// GEMINI-NEXT.md Section 3 cold start: admission cap bumped 64 → 4096 so a
// per-binding burst of new connections during the ARP/NDP probe window
// doesn't drop frames. PendingNeighPacket is 264 B on x86_64 (XdpDesc +
// UserspaceDpMeta + SessionDecision + flow key + queued_ns + probe_attempts),
// so worst-case per binding when the queue is fully populated is ~1.0 MiB.
// To avoid paying that ~1.0 MiB up front per binding × N bindings, the
// underlying VecDeque is now constructed with `VecDeque::new()` (zero
// capacity) at worker init — see worker/mod.rs.
// The buffer grows on push only when traffic actually queues up, and the
// 4096 admission check in poll_descriptor.rs enforces the upper bound.
// This unblocks parallel-connect storms during cluster failback while
// keeping idle-binding RSS near zero.
const MAX_PENDING_NEIGH: usize = 4096;

#[inline]
const fn tx_frame_capacity() -> usize {
    UMEM_FRAME_SIZE as usize
}

#[path = "coordinator/mod.rs"]
mod coordinator;
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
#[path = "worker/mod.rs"]
mod worker;
#[path = "worker_runtime.rs"]
mod worker_runtime;
pub use self::coordinator::Coordinator;
pub(crate) use self::worker::{
    BindingLiveSnapshot, BindingWorker, SyncedSessionEntry, XskBindMode, fabric_queue_hash,
    push_recent_exception, push_recent_session_delta, worker_loop,
};

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
    // #1187: 8 disposition-path counters added to eliminate per-packet
    // MESI thrash on BindingLiveState atomics during DDoS / config-
    // reload windows. See docs/pr/1187-telemetry-double-buffer/plan.md
    // (v7 PLAN-READY).
    screen_drops: u64,
    syn_cookie_challenges: u64,
    syn_cookie_secret_unavailable: u64,
    syn_cookie_ack_valid: u64,
    syn_cookie_ack_invalid: u64,
    syn_cookie_bypass: u64,
    policy_denied_packets: u64,
    route_miss_packets: u64,
    neighbor_miss_packets: u64,
    discard_route_packets: u64,
    next_table_packets: u64,
    local_delivery_packets: u64,
    exception_packets: u64,
}

impl BatchCounters {
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
        // #1187 disposition-path counters
        if self.screen_drops != 0 {
            live.screen_drops
                .fetch_add(self.screen_drops, Ordering::Relaxed);
            self.screen_drops = 0;
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
        if self.policy_denied_packets != 0 {
            live.policy_denied_packets
                .fetch_add(self.policy_denied_packets, Ordering::Relaxed);
            self.policy_denied_packets = 0;
        }
        if self.route_miss_packets != 0 {
            live.route_miss_packets
                .fetch_add(self.route_miss_packets, Ordering::Relaxed);
            self.route_miss_packets = 0;
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

mod poll_descriptor;
use poll_descriptor::poll_binding_process_descriptor;

// #946 Phase 1: per-packet pipeline stages extracted from the
// while-let body in `poll_binding_process_descriptor`. See
// `docs/pr/946-pipeline-phase1/plan.md` for the full plan.
mod poll_stages;

// Issue 67.1: session-delta processing (flush_session_deltas et al.)
// extracted into afxdp/session_delta.rs.
mod session_delta;
use session_delta::{flush_session_deltas, purge_queued_flows_for_closed_deltas};

// Issue 67.2: neighbor-dispatch helpers extracted into
// afxdp/neighbor_dispatch.rs.
mod neighbor_dispatch;
use neighbor_dispatch::{
    build_missing_neighbor_session_metadata, learn_dynamic_neighbor_from_packet,
    retry_pending_neigh,
};
// `learn_dynamic_neighbor` is only referenced by tests in
// afxdp/forwarding/tests.rs and afxdp/tests.rs; gate its import behind
// cfg(test) so non-test builds don't trip `unused_imports`.
#[cfg(test)]
use neighbor_dispatch::learn_dynamic_neighbor;

// Issue 67.3: disposition / telemetry recording extracted into
// afxdp/disposition.rs.
mod disposition;
use disposition::{
    DispositionCounters, record_disposition, record_exception, record_forwarding_disposition,
};
// `update_last_resolution` is only referenced by tests in afxdp/tests.rs;
// gate its import behind cfg(test).
#[cfg(test)]
use disposition::update_last_resolution;

// Issue 67.4: forward-request builders extracted into
// afxdp/forward_request.rs.
mod forward_request;
use forward_request::{build_live_forward_request_from_frame, should_install_local_reverse_session};
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
