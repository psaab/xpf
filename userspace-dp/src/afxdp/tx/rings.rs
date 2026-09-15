// XSK kernel-ring discipline: completion drain, fill submit, RX/TX
// kernel wake. Single-writer (owner worker); atomic ops use
// `Ordering::Relaxed`.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::afxdp::neighbor::monotonic_nanos;
use crate::afxdp::types::PreparedTxRecycle;
use crate::afxdp::worker::{BindingWorker, WorkerTelemetry};
use crate::afxdp::{
    FILL_BATCH_SIZE, FILL_WAKE_SAFETY_INTERVAL_NS, RX_WAKE_IDLE_POLLS, RX_WAKE_MIN_INTERVAL_NS,
    TX_WAKE_MIN_INTERVAL_NS, UMEM_FRAME_SIZE, XskBindMode,
};

use super::stats::{record_kick_latency, record_tx_completions_with_stamp};
use super::update_binding_debug_state;

/// #9900 F-092: TX completions reaped beyond `outstanding_tx` (including
/// completions drained at gauge 0, which are definitionally stale). The old
/// `saturating_sub` hid this skew; the counter surfaces it.
pub(in crate::afxdp) static TX_COMPLETION_SKEW_TOTAL: AtomicU64 = AtomicU64::new(0);
/// #9900 F-092: reaped completion offsets dropped instead of recycled (not an
/// aligned in-region frame base).
pub(in crate::afxdp) static TX_COMPLETION_INVALID_TOTAL: AtomicU64 = AtomicU64::new(0);
/// #9900 F-091/F-092: fill-ring offsets dropped instead of submitted (frame
/// base outside the owned region — the kernel masks to base, so the remainder
/// is never the reason).
pub(in crate::afxdp) static FILL_INVALID_TOTAL: AtomicU64 = AtomicU64::new(0);
/// #9900 F-092 (GPT-2): aligned in-region completions dropped because the
/// offset has no untracked-submit ownership — a duplicate or stale delivery
/// (or a tracked completion re-delivered after its recycle entry was
/// consumed). Recycling any of these would double-push the free pool.
pub(in crate::afxdp) static TX_COMPLETION_DUPLICATE_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Byte length of this binding's UMEM region (the range every offset it
/// recycles or submits must sit in). This is the REGION count — on shared
/// UMEM it exceeds the binding's own frame count, and shared-pool offsets
/// above the binding's sidecar are legitimate here.
#[inline]
fn umem_region_len(binding: &BindingWorker) -> u64 {
    (binding.umem.total_frames() as u64) * (UMEM_FRAME_SIZE as u64)
}

/// #9900 F-092: whether a completion offset may return to the TX free pool.
/// Untracked completions (no `in_flight_prepared_recycles` entry) are local-TX
/// and `FreeTxFrame` submits, which are aligned pool pops — so an unaligned
/// or out-of-region offset is a kernel fault, not a frame, and must be
/// dropped. (Unaligned in-place submits always pair with a `Fill*` recycle
/// and take the tracked path instead.)
#[inline]
fn completion_offset_returnable_to_free_pool(offset: u64, region_len: u64) -> bool {
    offset % (UMEM_FRAME_SIZE as u64) == 0 && offset < region_len
}

/// #9900 F-091/F-092: whether a fill-ring offset may be submitted to the
/// kernel. The kernel masks fill addrs to the chunk base (`xp_check_aligned`
/// in `net/xdp/xsk_buff_pool.c`) and indexes the chunk by it, so ANY
/// in-region offset submits the same frame — only the frame BASE must be
/// owned (in-region). Legitimate shapes are bases (initial fill) and
/// post-headroom RX addrs (steady-state recycles at base + 512, which is
/// `UMEM_HEADROOM` + `XDP_PACKET_HEADROOM`: the kernel sums the configured
/// frame headroom with its own 256 — `xsk_pool_get_headroom` — and hands
/// back `xdp.data`, NOT the chunk base). Constraining the intra-frame
/// remainder here would discard ordinary native RX and starve reception.
#[inline]
fn fill_offset_submittable(offset: u64, region_len: u64) -> bool {
    (offset & !((UMEM_FRAME_SIZE as u64) - 1)) < region_len
}

/// #9900 F-092: fold a reap batch into the gauge, counting over-delivery
/// instead of hiding it. Returns `(new_gauge, skew_delta)`; the caller adds
/// the delta to `TX_COMPLETION_SKEW_TOTAL`.
#[inline]
fn account_tx_completions(outstanding_tx: u32, reaped: u32) -> (u32, u64) {
    match outstanding_tx.checked_sub(reaped) {
        Some(left) => (left, 0),
        None => (0, (reaped - outstanding_tx) as u64),
    }
}

pub(in crate::afxdp) fn reap_tx_completions(
    binding: &mut BindingWorker,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> u32 {
    // #9900 F-092: NO `outstanding_tx == 0` early-return — it hid skew
    // permanently (a completion ring with entries at gauge 0 never drained).
    // The `available == 0 → None` fast path below keeps the idle cost at one
    // shared-memory read.
    let Some(available) = record_tx_completion_ring_available_for_reap(
        &mut binding.telemetry,
        binding.xsk.device.available(),
    ) else {
        return 0;
    };
    let mut reaped = 0u32;
    binding.scratch.scratch_completed_offsets.clear();
    let mut completed = binding.xsk.device.complete(available);
    while let Some(offset) = completed.read() {
        binding.scratch.scratch_completed_offsets.push(offset);
        reaped += 1;
    }
    completed.release();
    drop(completed);
    // #812: completion stamp — single fresh `monotonic_nanos()` for
    // the entire reap batch (plan §3.1 completion-ts site). Amortised
    // one VDSO call per reap (worst-case ~15 ns / TX_BATCH_SIZE-packet
    // batch = ~0.23 ns/pkt at the post-#920 batch of 64;
    // ~15 ns/pkt on the `reaped == 1` partial-batch worst case —
    // same shape as the submit-stamp cost analysis in plan §3.4).
    // #9900 F-092: at gauge 0 every completion is definitionally stale — all
    // six submit sites bump the gauge and the reap decrement is the only
    // drain — so the ring is drained WITHOUT recycling or sidecar folding.
    // Recycling here would double-push a frame the pool already holds.
    let stale_drain = binding.tx_pipeline.outstanding_tx == 0;
    if !stale_drain {
        let ts_completion = monotonic_nanos();
        // #812: delegate the per-offset fold to the shared helper so
        // tests exercising `record_tx_completions_with_stamp` cover the
        // exact production algorithm — NOT a test-only fake. See unit
        // pins under `#[cfg(test)]` below.
        record_tx_completions_with_stamp(
            &mut binding.tx_pipeline.tx_submit_ns,
            &binding.scratch.scratch_completed_offsets,
            ts_completion,
            &binding.live.owner_profile_owner,
        );
        for i in 0..binding.scratch.scratch_completed_offsets.len() {
            let offset = binding.scratch.scratch_completed_offsets[i];
            recycle_completed_tx_offset(binding, shared_recycles, offset);
        }
    }
    // #9900 F-092: count over-delivery instead of saturating it away. The
    // `reaped > outstanding > 0` residual (a bogus offset inside an otherwise
    // legitimate batch) still recycles after range/align filtering — the
    // batch members are indistinguishable without an ownership bitmap.
    let outstanding_before = binding.tx_pipeline.outstanding_tx;
    let (gauge, skew) = account_tx_completions(outstanding_before, reaped);
    binding.tx_pipeline.outstanding_tx = gauge;
    if skew != 0 && TX_COMPLETION_SKEW_TOTAL.fetch_add(skew, Ordering::Relaxed) < 10 {
        eprintln!(
            "TX_COMPLETION_SKEW: slot={} if={} q={} reaped={} outstanding_before={} (kernel over-delivered completions)",
            binding.slot, binding.ifindex, binding.queue_id, reaped, outstanding_before,
        );
    }
    binding.telemetry.dbg_completions_reaped += reaped as u64;
    binding
        .live
        .tx_completions
        .fetch_add(reaped as u64, Ordering::Relaxed);
    update_binding_debug_state(binding);
    reaped
}

fn record_tx_completion_ring_available(telemetry: &mut WorkerTelemetry, available: u32) {
    telemetry.dbg_tx_completion_ring_available = available;
    telemetry.dbg_tx_completion_ring_available_max = telemetry
        .dbg_tx_completion_ring_available_max
        .max(available);
}

#[must_use]
fn record_tx_completion_ring_available_for_reap(
    telemetry: &mut WorkerTelemetry,
    available: u32,
) -> Option<u32> {
    record_tx_completion_ring_available(telemetry, available);
    if available == 0 {
        None
    } else {
        Some(available)
    }
}

pub(in crate::afxdp) fn drain_pending_fill(binding: &mut BindingWorker, now_ns: u64) -> bool {
    if binding.tx_pipeline.pending_fill_frames.is_empty() {
        return false;
    }
    let batch_size = binding.tx_pipeline.pending_fill_frames.len().min(FILL_BATCH_SIZE);
    binding.scratch.scratch_fill.clear();
    while binding.scratch.scratch_fill.len() < batch_size {
        let Some(offset) = binding.tx_pipeline.pending_fill_frames.pop_front() else {
            break;
        };
        // #9900 F-091/F-092: validate before handing the offset to the kernel.
        // A bad offset is DROPPED (neither submitted nor pushed back — pushing
        // back would re-queue poison forever) and counted.
        if !fill_offset_submittable(offset, umem_region_len(binding)) {
            if FILL_INVALID_TOTAL.fetch_add(1, Ordering::Relaxed) < 10 {
                eprintln!(
                    "FILL_INVALID: slot={} if={} q={} offset={} (frame base outside the owned region; dropped, not submitted)",
                    binding.slot, binding.ifindex, binding.queue_id, offset,
                );
            }
            continue;
        }
        // Poison the frame before submitting to fill ring — the kernel should
        // overwrite this with real packet data on RX. If we ever read back the
        // poison pattern in the RX path, it means the kernel recycled a
        // descriptor without writing packet data (stale/uninit frame).
        if cfg!(feature = "debug-log") {
            if let Some(frame) =
                unsafe { binding.umem.area().slice_mut_unchecked(offset as usize, 8) }
            {
                frame.copy_from_slice(&0xDEAD_BEEF_DEAD_BEEFu64.to_ne_bytes());
            }
        }
        binding.scratch.scratch_fill.push(offset);
    }
    if binding.scratch.scratch_fill.is_empty() {
        return false;
    }
    let inserted = {
        let mut fill = binding.xsk.device.fill(binding.scratch.scratch_fill.len() as u32);
        let inserted = fill.insert(binding.scratch.scratch_fill.iter().copied());
        fill.commit();
        inserted
    };
    if inserted == 0 {
        binding.telemetry.dbg_fill_failed += binding.scratch.scratch_fill.len() as u64;
        for offset in binding.scratch.scratch_fill.drain(..).rev() {
            binding.tx_pipeline.pending_fill_frames.push_front(offset);
        }
        return false;
    }
    binding.telemetry.dbg_fill_submitted += inserted as u64;
    if inserted < binding.scratch.scratch_fill.len() as u32 {
        binding.telemetry.dbg_fill_failed += (binding.scratch.scratch_fill.len() as u32 - inserted) as u64;
        for offset in binding.scratch.scratch_fill.drain(inserted as usize..).rev() {
            binding.tx_pipeline.pending_fill_frames.push_front(offset);
        }
    }
    binding.scratch.scratch_fill.clear();
    // Only wake NAPI when the kernel signals it needs fill ring entries,
    // or as a safety net every FILL_WAKE_SAFETY_INTERVAL_NS to prevent
    // lost-wakeup stalls from the race between commit() and needs_wakeup.
    // Without the needs_wakeup gate, every drain triggers a sendto() syscall
    // (142K/sec at line rate), spending ~20% CPU in syscall entry/exit.
    if binding.xsk.device.needs_wakeup()
        || now_ns.saturating_sub(binding.timers.last_rx_wake_ns) >= FILL_WAKE_SAFETY_INTERVAL_NS
    {
        maybe_wake_rx(binding, true, now_ns);
    }
    update_binding_debug_state(binding);
    true
}

/// The unforced half of `maybe_wake_rx`'s gate, extracted so the throttle can
/// be tested without a bound socket (#8377).
///
/// WHAT THIS IS. A rate limiter on the steady-state RX keep-alive wake: at most
/// one `poll(POLLIN)` per `RX_WAKE_MIN_INTERVAL_NS`, and only after
/// `RX_WAKE_IDLE_POLLS` consecutive empty polls. Without the throttle the wake
/// fires on every empty poll and costs a syscall per loop iteration.
///
/// WHAT THIS IS NOT — recorded because a draft of #8377's fix asserted it was.
/// This is NOT a guarantee that a queue which has never seen a hardware RX
/// event gets its fill ring consumed. The syscall it eventually issues reaches
/// `mlx5e_xsk_wakeup`, which returns 0 without triggering NAPI when the channel
/// NAPI is already scheduled (`napi_if_scheduled_mark_missed`) or an XSK-TX NOP
/// is already pending (`MLX5E_SQ_STATE_PENDING_XSK_TX`) — and `e0c01ac2b`
/// records measuring exactly that: "ndo_xsk_wakeup's ICOSQ NOP mechanism fails
/// when NAPI is already scheduled from other sources". The Go NAPI probes
/// (`pkg/dataplane/userspace/process_napi.go`) remain load-bearing for cold
/// bringup; do not delete them on the strength of this path.
///
/// Behaviour-identical to the two sequential early returns it replaces.
fn rx_wake_due(empty_rx_polls: u32, last_rx_wake_ns: u64, now_ns: u64) -> bool {
    empty_rx_polls >= RX_WAKE_IDLE_POLLS
        && now_ns.saturating_sub(last_rx_wake_ns) >= RX_WAKE_MIN_INTERVAL_NS
}

pub(in crate::afxdp) fn maybe_wake_rx(binding: &mut BindingWorker, force: bool, now_ns: u64) {
    // After submitting fill ring entries, we must kick NAPI so the driver
    // consumes them and posts new RX WQEs. Without this, mlx5 increments
    // rx_xsk_buff_alloc_err and silently drops all incoming packets.
    //
    // poll(POLLIN) triggers xsk_poll → ndo_xsk_wakeup(XDP_WAKEUP_RX),
    // which makes the driver consume fill ring entries and post WQEs.
    // sendto() only triggers XDP_WAKEUP_TX (TX kick), NOT RX fill ring
    // processing — using sendto() for RX wake was the root cause of
    // fill ring starvation on idle interfaces with zero-copy mlx5.
    if !force {
        binding.timers.empty_rx_polls = binding.timers.empty_rx_polls.saturating_add(1);
        if !rx_wake_due(
            binding.timers.empty_rx_polls,
            binding.timers.last_rx_wake_ns,
            now_ns,
        ) {
            return;
        }
    }
    let fd = binding.xsk.device.as_raw_fd();
    // Use poll(POLLIN) for RX wakeup — triggers XDP_WAKEUP_RX.
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
    if rc >= 0 {
        binding.telemetry.dbg_rx_wake_sendto_ok += 1;
    } else {
        binding.telemetry.dbg_rx_wake_sendto_err += 1;
        binding.telemetry.dbg_rx_wake_sendto_errno = unsafe { *libc::__errno_location() };
    }
    // Also sendto for TX completions (needed for copy mode and TX kick).
    unsafe {
        libc::sendto(
            fd,
            core::ptr::null_mut(),
            0,
            libc::MSG_DONTWAIT,
            core::ptr::null_mut(),
            0,
        );
    }
    binding.telemetry.dbg_rx_wakeups += 1;
    binding.live.rx_wakeups.fetch_add(1, Ordering::Relaxed);
    binding.timers.last_rx_wake_ns = now_ns;
    binding.timers.empty_rx_polls = 0;
}

fn apply_prepared_recycle(
    free_tx_frames: &mut VecDeque<u64>,
    shared_recycles: &mut Vec<(u32, u64)>,
    recycle: PreparedTxRecycle,
    offset: u64,
) {
    let recycle_offset = recycle.recycle_offset(offset);
    match recycle {
        PreparedTxRecycle::FreeTxFrame => free_tx_frames.push_back(recycle_offset),
        PreparedTxRecycle::FillOnSlot(slot)
        | PreparedTxRecycle::FillOnSlotWithOffset { slot, .. } => {
            shared_recycles.push((slot, recycle_offset));
        }
    }
}

fn recycle_completed_tx_offset(
    binding: &mut BindingWorker,
    shared_recycles: &mut Vec<(u32, u64)>,
    offset: u64,
) {
    if let Some(recycle) = binding.tx_pipeline.in_flight_prepared_recycles.remove(&offset) {
        apply_prepared_recycle(
            &mut binding.tx_pipeline.free_tx_frames,
            shared_recycles,
            recycle,
            offset,
        );
    } else if completion_offset_returnable_to_free_pool(offset, umem_region_len(binding)) {
        // #9900 F-092 (GPT-2): PRODUCTION ownership transition — the offset
        // recycles only if an untracked submit recorded it. A duplicate or
        // stale delivery (or a tracked completion re-delivered after its
        // recycle entry was consumed) finds no entry and is dropped + counted
        // instead of double-pushed into the free pool. `debug_assert` on the
        // pool scan stays as the belt-and-braces exact property in tests.
        if binding.tx_pipeline.in_flight_untracked_tx.remove(&offset) {
            debug_assert!(
                !binding.tx_pipeline.free_tx_frames.contains(&offset),
                "TX completion double-free: offset {offset} already in the free pool",
            );
            binding.tx_pipeline.free_tx_frames.push_back(offset);
        } else if TX_COMPLETION_DUPLICATE_TOTAL.fetch_add(1, Ordering::Relaxed) < 10 {
            eprintln!(
                "TX_COMPLETION_DUPLICATE: slot={} if={} q={} offset={} (no untracked-submit ownership; dropped, not recycled)",
                binding.slot, binding.ifindex, binding.queue_id, offset,
            );
        }
    } else {
        // #9900 F-092: a completion for something that was never an aligned
        // in-region TX frame — kernel fault, not a frame. Drop it (recycling
        // would poison the free pool) and count it.
        if TX_COMPLETION_INVALID_TOTAL.fetch_add(1, Ordering::Relaxed) < 10 {
            eprintln!(
                "TX_COMPLETION_INVALID: slot={} if={} q={} offset={} (not an aligned in-region frame base; dropped, not recycled)",
                binding.slot, binding.ifindex, binding.queue_id, offset,
            );
        }
    }
}

pub(in crate::afxdp) fn maybe_wake_tx(binding: &mut BindingWorker, force: bool, now_ns: u64) {
    let bind_mode = XskBindMode::from_u8(binding.live.bind_mode.load(Ordering::Relaxed));
    if !bind_mode.is_zerocopy()
        || binding.xsk.tx.needs_wakeup()
        || force
        || now_ns.saturating_sub(binding.timers.last_tx_wake_ns) >= TX_WAKE_MIN_INTERVAL_NS
    {
        // Use a direct sendto() syscall (not any wrapper) so we can
        // observe errno and feed the #825 kick-latency telemetry.
        let fd = binding.xsk.tx.as_raw_fd();
        // #825 plan §3.3 site 1: two fresh `monotonic_nanos()` calls
        // bracket the `sendto` syscall. `now_ns` is caller-cached —
        // stale up to `IDLE_SPIN_ITERS * spin_cost` per #812 §3.1 R1
        // — so it is NOT suitable for measuring the kick cost; we
        // need fresh stamps to measure the syscall itself. Cost per
        // kick: ~30 ns VDSO (2 × ~15 ns) + the atomic fetch_adds in
        // `record_kick_latency` (≲15 ns), well within the §7 budget.
        let kick_start = monotonic_nanos();
        let rc = unsafe {
            libc::sendto(
                fd,
                core::ptr::null_mut(),
                0,
                libc::MSG_DONTWAIT,
                core::ptr::null_mut(),
                0,
            )
        };
        let kick_end = monotonic_nanos();
        binding.telemetry.dbg_sendto_calls += 1;
        // #825 plan §3.3 LOW-3 R1 sentinel, code-review R1 HIGH-1 hardening:
        // skip record unless (a) `kick_start != 0` AND (b) `kick_end >=
        // kick_start`. Both guards are required:
        //   - `kick_start != 0` catches the asymmetric failure mode where
        //     the first `monotonic_nanos()` call fails (returns 0) and the
        //     second succeeds — `kick_end - 0` would saturate bucket 15
        //     with a bogus-huge delta. It also drops the symmetric
        //     double-failure case (both 0) so a spurious bucket-0 record
        //     is not emitted on VDSO outage.
        //   - `kick_end >= kick_start` catches the backwards-clock /
        //     end-before-start case (wraparound in the `kick_end -
        //     kick_start` subtraction would otherwise saturate bucket
        //     15 with a bogus-huge delta). Both conditions must hold;
        //     this matches `record_tx_completions_with_stamp`'s
        //     `ts_completion >= ts_submit` precedent at :113-119.
        if kick_start != 0 && kick_end >= kick_start {
            let delta_ns = kick_end - kick_start;
            record_kick_latency(&binding.live.owner_profile_owner, delta_ns);
        }
        if rc < 0 {
            let errno = unsafe { *libc::__errno_location() };
            // EAGAIN/EWOULDBLOCK is normal for MSG_DONTWAIT; ENOBUFS means kernel dropped.
            if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                binding.telemetry.dbg_sendto_eagain += 1;
                // #825 plan §3.3 site 1 / §5: parallel atomic to
                // `dbg_sendto_eagain` (which is worker-local and
                // never published). Counts outer `sendto` returns
                // where `errno ∈ {EAGAIN, EWOULDBLOCK}` — the
                // "ring pushed back" signal T1 (#819 §4.1) keys
                // off. `dbg_sendto_eagain` stays in place: the
                // worker-local debug-tick log at
                // `worker.rs:~1051` continues to work.
                binding
                    .live
                    .owner_profile_owner
                    .tx_kick_retry_count
                    .fetch_add(1, Ordering::Relaxed);
            } else if errno == libc::ENOBUFS {
                binding.telemetry.dbg_sendto_enobufs += 1;
                if binding.telemetry.dbg_sendto_enobufs <= 10 {
                    eprintln!(
                        "TX_ENOBUFS: slot={} if={} q={} outstanding_tx={} free_tx={}",
                        binding.slot,
                        binding.ifindex,
                        binding.queue_id,
                        binding.tx_pipeline.outstanding_tx,
                        binding.tx_pipeline.free_tx_frames.len(),
                    );
                }
            } else {
                binding.telemetry.dbg_sendto_err += 1;
                if binding.telemetry.dbg_sendto_err <= 5 {
                    eprintln!(
                        "DBG SENDTO_ERR: slot={} if={} q={} errno={} outstanding_tx={} free_tx={}",
                        binding.slot,
                        binding.ifindex,
                        binding.queue_id,
                        errno,
                        binding.tx_pipeline.outstanding_tx,
                        binding.tx_pipeline.free_tx_frames.len(),
                    );
                }
            }
        }
        binding.timers.last_tx_wake_ns = now_ns;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializer for exact-delta assertions on the process-global TX
    /// completion counters (SKEW/INVALID/DUPLICATE/FILL). Several tests bump
    /// the same statics, so unsynchronized exact deltas flake under parallel
    /// execution. Every test that bumps OR asserts these counters holds this
    /// lock for its duration.
    static COUNTER_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn apply_prepared_recycle_routes_fill_and_free_explicitly() {
        let mut free_tx_frames = VecDeque::new();
        let mut shared_recycles = Vec::new();

        apply_prepared_recycle(
            &mut free_tx_frames,
            &mut shared_recycles,
            PreparedTxRecycle::FreeTxFrame,
            41,
        );
        apply_prepared_recycle(
            &mut free_tx_frames,
            &mut shared_recycles,
            PreparedTxRecycle::FillOnSlot(7),
            42,
        );
        apply_prepared_recycle(
            &mut free_tx_frames,
            &mut shared_recycles,
            PreparedTxRecycle::FillOnSlotWithOffset {
                slot: 8,
                offset: 40,
            },
            44,
        );

        assert_eq!(free_tx_frames, VecDeque::from(vec![41]));
        assert_eq!(shared_recycles, vec![(7, 42), (8, 40)]);
    }

    #[test]
    fn record_tx_completion_ring_available_tracks_zero_current_and_window_max() {
        let mut telemetry = WorkerTelemetry::default();

        record_tx_completion_ring_available(&mut telemetry, 8);
        assert_eq!(telemetry.dbg_tx_completion_ring_available, 8);
        assert_eq!(telemetry.dbg_tx_completion_ring_available_max, 8);

        record_tx_completion_ring_available(&mut telemetry, 0);
        assert_eq!(telemetry.dbg_tx_completion_ring_available, 0);
        assert_eq!(
            telemetry.dbg_tx_completion_ring_available_max, 8,
            "available == 0 must still publish the current idle sample without clearing the debug-window peak"
        );

        record_tx_completion_ring_available(&mut telemetry, 13);
        assert_eq!(telemetry.dbg_tx_completion_ring_available, 13);
        assert_eq!(telemetry.dbg_tx_completion_ring_available_max, 13);
    }

    #[test]
    fn record_tx_completion_ring_available_for_reap_records_before_zero_decision() {
        let mut telemetry = WorkerTelemetry {
            dbg_tx_completion_ring_available_max: 8,
            ..Default::default()
        };

        assert_eq!(
            record_tx_completion_ring_available_for_reap(&mut telemetry, 0),
            None
        );
        assert_eq!(telemetry.dbg_tx_completion_ring_available, 0);
        assert_eq!(
            telemetry.dbg_tx_completion_ring_available_max, 8,
            "zero-available reap decisions must preserve the debug-window peak"
        );

        assert_eq!(
            record_tx_completion_ring_available_for_reap(&mut telemetry, 13),
            Some(13)
        );
        assert_eq!(telemetry.dbg_tx_completion_ring_available, 13);
        assert_eq!(telemetry.dbg_tx_completion_ring_available_max, 13);
    }

    // #8377: the steady-state RX keep-alive throttle. Both bounds, both
    // directions.
    //
    // This asserts the RATE LIMITER, not a cold-start guarantee — an earlier
    // draft of this cell claimed the latter, and it does not hold (see
    // `rx_wake_due`'s doc comment for why, and for the measurement that
    // settled it). What it does pin is that the gate cannot latch SHUT: a
    // binding whose RX is permanently empty still reaches the wake, so the
    // poll loop cannot end up counting empty polls forever without ever
    // issuing the syscall it counts them for.
    //
    // `last_rx_wake_ns` is seeded from `monotonic_nanos()` at binding
    // construction, NOT zero — `timers.rs` documents that it is deliberately
    // not `Default` for exactly that reason — so the interval term is
    // exercised against a realistic elapsed time rather than against 0, which
    // would satisfy it trivially.
    #[test]
    fn rx_wake_fires_for_a_queue_that_never_receives_8377() {
        let now_ns: u64 = 5_000_000_000;
        // Constructed 1 ms ago; RX empty ever since.
        let born_ns: u64 = now_ns - 1_000_000;

        // Below the poll floor the gate stays shut — the throttle is real.
        for polls in 0..RX_WAKE_IDLE_POLLS {
            assert!(
                !rx_wake_due(polls, born_ns, now_ns),
                "rx_wake_due opened at {polls} empty polls, below the \
                 RX_WAKE_IDLE_POLLS={RX_WAKE_IDLE_POLLS} floor; the wake would \
                 fire on every empty poll and cost a syscall per iteration"
            );
        }
        // At the floor it opens.
        assert!(
            rx_wake_due(RX_WAKE_IDLE_POLLS, born_ns, now_ns),
            "rx_wake_due never opens for a binding whose RX is permanently \
             empty; the keep-alive wake has latched shut and the poll loop \
             would spin counting empty polls without ever waking"
        );

        // The interval term, at its boundary in BOTH directions. A single
        // sample on one side of a threshold cannot see an inverted comparison.
        let last = now_ns - RX_WAKE_MIN_INTERVAL_NS;
        assert!(
            rx_wake_due(RX_WAKE_IDLE_POLLS, last, now_ns),
            "exactly RX_WAKE_MIN_INTERVAL_NS since the last wake must open the gate"
        );
        assert!(
            !rx_wake_due(RX_WAKE_IDLE_POLLS, last + 1, now_ns),
            "one nanosecond short of RX_WAKE_MIN_INTERVAL_NS must not open the gate"
        );

        // A clock that has gone backwards must not open the gate by underflow.
        assert!(
            !rx_wake_due(RX_WAKE_IDLE_POLLS, now_ns + 1_000_000, now_ns),
            "a backwards clock must saturate to 0, not wrap to a huge interval"
        );
    }

    #[test]
    fn account_tx_completions_counts_overdelivery_9900() {
        assert_eq!(account_tx_completions(5, 3), (2, 0));
        assert_eq!(account_tx_completions(2, 2), (0, 0));
        assert_eq!(account_tx_completions(0, 0), (0, 0));
        // Over-delivery clamps to 0 AND reports the delta (the old
        // saturating_sub swallowed it).
        assert_eq!(account_tx_completions(2, 5), (0, 3));
        assert_eq!(account_tx_completions(0, 1), (0, 1));
    }

    #[test]
    fn completion_offset_predicate_admits_pool_bases_only_9900() {
        let region = 256u64 * 4096;
        assert!(completion_offset_returnable_to_free_pool(0, region));
        assert!(completion_offset_returnable_to_free_pool(4096, region));
        assert!(completion_offset_returnable_to_free_pool(
            region - 4096,
            region
        ));
        // RX-addr and in-place shapes never complete untracked.
        assert!(!completion_offset_returnable_to_free_pool(256, region));
        assert!(!completion_offset_returnable_to_free_pool(4096 + 252, region));
        assert!(!completion_offset_returnable_to_free_pool(region, region));
        assert!(!completion_offset_returnable_to_free_pool(region + 4096, region));
        assert!(!completion_offset_returnable_to_free_pool(
            (u64::MAX - 4095) & !4095,
            region
        ));
    }

    #[test]
    fn fill_offset_predicate_admits_any_in_region_offset_9900() {
        let region = 256u64 * 4096;
        // Bases (initial fill)…
        assert!(fill_offset_submittable(0, region));
        assert!(fill_offset_submittable(4096, region));
        // …and post-headroom RX addrs (steady-state recycles at base + 512 —
        // rejecting these starved reception, GPT-1). The kernel masks to the
        // chunk base, so every in-region remainder submits the same frame.
        assert!(fill_offset_submittable(512, region));
        assert!(fill_offset_submittable(4096 + 512, region));
        assert!(fill_offset_submittable(region - 4096 + 512, region));
        assert!(fill_offset_submittable(256, region));
        assert!(fill_offset_submittable(4095, region));
        assert!(fill_offset_submittable(region - 1, region));
        // Only the frame base must be owned: out-of-region bases refuse.
        assert!(!fill_offset_submittable(region, region));
        assert!(!fill_offset_submittable(region + 512, region));
        assert!(!fill_offset_submittable(u64::MAX, region));
    }

    #[test]
    fn recycle_completed_tx_offset_drops_invalid_completion_9900() {
        let _counter_lock = COUNTER_TEST_LOCK.lock().expect("counter test lock");
        let mut binding = BindingWorker::new_for_mirror_test(7, 1, 11, 0);
        let free_before = binding.tx_pipeline.free_tx_frames.len();
        let invalid_before = TX_COMPLETION_INVALID_TOTAL.load(Ordering::Relaxed);
        let mut shared = Vec::new();
        // Untracked RX-addr shape, region-exact OOB, aligned-huge: all dropped.
        recycle_completed_tx_offset(&mut binding, &mut shared, 256);
        recycle_completed_tx_offset(&mut binding, &mut shared, 256 * 4096);
        recycle_completed_tx_offset(&mut binding, &mut shared, (u64::MAX - 4095) & !4095);
        assert_eq!(binding.tx_pipeline.free_tx_frames.len(), free_before);
        assert!(shared.is_empty());
        assert_eq!(
            TX_COMPLETION_INVALID_TOTAL.load(Ordering::Relaxed),
            invalid_before + 3
        );
        // Control: pop-then-record-then-complete (a genuine submit/completion
        // pair) recycles byte-identically with no count.
        let held = binding.tx_pipeline.free_tx_frames.pop_front().unwrap();
        binding.tx_pipeline.in_flight_untracked_tx.insert(held);
        recycle_completed_tx_offset(&mut binding, &mut shared, held);
        assert_eq!(binding.tx_pipeline.free_tx_frames.len(), free_before);
        assert_eq!(
            TX_COMPLETION_INVALID_TOTAL.load(Ordering::Relaxed),
            invalid_before + 3
        );
        // GPT-2: the SAME completion delivered twice — the second finds no
        // ownership and is dropped as a duplicate, not double-pushed.
        let dup_before = TX_COMPLETION_DUPLICATE_TOTAL.load(Ordering::Relaxed);
        recycle_completed_tx_offset(&mut binding, &mut shared, held);
        assert_eq!(binding.tx_pipeline.free_tx_frames.len(), free_before);
        assert_eq!(
            TX_COMPLETION_DUPLICATE_TOTAL.load(Ordering::Relaxed),
            dup_before + 1
        );

    }
    #[test]
    fn reap_tx_completions_drains_stale_ring_at_zero_gauge_9900() {
        let _counter_lock = COUNTER_TEST_LOCK.lock().expect("counter test lock");
        let mut binding = BindingWorker::new_for_mirror_test(7, 1, 11, 0);
        binding.tx_pipeline.outstanding_tx = 0;
        binding.xsk.device.push_comp_for_test(0);
        let free_before = binding.tx_pipeline.free_tx_frames.len();
        let skew_before = TX_COMPLETION_SKEW_TOTAL.load(Ordering::Relaxed);
        let mut shared = Vec::new();
        let reaped = reap_tx_completions(&mut binding, &mut shared);
        // Ring drained (no wedging) but NOT recycled (no double-push).
        assert_eq!(reaped, 1);
        assert_eq!(binding.xsk.device.available(), 0);
        assert_eq!(binding.tx_pipeline.outstanding_tx, 0);
        assert_eq!(binding.tx_pipeline.free_tx_frames.len(), free_before);
        assert!(shared.is_empty());
        assert_eq!(
            TX_COMPLETION_SKEW_TOTAL.load(Ordering::Relaxed),
            skew_before + 1
        );
        // The sidecar fold is skipped too: no live stamp is disturbed.
        assert!(
            binding
                .tx_pipeline
                .tx_submit_ns
                .iter()
                .all(|s| *s == crate::afxdp::binding_state::TX_SIDECAR_UNSTAMPED)
        );
    }

    #[test]
    fn reap_tx_completions_counts_overdelivery_residual_9900() {
        let _counter_lock = COUNTER_TEST_LOCK.lock().expect("counter test lock");
        // set (GPT-2) distinguishes the batch members — the genuinely
        // submitted offset recycles, the bogus one drops as a duplicate.
        // (Pre-GPT-2 this recycled both after range/align filtering.)
        let mut binding = BindingWorker::new_for_mirror_test(7, 1, 11, 0);
        let first = binding.tx_pipeline.free_tx_frames.pop_front().unwrap();
        let second = binding.tx_pipeline.free_tx_frames.pop_front().unwrap();
        binding.tx_pipeline.outstanding_tx = 1;
        binding.tx_pipeline.in_flight_untracked_tx.insert(first);
        binding.xsk.device.push_comp_for_test(first);
        binding.xsk.device.push_comp_for_test(second);
        let skew_before = TX_COMPLETION_SKEW_TOTAL.load(Ordering::Relaxed);
        let dup_before = TX_COMPLETION_DUPLICATE_TOTAL.load(Ordering::Relaxed);
        let mut shared = Vec::new();
        let reaped = reap_tx_completions(&mut binding, &mut shared);
        assert_eq!(reaped, 2);
        assert_eq!(binding.tx_pipeline.outstanding_tx, 0);
        assert_eq!(
            TX_COMPLETION_SKEW_TOTAL.load(Ordering::Relaxed),
            skew_before + 1
        );
        assert_eq!(
            TX_COMPLETION_DUPLICATE_TOTAL.load(Ordering::Relaxed),
            dup_before + 1
        );
        assert_eq!(binding.tx_pipeline.free_tx_frames.len(), 255);
    }

    #[test]
    fn drain_pending_fill_drops_invalid_offset_9900() {
        let _counter_lock = COUNTER_TEST_LOCK.lock().expect("counter test lock");
        let mut binding = BindingWorker::new_for_mirror_test(7, 1, 11, 0);
        let region = 256u64 * 4096;
        binding.tx_pipeline.pending_fill_frames.push_back(0);
        binding.tx_pipeline.pending_fill_frames.push_back(256);
        binding
            .tx_pipeline
            .pending_fill_frames
            .push_back(region - 1);
        binding
            .tx_pipeline
            .pending_fill_frames
            .push_back(region + 4096);
        let invalid_before = FILL_INVALID_TOTAL.load(Ordering::Relaxed);
        assert!(drain_pending_fill(&mut binding, monotonic_nanos()));
        // Invalids are dropped, NOT requeued; the in-region triple submits
        // (base, headroom addr, last-frame tail — the kernel masks to base).
        assert!(binding.tx_pipeline.pending_fill_frames.is_empty());
        assert_eq!(binding.xsk.device.pending(), 3);
        assert_eq!(
            FILL_INVALID_TOTAL.load(Ordering::Relaxed),
            invalid_before + 1
        );
    }
}
