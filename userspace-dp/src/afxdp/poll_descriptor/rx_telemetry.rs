// #1327 Step 1: extracted from poll_descriptor.rs (now mod.rs) to a
// sibling module so the inner-loop driver in mod.rs doesn't have to
// scroll past 180 LOC of pure telemetry to find the next stage.
// This is a verbatim move — no behavioural change. The `pub(super)`
// visibility lets the inner-loop driver in mod.rs call it; nothing
// else in the crate needs to.

use super::*;


// #1128: per-descriptor RX-side bookkeeping lifted out of the inner
// loop in `poll_binding_process_descriptor`.
//
// The work here, in order, is:
//   1. prefetch the metadata header (96 bytes, two cache lines) and
//      the first 64 bytes of frame data into L1 (#909);
//   2. bump the unconditional per-binding counters that drive
//      `show interfaces` and the live status RPCs:
//      `telemetry.counters.{touched, rx_packets, rx_bytes}` and
//      `telemetry.dbg.{rx, rx_bytes_total, rx_max_frame}`;
//   3. for desc.len > 1514, bump `telemetry.dbg.rx_over_1514` and
//      (only under `cfg!(feature = "debug-log")`) eprint up to 20
//      oversized-frame breadcrumbs;
//   4. under `cfg!(feature = "debug-log")` only: RX-side TCP flag
//      census (FIN / SYN+ACK / zero-window / RST), poison-
//      descriptor detection, and a per-binding first-10 frame dump.
//
// In release builds without `--features debug-log` every
// `cfg!(...)` branch in steps 3 and 4 collapses to false and LLVM
// eliminates the debug-only body, leaving just the prefetches plus
// the unconditional counter increments in step 2. That residue is
// small enough that LLVM will inline a single call site regardless
// of any annotation. `#[inline]` (not `#[inline(always)]`) is
// deliberate: with `--features debug-log` the body is ~200 LOC, and
// forcing inline of that into the hot loop would bloat L1-i in
// debug builds for no production gain. `#[inline]` lets the
// compiler honor the body-size heuristic, which inlines tight
// production builds and correctly declines on the bulky debug
// path. The goal is *source-level* separation of housekeeping
// noise from forwarding logic, per the modularity discipline in #1128.
#[inline]
pub(super) fn record_rx_descriptor_telemetry(
    desc: XdpDesc,
    area: &UmemAreaHandle,
    telemetry: &mut TelemetryContext,
    worker_ctx: &WorkerContext,
) {
    // Prefetch the userspace-dp metadata header (96 bytes) at
    // desc.addr - meta_len. try_parse_metadata reads this
    // first, on the magic/version/length compare; before this
    // prefetch landed, that compare consumed ~33 % of
    // poll_binding_process_descriptor self-time on a perf
    // profile under iperf3 -P 128 / 25 Gb/s shaper (#909).
    //
    // The metadata is exactly 96 bytes (UserspaceDpMeta has a
    // const-asserted size; first field is `magic`) and starts
    // 96 bytes before the frame. UMEM frames are 4096-byte
    // aligned with a 256-byte headroom, so desc.addr is
    // 64-byte aligned by construction; the 96 bytes therefore
    // straddle exactly two cache lines and we issue two
    // prefetches.
    #[cfg(target_arch = "x86_64")]
    {
        debug_assert!(
            desc.addr.is_multiple_of(64),
            "UMEM frame at desc.addr={} should be 64-byte aligned",
            desc.addr,
        );
        let meta_len = std::mem::size_of::<UserspaceDpMeta>();
        if (desc.addr as usize) >= meta_len {
            let meta_offset = (desc.addr as usize) - meta_len;
            if let Some(pf_meta) = area.area().slice(meta_offset, meta_len) {
                unsafe {
                    core::arch::x86_64::_mm_prefetch(
                        pf_meta.as_ptr() as *const i8,
                        core::arch::x86_64::_MM_HINT_T0,
                    );
                    core::arch::x86_64::_mm_prefetch(
                        pf_meta.as_ptr().add(64) as *const i8,
                        core::arch::x86_64::_MM_HINT_T0,
                    );
                }
            }
        }
    }

    // Prefetch frame data into L1 while processing telemetry.counters.
    // UMEM frames are cold (last touched by NIC DMA); this hides
    // ~100ns DRAM latency before metadata parse.
    #[cfg(target_arch = "x86_64")]
    if let Some(pf) = area.area().slice(desc.addr as usize, 64.min(desc.len as usize)) {
        unsafe {
            core::arch::x86_64::_mm_prefetch(
                pf.as_ptr() as *const i8,
                core::arch::x86_64::_MM_HINT_T0,
            );
        }
    }
    telemetry.counters.touched = true;
    telemetry.counters.rx_packets += 1;
    telemetry.counters.rx_bytes += desc.len as u64;
    telemetry.dbg.rx += 1;
    telemetry.dbg.rx_bytes_total += desc.len as u64;
    if desc.len > telemetry.dbg.rx_max_frame {
        telemetry.dbg.rx_max_frame = desc.len;
    }
    // #5190 (A1-b1-F7): a FIXED 1514-byte comparison, not an MTU test. The
    // per-interface MTU / jumbo configuration is not available here (this runs
    // before the shim metadata is parsed, so even the 802.1Q tag presence is
    // unknown), so a valid in-band VLAN-tagged full-MTU frame (1518) and every
    // jumbo frame trip it. The counter is named for what it measures so it is
    // not read as an anomaly signal; see `DebugPollCounters::rx_over_1514`.
    if desc.len > 1514 {
        telemetry.dbg.rx_over_1514 += 1;
        if cfg!(feature = "debug-log") {
            thread_local! {
                static RX_OVER_1514_LOG: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
            }
            RX_OVER_1514_LOG.with(|c| {
                let n = c.get();
                if n < 20 {
                    c.set(n + 1);
                    eprintln!(
                        "DBG RX_OVER_1514[{}]: if={} q={} desc.len={} \
                         (over the FIXED 1514 size — a valid VLAN-tagged or \
                         jumbo frame lands here too; not an MTU test)",
                        n, worker_ctx.ident.ifindex, worker_ctx.ident.queue_id, desc.len,
                    );
                }
            });
        }
    }
    // TCP flag detection on RX
    if cfg!(feature = "debug-log") {
        if desc.len >= 54 {
            if let Some(rx_frame) = area.area().slice(desc.addr as usize, desc.len as usize)
            {
                // Check for FIN, SYN+ACK, zero-window (#2151: shared predicates).
                if let Some(tcp_info) = extract_tcp_flags_and_window(rx_frame) {
                    if crate::tcp_flags::has_fin(tcp_info.0) {
                        // FIN
                        telemetry.dbg.rx_tcp_fin += 1;
                    }
                    if crate::tcp_flags::is_syn_ack(tcp_info.0) {
                        // SYN+ACK
                        telemetry.dbg.rx_tcp_synack += 1;
                    }
                    if tcp_info.1 == 0 && !crate::tcp_flags::has_syn(tcp_info.0) {
                        // zero window, not SYN
                        telemetry.dbg.rx_tcp_zero_window += 1;
                        if telemetry.dbg.rx_tcp_zero_window <= 10 {
                            eprintln!(
                                "RX_TCP_ZERO_WIN[{}]: if={} q={} len={} flags=0x{:02x}",
                                telemetry.dbg.rx_tcp_zero_window,
                                worker_ctx.ident.ifindex,
                                worker_ctx.ident.queue_id,
                                desc.len,
                                tcp_info.0,
                            );
                        }
                    }
                }
                if frame_has_tcp_rst(rx_frame) {
                    telemetry.dbg.rx_tcp_rst += 1;
                    thread_local! {
                        static RX_RST_LOG_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
                    }
                    RX_RST_LOG_COUNT.with(|c| {
                        let n = c.get();
                        if n < 50 {
                            c.set(n + 1);
                            let summary = decode_frame_summary(rx_frame);
                            eprintln!(
                                "RST_DETECT RX[{}]: if={} q={} len={} {}",
                                n, worker_ctx.ident.ifindex, worker_ctx.ident.queue_id, desc.len, summary,
                            );
                            if n < 5 {
                                let hex_len = (desc.len as usize).min(rx_frame.len()).min(80);
                                let hex: String = rx_frame[..hex_len]
                                    .iter()
                                    .map(|b| format!("{:02x}", b))
                                    .collect::<Vec<_>>()
                                    .join(" ");
                                eprintln!("RST_DETECT RX_HEX[{n}]: {hex}");
                            }
                        }
                    });
                }
            }
        }
    }
    // Poison check: detect if kernel recycled descriptor without writing data
    if cfg!(feature = "debug-log") {
        if desc.len >= 8 {
            if let Some(first8) = area.area().slice(desc.addr as usize, 8) {
                if first8 == &0xDEAD_BEEF_DEAD_BEEFu64.to_ne_bytes() {
                    eprintln!(
                        "DBG POISON_DETECTED: if={} q={} desc.addr={:#x} desc.len={} — kernel returned poisoned frame!",
                        worker_ctx.ident.ifindex, worker_ctx.ident.queue_id, desc.addr, desc.len,
                    );
                }
            }
        }
    }
    if cfg!(feature = "debug-log") {
        if telemetry.dbg.rx <= 10 {
            if let Some(rx_frame) = area.area().slice(desc.addr as usize, desc.len as usize)
            {
                // Decode IP+TCP details from the frame
                let pkt_detail = decode_frame_summary(rx_frame);
                eprintln!(
                    "DBG RX_ETH[{}]: if={} q={} len={} {}",
                    telemetry.dbg.rx, worker_ctx.ident.ifindex, worker_ctx.ident.queue_id, desc.len, pkt_detail,
                );
                // Full hex dump for first 3 packets
                if telemetry.dbg.rx <= 3 {
                    let dump_len = (desc.len as usize).min(rx_frame.len()).min(80);
                    let hex: String = rx_frame[..dump_len]
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ");
                    eprintln!("DBG RX_HEX[{}]: {}", telemetry.dbg.rx, hex);
                }
            }
        }
    }
}
