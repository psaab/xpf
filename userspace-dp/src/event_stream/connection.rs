//! I/O thread: connection lifecycle, reconnect, replay, and the connected loop.
//!
//! Pure code motion out of `mod.rs` (#6235); no logic change. `io_thread_main`
//! owns the reconnect loop; `try_connect` retries the daemon socket;
//! `replay_buffered` re-sends un-ACKed frames (parking an ordered replay-gap
//! FullResync barrier, #5267); `write_all_backpressured` is the stop-aware
//! nonblocking backpressured writer (#2877) shared with the drain path; and
//! `run_connected_loop` is the steady-state drain/write/read/keepalive cycle.

use super::*;

pub(super) fn io_thread_main(
    rx: mpsc::Receiver<EventFrame>,
    shared: Arc<EventStreamShared>,
    socket_path: String,
) {
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::with_capacity(REPLAY_BUFFER_CAPACITY);
    let mut ctrl_read_buf: Vec<u8> = Vec::with_capacity(128);

    while !shared.stop.load(Ordering::Acquire) {
        // ---- Connect phase ----
        let stream = match try_connect(&socket_path, &shared) {
            Some(s) => s,
            None => break, // stop requested during connect
        };
        stream.set_nonblocking(true).ok();
        // #5267: `connected` stays set BEFORE `replay_buffered`. It gates only
        // the LOSSLESS producer path (`send_lossless_encoded` fails closed when
        // clear); deferring it past the non-gap replay window would make every
        // worker `push_delta_lossless` return "not connected" mid-reconnect,
        // which `flush_session_deltas` latches as loss-of-sync -> a spurious
        // full owner-RG resync on every CLEAN reconnect (the exact churn class
        // this fix removes). Wire ORDERING is instead guaranteed by allocating
        // the replay-gap FullResync's seq under `producer_seq_lock` and merging
        // it into the drain in seq order (below), so the `connected` timing is
        // orthogonal to ordering.
        shared.connected.store(true, Ordering::Release);
        eprintln!("xpf-event-stream: connected to {}", socket_path);

        // #5267: per-connection slot for a replay-gap FullResync barrier.
        // `replay_buffered` allocates the barrier's seq under `producer_seq_lock`
        // and PARKS the frame here instead of writing it out of order; the
        // connected loop's channel drain emits it in seq order relative to the
        // concurrently-committed deltas. Fresh per connection so a stale barrier
        // from a prior connection is never re-emitted.
        let mut pending_resync: Option<EventFrame> = None;

        // Replay buffered events from last acked seq. A replay-buffer gap parks
        // an ordered FullResync barrier in `pending_resync` rather than writing
        // it directly ahead of the still-queued lower-seq deltas.
        let acked = shared.acked_seq.load(Ordering::Acquire);
        let replay_result = replay_buffered(
            &stream,
            &mut replay_buf,
            acked,
            &shared,
            &mut pending_resync,
        );
        if replay_result.is_err() {
            shared.connected.store(false, Ordering::Release);
            eprintln!("xpf-event-stream: replay failed, reconnecting");
            continue;
        }

        // ---- Steady-state loop ----
        ctrl_read_buf.clear(); // discard stale data from previous connection
        let disconnect = run_connected_loop(
            &rx,
            &stream,
            &shared,
            &mut replay_buf,
            &mut ctrl_read_buf,
            &mut pending_resync,
            KEEPALIVE_IDLE_INTERVAL,
        );

        shared.connected.store(false, Ordering::Release);
        if disconnect {
            eprintln!("xpf-event-stream: disconnected, will reconnect");
        }
    }

    // Drain remaining events on shutdown
    drain_remaining(&rx, &shared);
    release_replay_dataplane_event_queue_budget(&shared, &mut replay_buf);
    shared.connected.store(false, Ordering::Release);
    eprintln!("xpf-event-stream: I/O thread exiting");
}

/// Try to connect to the daemon event socket, retrying every 100ms.
/// Returns None if stop is requested.
///
/// #9171: THE PEER IS VERIFIED HERE, and this was the one leg of six that did
/// not. Five siblings check -- three Go dials, one Go accept and two Rust
/// accepts -- and this client simply connected.
///
/// A CLIENT has to authenticate its server. `SO_PEERCRED` on a connected socket
/// returns the credentials of the other end whichever end asked, so the same
/// helper the accept paths use answers the question here; it is reused rather
/// than re-spelled, because two readings of one syscall are how they diverge.
///
/// What this closes is not hypothetical. The gap was dismissed as needing
/// "write access to a root-owned, non-world-writable directory, i.e. root
/// already" -- and the runtime-dir trust check tested only `S_IWOTH`, so a
/// root-owned GROUP-writable directory passed it. Each finding was dismissed by
/// assuming the other held. Together: a member of that group unlinks the socket,
/// binds their own, and this loop hands them the live session-delta stream plus
/// a `FullResync` -- the firewall's session table, addresses, ports and zone
/// identity -- and accepts forged ACKs back.
///
/// On refusal the connection is DROPPED and the loop keeps retrying rather than
/// giving up: an impostor holding the path must not be able to terminate the
/// stream permanently, and the real socket returning must heal it. The refusal
/// is logged ONCE per takeover episode -- at 100 ms retries an unconditional
/// warning would emit ten lines a second and bury itself, which is the shape a
/// reader learns to filter out.
fn try_connect(path: &str, shared: &Arc<EventStreamShared>) -> Option<UnixStream> {
    let mut warned = false;
    loop {
        if shared.stop.load(Ordering::Acquire) {
            return None;
        }
        match UnixStream::connect(path) {
            Ok(stream) => match crate::server::lifecycle::reject_unprivileged_peer(
                "event stream socket",
                &stream,
            ) {
                Ok(()) => {
                    warned = false;
                    return Some(stream);
                }
                Err(e) => {
                    if !warned {
                        warned = true;
                        eprintln!(
                            "xpf-event-stream: REFUSING to stream session state to an \
                             untrusted peer on {path}: {e} -- something other than the \
                             daemon is bound to this path; retrying, and not sending \
                             until it is the daemon again"
                        );
                    }
                    drop(stream);
                    thread::sleep(Duration::from_millis(100));
                }
            },
            Err(_) => {
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

/// Replay buffered events that are newer than the last acked sequence.
/// If the replay buffer doesn't cover acked+1, send FullResync.
pub(super) fn replay_buffered(
    stream: &UnixStream,
    replay_buf: &mut VecDeque<EventFrame>,
    acked_seq: u64,
    shared: &Arc<EventStreamShared>,
    pending_resync: &mut Option<EventFrame>,
) -> io::Result<()> {
    // One shared deadline bounds the whole replay so a stuck reader cannot hold
    // the I/O thread for `frames * deadline` (#2877). `write_all_backpressured`
    // keeps the socket NONBLOCKING (the canonical data-frame mode) and polls
    // the stop flag each WouldBlock cycle; on stop/deadline/error it returns
    // Err and the caller reconnects.
    let deadline = Instant::now() + REPLAY_DRAIN_WRITE_DEADLINE;
    // Check if replay buffer covers what we need. On a true fresh start
    // (acked_seq == 0 and no buffered frames), start clean. Otherwise any gap
    // at acked+1 requires FullResync, including the acked_seq==0 case where an
    // overrun replay buffer has already trimmed seq 1.
    let oldest_buffered = replay_buf.front().map(|f| f.seq).unwrap_or(0);
    let has_gap = (replay_buf.is_empty() && acked_seq > 0) || oldest_buffered > acked_seq + 1;
    if has_gap {
        // #5267: allocate the FullResync's seq UNDER `producer_seq_lock` and
        // PARK the frame in `pending_resync` instead of writing it directly to
        // the socket. Writing it here (outside the lock, ahead of the channel
        // drain) put a HIGHER seq on the wire before the lower-seq deltas still
        // queued in the channel: the Go reader (zero reorder tolerance) then
        // diagnosed a session-sync gap on the first post-barrier delta and
        // dropped the connection, churning resyncs on the very HA-recovery
        // barrier. Holding the lock for JUST the `fetch_add` guarantees every
        // delta already committed to the channel has a strictly LOWER seq (the
        // channel commit is atomic under the same lock, #3878) and every delta
        // committed afterward has a strictly higher seq; the connected loop's
        // drain then merges this barrier into the write stream in seq order
        // (`drain_channel_into_write_buf`). The lock is released immediately —
        // no socket write happens under it, so a wedged reader can never stall
        // the producers through this path, and there is no lock-ordering cycle
        // (the section is a single atomic).
        let seq = {
            let _guard = shared
                .producer_seq_lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            shared.next_seq.fetch_add(1, Ordering::Relaxed) + 1
        };
        *pending_resync = Some(EventFrame::encode_full_resync(seq));
        eprintln!(
            "xpf-event-stream: queued ordered FullResync seq {} (buffer gap: acked={}, oldest_buffered={})",
            seq, acked_seq, oldest_buffered
        );
        // Keep the stale replay window until the daemon ACKs the FullResync.
        // Clearing here can make an acked_seq=0 reconnect look like a clean
        // fresh start and permanently suppress the required bulk export.
        // `frames_sent` is bumped when the ordered drain accepts the barrier,
        // matching producer-frame enqueue accounting. When the stream is
        // paused that means replay retention rather than a socket write; #5328
        // tracks the existing Resume path's missing replay-suffix scheduling.
        return Ok(());
    }

    // Replay frames newer than acked_seq
    let mut replayed = 0u64;
    for frame in replay_buf.iter() {
        if frame.seq > acked_seq {
            write_all_backpressured(stream, frame.as_bytes(), shared, deadline)?;
            replayed += 1;
        }
    }
    if replayed > 0 {
        shared
            .frames_replayed
            .fetch_add(replayed, Ordering::Relaxed);
        eprintln!("xpf-event-stream: replayed {replayed} events");
    }
    Ok(())
}

/// Write all of `bytes` to the NONBLOCKING `stream`, honoring backpressure
/// without ever wedging the I/O thread (#2877).
///
/// The replay (`replay_buffered`) and drain (`handle_drain_request`) paths must
/// push frames to a socket whose daemon reader may have stalled. The old
/// `write_frame_blocking` flipped the socket to BLOCKING and called `write_all`
/// with no deadline and no stop check, so a stuck reader held the I/O thread in
/// the blocking write forever — and since `EventStreamSender::stop` joins that
/// thread, a write-blocked thread could not observe the stop flag and
/// stop/demotion hung. That violates the slow-consumer invariant in
/// `docs/session-sync-design.md`: a slow telemetry/session consumer must never
/// stall the helper.
///
/// This writer keeps the socket nonblocking (the same mode the steady-state
/// data-frame writes use) and, on `WouldBlock`, sleeps `REPLAY_DRAIN_WRITE_POLL`
/// and retries — polling `shared.stop` every cycle and bailing at `deadline`.
/// It returns `Err` on stop (Interrupted), deadline (TimedOut), or a real
/// socket error so the caller reconnects / withholds DrainComplete rather than
/// blocking indefinitely. `deadline` is shared across all frames in one
/// replay/drain pass so total time is bounded even if stop is never raised.
pub(super) fn write_all_backpressured(
    stream: &UnixStream,
    bytes: &[u8],
    shared: &Arc<EventStreamShared>,
    deadline: Instant,
) -> io::Result<()> {
    use std::io::Write;
    let mut written = 0usize;
    while written < bytes.len() {
        if shared.stop.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "event stream stop requested during replay/drain write",
            ));
        }
        match (&*stream).write(&bytes[written..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "event stream replay/drain write returned 0",
                ));
            }
            Ok(n) => written += n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "event stream replay/drain write deadline exceeded",
                    ));
                }
                thread::sleep(REPLAY_DRAIN_WRITE_POLL);
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Append the idle keepalive frame when one is due AND the pending write
/// backlog is still below `WRITE_BACKLOG_MAX_BYTES`. Returns true if bytes
/// were appended.
///
/// #2883 routed the keepalive through `write_buf` so a `WouldBlock` on a full
/// kernel send buffer is ordinary backpressure rather than a fatal reconnect.
/// That made the keepalive a PRODUCER into the backlog — and it was the only
/// producer that did not check the cap. `drain_channel_into_write_buf` halts at
/// `WRITE_BACKLOG_MAX_BYTES` precisely so a live-but-non-reading consumer cannot
/// migrate unbounded bytes into the heap-backed backlog; a consumer wedged there
/// keeps `drained_any == false` forever, which is exactly the condition that
/// arms the idle keepalive, so the keepalive appended past the cap on every
/// interval with nothing to ever reclaim it (`advance` is never called because
/// the socket write returns `WouldBlock`). The growth is slow — one
/// `FRAME_HEADER_SIZE` frame per `KEEPALIVE_IDLE_INTERVAL` — but it is
/// monotonic and unbounded, and it falsifies the documented
/// `cap + one max EventFrame` ceiling (#5189 A1-b10-F4).
///
/// Suppressing the keepalive at the cap loses nothing: the backlog holds
/// ≥ 16 MiB of unwritten frames, so pending DATA already supplies every bit of
/// liveness the keepalive exists to signal, and a genuinely dead consumer is
/// still detected by the normal socket-error / EOF path.
///
/// `last_write` is deliberately NOT re-armed when the append is suppressed: the
/// keepalive stays due, so the first cycle after the backlog drains below the
/// cap emits it immediately instead of waiting out another full interval.
pub(super) fn append_idle_keepalive_if_due(
    write_buf: &mut WriteBacklog,
    last_write: &mut Instant,
    keepalive_interval: Duration,
) -> bool {
    if last_write.elapsed() < keepalive_interval {
        return false;
    }
    // #5189 (A1-b10-F4): measure UNWRITTEN bytes (`pending_len`), the same
    // quantity the drain-loop cap and the pause/backpressure logic use (#4974);
    // the raw backing-`Vec` length also counts the reclaimable written prefix.
    if write_buf.pending_len() >= WRITE_BACKLOG_MAX_BYTES {
        return false;
    }
    let mut ka = [0u8; FRAME_HEADER_SIZE];
    ka[4] = MSG_KEEPALIVE;
    write_buf.extend_from_slice(&ka);
    *last_write = Instant::now();
    true
}

/// Main connected loop. Returns true if we should reconnect, false if stopping.
pub(super) fn run_connected_loop(
    rx: &mpsc::Receiver<EventFrame>,
    stream: &UnixStream,
    shared: &Arc<EventStreamShared>,
    replay_buf: &mut VecDeque<EventFrame>,
    ctrl_read_buf: &mut Vec<u8>,
    pending_resync: &mut Option<EventFrame>,
    keepalive_interval: Duration,
) -> bool {
    use std::io::{Read, Write};

    let mut write_buf = WriteBacklog::with_capacity(4096);
    let mut tmp_read = [0u8; 64];
    let mut idle_cycles = 0u32;
    let mut last_write = Instant::now();

    loop {
        if shared.stop.load(Ordering::Acquire) {
            return false;
        }

        let paused = shared.paused.load(Ordering::Acquire);

        let drain = drain_channel_into_write_buf(
            rx,
            shared,
            replay_buf,
            &mut write_buf,
            paused,
            pending_resync,
        );
        if drain.disconnected {
            return false;
        }
        let drained_any = drain.drained_any;

        // Write buffered frames to socket. On a partial (short) write we advance
        // the backlog cursor in O(1) instead of memmoving the whole remaining
        // suffix to offset 0 on every write (the #4974 O(n^2) drain).
        if !write_buf.is_empty() {
            match (&*stream).write(write_buf.pending()) {
                Ok(n) => {
                    write_buf.advance(n);
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // Socket buffer full, keep write_buf for next cycle
                }
                Err(_) => {
                    // Socket error -- disconnect
                    return true;
                }
            }
        }

        // Read control frames from daemon (non-blocking), accumulating
        // partial reads so that incomplete frames are not lost.
        match (&*stream).read(&mut tmp_read) {
            Ok(0) => {
                // EOF -- peer closed
                return true;
            }
            Ok(n) => {
                ctrl_read_buf.extend_from_slice(&tmp_read[..n]);
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // No data available -- normal
            }
            Err(_) => {
                return true;
            }
        }

        // Process complete control frames from accumulated buffer
        if !ctrl_read_buf.is_empty() {
            let (action, consumed) =
                process_control_frames(ctrl_read_buf, shared, rx, stream, replay_buf);
            if consumed > 0 {
                ctrl_read_buf.drain(..consumed);
            }
            if let Some(reconnect) = action {
                return reconnect;
            }
        }

        // Idle backoff + keepalive
        if drained_any {
            idle_cycles = 0;
            last_write = Instant::now();
        } else {
            idle_cycles = idle_cycles.saturating_add(1);
            if idle_cycles > 10 {
                // Enqueue a keepalive (prevents idle disconnect on the Go side)
                // through the SAME `write_buf` backpressure path data frames use
                // (#2883). The old code called `write_all` directly on the
                // nonblocking socket and returned true (immediate reconnect) on
                // ANY error — including `WouldBlock` when the kernel send buffer
                // is full under a slow reader — bypassing the partial-write /
                // WouldBlock backpressure and stall accounting and causing
                // reconnect churn -> replay storms. Routing the keepalive bytes
                // into `write_buf` makes WouldBlock ordinary backpressure: the
                // top-of-loop flush retains the remainder for the next cycle,
                // and a genuinely dead consumer is still detected by the normal
                // socket-error / EOF path rather than by a false reconnect on
                // transient fullness.
                //
                // #5189 (A1-b10-F4): the keepalive append obeys the SAME
                // `WRITE_BACKLOG_MAX_BYTES` ceiling the producer drain
                // enforces — see `append_idle_keepalive_if_due`.
                append_idle_keepalive_if_due(&mut write_buf, &mut last_write, keepalive_interval);
                thread::sleep(Duration::from_millis(1));
            }
        }
    }
}
