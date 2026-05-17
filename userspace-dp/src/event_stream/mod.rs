//! Event stream producer for session sync.
//!
//! Replaces the polled `drain_session_deltas` RPC with a push-based binary
//! event stream over a dedicated Unix socket. The Go daemon creates a listener
//! at the event socket path; the helper connects and pushes binary-framed
//! session events (open/close/update) with monotonic sequence numbers.
//!
//! Wire format (per docs/session-sync-design.md):
//!   Frame header: [length:u32 LE][type:u8][reserved:3][seq:u64 LE]
//!   Payload: type-specific binary (see codec module)

pub(crate) mod codec;

pub(crate) use codec::{close_flags, EventFrame};

use crate::session::{SessionDelta, SessionDeltaKind};
use codec::{FRAME_HEADER_SIZE, MSG_ACK, MSG_DRAIN_REQUEST, MSG_KEEPALIVE, MSG_PAUSE, MSG_RESUME};
use rustc_hash::FxHashMap;
use std::collections::VecDeque;
use std::io;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender, TryRecvError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Interval between keepalive frames to prevent idle disconnect.
#[allow(dead_code)] // reserved for event stream keepalive logic
const KEEPALIVE_INTERVAL_NS: u64 = 10_000_000_000; // 10 seconds

/// Maximum event frames buffered in the mpsc channel (shared across workers).
const CHANNEL_CAPACITY: usize = 8192;

/// Maximum frames retained for replay after disconnect.
const REPLAY_BUFFER_CAPACITY: usize = 4096;

/// Upper bound for explicit lossless queueing operations such as full
/// session export on connect. Normal packet-path delta export remains
/// non-blocking via `try_send`.
const LOSSLESS_QUEUE_TIMEOUT: Duration = Duration::from_secs(5);
const LOSSLESS_QUEUE_RETRY_DELAY: Duration = Duration::from_micros(50);

// ---------------------------------------------------------------------------
// Shared state between I/O thread and workers
// ---------------------------------------------------------------------------

/// Statistics exposed to coordinator / status reporting.
pub(crate) struct EventStreamStats {
    pub(crate) connected: bool,
    pub(crate) seq: u64,
    pub(crate) acked_seq: u64,
    pub(crate) sent: u64,
    pub(crate) dropped: u64,
    #[allow(dead_code)] // stats field for future reporting
    pub(crate) replayed: u64,
}

struct EventStreamShared {
    /// Workers fetch_add to get globally monotonic sequence numbers.
    next_seq: AtomicU64,
    /// Updated by I/O thread from Ack frames.
    acked_seq: AtomicU64,
    /// Set by Pause, cleared by Resume.
    paused: AtomicBool,
    /// True when the event socket is connected.
    connected: AtomicBool,
    /// Counters.
    frames_sent: AtomicU64,
    frames_dropped: AtomicU64,
    frames_replayed: AtomicU64,
}

impl EventStreamShared {
    fn new() -> Self {
        Self {
            next_seq: AtomicU64::new(0),
            acked_seq: AtomicU64::new(0),
            paused: AtomicBool::new(false),
            connected: AtomicBool::new(false),
            frames_sent: AtomicU64::new(0),
            frames_dropped: AtomicU64::new(0),
            frames_replayed: AtomicU64::new(0),
        }
    }
}

// ---------------------------------------------------------------------------
// EventStreamSender -- coordinator-level handle
// ---------------------------------------------------------------------------

/// Coordinator-level event stream handle. Owns the I/O thread.
pub(crate) struct EventStreamSender {
    tx: SyncSender<EventFrame>,
    shared: Arc<EventStreamShared>,
    io_thread: Option<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
}

impl EventStreamSender {
    /// Create a new event stream sender and spawn the I/O thread.
    /// The helper connects to the daemon listener at `socket_path`.
    pub(crate) fn new(socket_path: &str) -> Self {
        let (tx, rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
        let shared = Arc::new(EventStreamShared::new());
        let stop = Arc::new(AtomicBool::new(false));

        let shared_clone = shared.clone();
        let stop_clone = stop.clone();
        let path = socket_path.to_string();

        let io_thread = thread::Builder::new()
            .name("xpf-event-stream".to_string())
            .spawn(move || {
                io_thread_main(rx, shared_clone, stop_clone, path);
            })
            .expect("spawn event stream I/O thread");

        Self {
            tx,
            shared,
            io_thread: Some(io_thread),
            stop,
        }
    }

    /// Get a lightweight handle to pass to worker threads.
    pub(crate) fn worker_handle(&self) -> EventStreamWorkerHandle {
        EventStreamWorkerHandle {
            tx: self.tx.clone(),
            shared: self.shared.clone(),
        }
    }

    /// Current event stream statistics.
    pub(crate) fn stats(&self) -> EventStreamStats {
        EventStreamStats {
            connected: self.shared.connected.load(Ordering::Relaxed),
            seq: self.shared.next_seq.load(Ordering::Relaxed),
            acked_seq: self.shared.acked_seq.load(Ordering::Relaxed),
            sent: self.shared.frames_sent.load(Ordering::Relaxed),
            dropped: self.shared.frames_dropped.load(Ordering::Relaxed),
            replayed: self.shared.frames_replayed.load(Ordering::Relaxed),
        }
    }

    /// Signal the I/O thread to stop and wait for it to exit.
    pub(crate) fn stop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(join) = self.io_thread.take() {
            let _ = join.join();
        }
    }
}

impl Drop for EventStreamSender {
    fn drop(&mut self) {
        self.stop();
    }
}

// ---------------------------------------------------------------------------
// EventStreamWorkerHandle -- lightweight clone for worker threads
// ---------------------------------------------------------------------------

/// Worker-thread handle. Cheap to clone (Arc + SyncSender clone).
#[derive(Clone)]
pub(crate) struct EventStreamWorkerHandle {
    tx: SyncSender<EventFrame>,
    shared: Arc<EventStreamShared>,
}

impl EventStreamWorkerHandle {
    /// Allocate the next globally-monotonic sequence number.
    pub(crate) fn next_seq(&self) -> u64 {
        self.shared.next_seq.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Non-blocking send. Returns false if the channel is full (event dropped).
    pub(crate) fn try_send(&self, frame: EventFrame) -> bool {
        match self.tx.try_send(frame) {
            Ok(()) => true,
            Err(mpsc::TrySendError::Full(_)) => {
                self.shared.frames_dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                self.shared.frames_dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    fn send_frame_lossless(&self, mut frame: EventFrame) -> Result<(), String> {
        if !self.shared.connected.load(Ordering::Acquire) {
            return Err("event stream not connected".to_string());
        }
        let deadline = Instant::now() + LOSSLESS_QUEUE_TIMEOUT;
        loop {
            match self.tx.try_send(frame) {
                Ok(()) => return Ok(()),
                Err(mpsc::TrySendError::Full(returned)) => {
                    frame = returned;
                    if !self.shared.connected.load(Ordering::Acquire) {
                        return Err(format!(
                            "event stream disconnected while queuing seq {}",
                            frame.seq
                        ));
                    }
                    if Instant::now() >= deadline {
                        return Err(format!(
                            "timed out queuing event stream frame seq {}",
                            frame.seq
                        ));
                    }
                    thread::sleep(LOSSLESS_QUEUE_RETRY_DELAY);
                }
                Err(mpsc::TrySendError::Disconnected(returned)) => {
                    return Err(format!(
                        "event stream channel disconnected while queuing seq {}",
                        returned.seq
                    ));
                }
            }
        }
    }

    fn encode_delta_frame(
        &self,
        delta: &SessionDelta,
        zone_name_to_id: &FxHashMap<String, u16>,
    ) -> EventFrame {
        let seq = self.next_seq();
        match delta.kind {
            SessionDeltaKind::Open => EventFrame::encode_session_open(
                seq,
                &delta.key,
                &delta.decision,
                &delta.metadata,
                zone_name_to_id,
                delta.fabric_redirect_sync,
            ),
            SessionDeltaKind::Close => EventFrame::encode_session_close(
                seq,
                &delta.key,
                delta.metadata.owner_rg_id,
                close_flags(delta),
                delta.metadata.ingress_zone,
                delta.metadata.egress_zone,
            ),
        }
    }

    /// Encode and send a session delta as an event frame.
    pub(crate) fn push_delta(
        &self,
        delta: &SessionDelta,
        zone_name_to_id: &FxHashMap<String, u16>,
    ) {
        let frame = self.encode_delta_frame(delta, zone_name_to_id);
        self.try_send(frame);
    }

    /// Lossless variant used for explicit bootstrap/replay exports. This path
    /// may wait briefly for queue capacity, but it never silently drops.
    pub(crate) fn push_delta_lossless(
        &self,
        delta: &SessionDelta,
        zone_name_to_id: &FxHashMap<String, u16>,
    ) -> Result<(), String> {
        let frame = self.encode_delta_frame(delta, zone_name_to_id);
        self.send_frame_lossless(frame)
    }
}

// ---------------------------------------------------------------------------
// I/O thread -- manages connection, writes events, reads control frames
// ---------------------------------------------------------------------------

fn io_thread_main(
    rx: mpsc::Receiver<EventFrame>,
    shared: Arc<EventStreamShared>,
    stop: Arc<AtomicBool>,
    socket_path: String,
) {
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::with_capacity(REPLAY_BUFFER_CAPACITY);
    let mut ctrl_read_buf: Vec<u8> = Vec::with_capacity(128);

    while !stop.load(Ordering::Acquire) {
        // ---- Connect phase ----
        let stream = match try_connect(&socket_path, &stop) {
            Some(s) => s,
            None => break, // stop requested during connect
        };
        stream.set_nonblocking(true).ok();
        shared.connected.store(true, Ordering::Release);
        eprintln!("xpf-event-stream: connected to {}", socket_path);

        // Replay buffered events from last acked seq
        let acked = shared.acked_seq.load(Ordering::Acquire);
        let replay_result = replay_buffered(&stream, &mut replay_buf, acked, &shared);
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
            &stop,
            &mut replay_buf,
            &mut ctrl_read_buf,
        );

        shared.connected.store(false, Ordering::Release);
        if disconnect {
            eprintln!("xpf-event-stream: disconnected, will reconnect");
        }
    }

    // Drain remaining events on shutdown
    drain_remaining(&rx);
    shared.connected.store(false, Ordering::Release);
    eprintln!("xpf-event-stream: I/O thread exiting");
}

/// Try to connect to the daemon event socket, retrying every 100ms.
/// Returns None if stop is requested.
fn try_connect(path: &str, stop: &Arc<AtomicBool>) -> Option<UnixStream> {
    loop {
        if stop.load(Ordering::Acquire) {
            return None;
        }
        match UnixStream::connect(path) {
            Ok(stream) => return Some(stream),
            Err(_) => {
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

/// Replay buffered events that are newer than the last acked sequence.
/// If the replay buffer doesn't cover acked+1, send FullResync.
fn replay_buffered(
    stream: &UnixStream,
    replay_buf: &mut VecDeque<EventFrame>,
    acked_seq: u64,
    shared: &Arc<EventStreamShared>,
) -> io::Result<()> {
    // Check if replay buffer covers what we need. On a true fresh start
    // (acked_seq == 0 and no buffered frames), start clean. Otherwise any gap
    // at acked+1 requires FullResync, including the acked_seq==0 case where an
    // overrun replay buffer has already trimmed seq 1.
    let oldest_buffered = replay_buf.front().map(|f| f.seq).unwrap_or(0);
    let has_gap = (replay_buf.is_empty() && acked_seq > 0) || oldest_buffered > acked_seq + 1;
    if has_gap {
        let seq = shared.next_seq.fetch_add(1, Ordering::Relaxed) + 1;
        let frame = EventFrame::encode_full_resync(seq);
        write_frame_blocking(stream, &frame)?;
        shared.frames_sent.fetch_add(1, Ordering::Relaxed);
        eprintln!(
            "xpf-event-stream: sent FullResync (buffer gap: acked={}, oldest_buffered={})",
            acked_seq, oldest_buffered
        );
        replay_buf.clear();
        return Ok(());
    }

    // Replay frames newer than acked_seq
    let mut replayed = 0u64;
    for frame in replay_buf.iter() {
        if frame.seq > acked_seq {
            write_frame_blocking(stream, frame)?;
            replayed += 1;
        }
    }
    if replayed > 0 {
        shared
            .frames_replayed
            .fetch_add(replayed, Ordering::Relaxed);
        shared.frames_sent.fetch_add(replayed, Ordering::Relaxed);
        eprintln!("xpf-event-stream: replayed {replayed} events");
    }
    Ok(())
}

/// Write a full frame to the stream (blocking).
fn write_frame_blocking(stream: &UnixStream, frame: &EventFrame) -> io::Result<()> {
    use std::io::Write;
    // Temporarily set blocking for reliable writes during replay/drain
    stream.set_nonblocking(false).ok();
    let result = (&*stream).write_all(frame.as_bytes());
    stream.set_nonblocking(true).ok();
    result
}

/// Main connected loop. Returns true if we should reconnect, false if stopping.
fn run_connected_loop(
    rx: &mpsc::Receiver<EventFrame>,
    stream: &UnixStream,
    shared: &Arc<EventStreamShared>,
    stop: &Arc<AtomicBool>,
    replay_buf: &mut VecDeque<EventFrame>,
    ctrl_read_buf: &mut Vec<u8>,
) -> bool {
    use std::io::{Read, Write};

    let mut write_buf: Vec<u8> = Vec::with_capacity(4096);
    let mut tmp_read = [0u8; 64];
    let mut idle_cycles = 0u32;
    let mut last_write = Instant::now();

    loop {
        if stop.load(Ordering::Acquire) {
            return false;
        }

        let paused = shared.paused.load(Ordering::Acquire);
        let mut drained_any = false;

        // Drain channel into replay buffer + write buffer
        loop {
            match rx.try_recv() {
                Ok(frame) => {
                    drained_any = true;
                    // Add to replay buffer (drop oldest if over capacity)
                    if replay_buf.len() >= REPLAY_BUFFER_CAPACITY {
                        replay_buf.pop_front();
                    }
                    replay_buf.push_back(frame.clone());

                    if !paused {
                        write_buf.extend_from_slice(frame.as_bytes());
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return false,
            }
        }

        // Write buffered frames to socket
        if !write_buf.is_empty() {
            match (&*stream).write(&write_buf) {
                Ok(n) => {
                    if n < write_buf.len() {
                        // Partial write -- keep remainder
                        write_buf.drain(..n);
                    } else {
                        write_buf.clear();
                    }
                    // Count frames sent (approximate -- count by frames drained)
                    shared.frames_sent.fetch_add(1, Ordering::Relaxed);
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
                // Send keepalive to prevent idle disconnect on Go side
                if last_write.elapsed().as_secs() >= 10 {
                    let mut ka = [0u8; FRAME_HEADER_SIZE];
                    ka[4] = MSG_KEEPALIVE;
                    if let Err(_) = (&*stream).write_all(&ka) {
                        return true; // disconnect
                    }
                    last_write = Instant::now();
                }
                thread::sleep(Duration::from_millis(1));
            }
        }
    }
}

/// Process control frames received from the daemon.
/// Returns (action, bytes_consumed) where action is Some(true) to reconnect,
/// Some(false) to stop, or None to continue. Only complete frames are consumed;
/// any trailing partial frame is left for the next read cycle.
fn process_control_frames(
    data: &[u8],
    shared: &Arc<EventStreamShared>,
    rx: &mpsc::Receiver<EventFrame>,
    stream: &UnixStream,
    replay_buf: &mut VecDeque<EventFrame>,
) -> (Option<bool>, usize) {
    let mut offset = 0;
    while offset + FRAME_HEADER_SIZE <= data.len() {
        let payload_len = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let frame_len = FRAME_HEADER_SIZE + payload_len as usize;
        if offset + frame_len > data.len() {
            break; // incomplete frame -- wait for more data
        }
        let msg_type = data[offset + 4];
        let seq = u64::from_le_bytes([
            data[offset + 8],
            data[offset + 9],
            data[offset + 10],
            data[offset + 11],
            data[offset + 12],
            data[offset + 13],
            data[offset + 14],
            data[offset + 15],
        ]);
        offset += frame_len;

        match msg_type {
            MSG_ACK => {
                shared.acked_seq.store(seq, Ordering::Release);
                // Trim replay buffer: remove frames with seq <= acked
                while let Some(front) = replay_buf.front() {
                    if front.seq <= seq {
                        replay_buf.pop_front();
                    } else {
                        break;
                    }
                }
            }
            MSG_PAUSE => {
                shared.paused.store(true, Ordering::Release);
                eprintln!("xpf-event-stream: paused by daemon");
            }
            MSG_RESUME => {
                shared.paused.store(false, Ordering::Release);
                eprintln!("xpf-event-stream: resumed by daemon");
                // Flush any buffered-during-pause frames on next write cycle
            }
            MSG_DRAIN_REQUEST => {
                // Drain channel until we have all events up to target seq,
                // then send DrainComplete.
                let target_seq = seq;
                handle_drain_request(target_seq, rx, stream, shared, replay_buf);
            }
            _ => {
                eprintln!("xpf-event-stream: unknown control frame type {}", msg_type);
            }
        }
    }
    (None, offset)
}

/// Handle DrainRequest: drain channel, write all buffered events up to target
/// seq, then send DrainComplete.
fn handle_drain_request(
    target_seq: u64,
    rx: &mpsc::Receiver<EventFrame>,
    stream: &UnixStream,
    shared: &Arc<EventStreamShared>,
    replay_buf: &mut VecDeque<EventFrame>,
) {
    use std::io::Write;
    use std::time::Instant;

    let deadline = Instant::now() + Duration::from_millis(200);
    let was_paused = shared.paused.load(Ordering::Acquire);

    // Drain channel until we've seen target_seq or timeout
    loop {
        match rx.try_recv() {
            Ok(frame) => {
                let frame_seq = frame.seq;
                if replay_buf.len() >= REPLAY_BUFFER_CAPACITY {
                    replay_buf.pop_front();
                }
                replay_buf.push_back(frame);
                if frame_seq >= target_seq {
                    break;
                }
            }
            Err(TryRecvError::Empty) => {
                // Check if we already have the target in replay buf
                if replay_buf
                    .back()
                    .map(|f| f.seq >= target_seq)
                    .unwrap_or(false)
                {
                    break;
                }
                if Instant::now() >= deadline {
                    eprintln!(
                        "xpf-event-stream: drain timeout, highest_seq={}",
                        replay_buf.back().map(|f| f.seq).unwrap_or(0)
                    );
                    break;
                }
                thread::sleep(Duration::from_micros(100));
            }
            Err(TryRecvError::Disconnected) => break,
        }
    }

    // Write all replay-buffered frames to socket (blocking)
    stream.set_nonblocking(false).ok();
    for frame in replay_buf.iter() {
        if let Err(e) = (&*stream).write_all(frame.as_bytes()) {
            eprintln!("xpf-event-stream: drain write error: {e}");
            break;
        }
        shared.frames_sent.fetch_add(1, Ordering::Relaxed);
    }

    // Send DrainComplete
    let drain_seq = replay_buf.back().map(|f| f.seq).unwrap_or(target_seq);
    let complete_frame = EventFrame::encode_drain_complete(drain_seq);
    if let Err(e) = (&*stream).write_all(complete_frame.as_bytes()) {
        eprintln!("xpf-event-stream: drain complete write error: {e}");
    }
    shared.frames_sent.fetch_add(1, Ordering::Relaxed);
    stream.set_nonblocking(true).ok();

    // Restore pause state
    if was_paused {
        shared.paused.store(true, Ordering::Release);
    }

    eprintln!("xpf-event-stream: drain complete up to seq {}", drain_seq);
}

/// Drain remaining events from the channel on shutdown.
fn drain_remaining(rx: &mpsc::Receiver<EventFrame>) {
    loop {
        match rx.try_recv() {
            Ok(_) => {}
            Err(_) => break,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
