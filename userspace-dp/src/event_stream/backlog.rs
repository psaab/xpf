//! Cursor-backed pending socket-write backlog for the connected I/O loop.
//!
//! Pure code motion out of `mod.rs` (#6235); no logic change. The connected
//! loop (`connection.rs`) and the channel drain (`drain.rs`) keep unwritten
//! socket bytes in [`WriteBacklog`] between cycles, bounded by
//! [`WRITE_BACKLOG_MAX_BYTES`].

/// Hard cap on the I/O thread's pending socket-write backlog (`write_buf`).
///
/// The bounded mpsc channel (`CHANNEL_CAPACITY`) is the only intended
/// backpressure surface. Without this cap a wedged daemon (socket open but
/// not reading → `write_buf` writes return `WouldBlock`) lets the I/O thread
/// migrate the entire channel into the heap-backed `write_buf` every cycle;
/// the channel then refills from worker `try_send`, the I/O thread drains it
/// again, and `write_buf` grows without bound → helper OOM / allocator
/// pressure on the forwarding plane (#2381). Once the backlog reaches this
/// cap the I/O thread stops pulling frames out of the channel, so the bounded
/// channel becomes the real backpressure surface and `try_send` drops (with
/// the existing `frames_dropped` / per-kind `queue_full` counters) instead of
/// silently relocating bytes into one unbounded buffer.
///
/// `EventFrame::data` is a fixed `[u8; 512]` (see codec.rs), so a fully
/// drained `CHANNEL_CAPACITY` (8192) channel is at most 8192 × 512 ≈ 4 MiB of
/// bytes. 16 MiB is therefore ≈ 4× that worst-case channel drain — generous
/// headroom so transient bursts (plus any in-flight replay/partial-write
/// remainder) are absorbed losslessly, while a persistently stalled consumer
/// stays bounded.

/// The cap is checked at the top of the drain loop, before the in-flight frame
/// is appended, so the UNWRITTEN backlog can reach at most
/// `WRITE_BACKLOG_MAX_BYTES` plus one already-pulled max `EventFrame` (≤ 512 B)
/// before the drain halts — i.e. the bound is `cap + one frame`, not a strict
/// 16 MiB. The overshoot is bounded and accepted (simpler than a pre-reserve
/// check); memory is bounded either way.
///
/// #4974: the cap and every backpressure decision measure UNWRITTEN bytes
/// (`WriteBacklog::pending_len()`), not the raw backing-`Vec` length. The
/// backlog is cursor-backed (`WriteBacklog`): bytes already handed to the
/// socket sit in a reclaimable prefix and are compacted geometrically, so the
/// `Vec` can transiently hold up to ~2× the pending length. Accounting on the
/// raw length would trip the cap early and drift the pause/resume logic.
pub(super) const WRITE_BACKLOG_MAX_BYTES: usize = 16 * 1024 * 1024;

/// Cursor-backed pending socket-write backlog for the connected I/O loop.
///
/// #4974: the connected loop keeps unwritten socket bytes here between cycles.
/// A slow reader accepts only a few bytes per `write`, leaving a large suffix
/// for the next cycle. The original code stored the backlog in a bare `Vec<u8>`
/// and reclaimed each short write with `write_buf.drain(..n)`, which memmoves
/// the ENTIRE remaining suffix down to offset 0 on every write — O(backlog) per
/// write, so O(backlog²) total copy work while a slow consumer nibbles through
/// a multi-MiB backlog, all on the single event I/O thread during exactly the
/// slow-consumer condition.
///
/// Instead we track a `start` cursor into `buf`: `buf[start..]` is the
/// unwritten pending suffix, `buf[..start]` is written-and-reclaimable. A
/// successful write of `n` bytes advances `start` in O(1) (no memmove). The
/// consumed prefix is reclaimed by GEOMETRIC compaction — a single copy of the
/// pending suffix to offset 0 only once the prefix reaches half the buffer
/// (`start >= buf.len()/2`). Because a compaction then copies at most `start`
/// bytes and resets `start` to 0, total compaction work is bounded by the total
/// bytes ever written (amortized O(1) per write, O(total_bytes) overall), and
/// `buf.len()` stays within ~2× the pending length (bounded, not the unbounded
/// growth #2381 guards against). Byte order and exactly-once delivery are
/// preserved: appends only ever go to the tail and compaction never reorders
/// the pending suffix.
pub(super) struct WriteBacklog {
    /// Backing storage. `buf[start..]` is the unwritten pending suffix.
    buf: Vec<u8>,
    /// Offset of the first unwritten byte. Bytes below it were already written
    /// to the socket and are reclaimable by compaction.
    start: usize,
    /// #4974: total bytes moved by geometric compaction, so the amortized
    /// -linear regression gate can assert bounded copy work. Test-only.
    #[cfg(test)]
    pub(super) compacted_bytes: usize,
}

impl WriteBacklog {
    pub(super) fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
            start: 0,
            #[cfg(test)]
            compacted_bytes: 0,
        }
    }

    /// Unwritten bytes still owed to the socket. This is the value the
    /// `WRITE_BACKLOG_MAX_BYTES` cap and the pause/backpressure logic use — NOT
    /// the raw `Vec` length, which also counts the reclaimable written prefix.
    #[inline]
    pub(super) fn pending_len(&self) -> usize {
        self.buf.len() - self.start
    }

    #[inline]
    pub(super) fn is_empty(&self) -> bool {
        self.start >= self.buf.len()
    }

    /// The unwritten suffix to hand to the next socket `write`.
    #[inline]
    pub(super) fn pending(&self) -> &[u8] {
        &self.buf[self.start..]
    }

    /// Append freshly produced frame bytes to the pending tail. Reclaims the
    /// consumed prefix first (geometrically) so the `Vec` tracks the pending
    /// length rather than the lifetime sum of everything ever queued.
    pub(super) fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.compact_if_needed();
        self.buf.extend_from_slice(bytes);
    }

    /// Record a successful socket write of `n` bytes. Advances the cursor in
    /// O(1); when the backlog fully drains it resets without a copy, otherwise
    /// it compacts geometrically. Replaces the O(backlog) `drain(..n)` memmove.
    pub(super) fn advance(&mut self, n: usize) {
        self.start += n;
        debug_assert!(
            self.start <= self.buf.len(),
            "write reported more than pending"
        );
        if self.start >= self.buf.len() {
            // Fully drained -- reset to empty without moving any bytes.
            self.buf.clear();
            self.start = 0;
        } else {
            self.compact_if_needed();
        }
    }

    /// Geometric compaction trigger: reclaim the consumed prefix only once it
    /// reaches half the buffer. At that point the pending suffix being copied is
    /// no larger than the prefix being discarded, so the copy cost is charged to
    /// already-consumed bytes and total compaction work stays O(total_bytes).
    #[inline]
    fn compact_if_needed(&mut self) {
        if self.start != 0 && self.start >= self.buf.len() / 2 {
            self.compact();
        }
    }

    /// Move the pending suffix down to offset 0 and drop the consumed prefix.
    fn compact(&mut self) {
        if self.start == 0 {
            return;
        }
        let pending = self.buf.len() - self.start;
        self.buf.copy_within(self.start.., 0);
        self.buf.truncate(pending);
        self.start = 0;
        #[cfg(test)]
        {
            self.compacted_bytes += pending;
        }
    }
}
