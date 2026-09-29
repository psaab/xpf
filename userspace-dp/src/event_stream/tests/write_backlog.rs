// #4974: cursor-backed pending socket-write backlog (`WriteBacklog`).
//
// The connected I/O loop stores unwritten socket bytes in `WriteBacklog`
// between cycles. A slow reader accepts only a few bytes per `write`, leaving a
// large suffix for the next cycle. The pre-#4974 code kept the backlog in a
// bare `Vec<u8>` and reclaimed each short write with `write_buf.drain(..n)`,
// which memmoves the ENTIRE remaining suffix down to offset 0 on every write —
// O(backlog) per write, O(backlog^2) total copy work while a slow consumer
// nibbles a multi-MiB backlog. The cursor-backed backlog advances a start
// index in O(1) and reclaims the consumed prefix by GEOMETRIC compaction, so
// total compaction copy work is bounded LINEARLY by the bytes ever queued.

use super::*;

/// Regression gate: driving thousands of small partial writes through a large
/// backlog must keep total compaction copy work within a LINEAR bound. The
/// pre-#4974 per-write `drain(..n)` memmove is O(backlog^2) and blows the bound
/// by orders of magnitude, so reverting `WriteBacklog::advance` to a per-write
/// full memmove turns THIS test RED (target-count 1).
#[test]
fn partial_write_backlog_is_amortized_linear_4974() {
    let mut backlog = WriteBacklog::with_capacity(4096);

    // A representative event-frame worth of bytes.
    let frame = vec![0xABu8; 200];
    // The slow reader accepts only a small, fixed chunk per write cycle.
    const CHUNK: usize = 128;

    let mut total_appended: usize = 0;

    // Preload a large backlog so the suffix a per-write drain(..n) would memmove
    // is big (~1.2 MiB). start stays 0 here, so no compaction fires yet.
    for _ in 0..6_000 {
        backlog.extend_from_slice(&frame);
        total_appended += frame.len();
    }

    // Nibble the backlog down in many small partial writes while a slow producer
    // keeps appending — the connected loop under a persistently slow reader.
    let mut writes = 0u64;
    let mut appends_left = 3_000u32;
    while !backlog.is_empty() {
        let n = CHUNK.min(backlog.pending_len());
        backlog.advance(n);
        writes += 1;
        if appends_left > 0 && writes % 4 == 0 {
            backlog.extend_from_slice(&frame);
            total_appended += frame.len();
            appends_left -= 1;
        }
    }

    assert!(
        writes > 5_000,
        "test must exercise many partial writes, got {writes}"
    );
    // Geometric compaction MUST have run (otherwise the backlog would have grown
    // the Vec without reclaiming the written prefix).
    assert!(
        backlog.compacted_bytes > 0,
        "geometric compaction must have reclaimed the consumed prefix"
    );

    // Linear bound: geometric compaction copies at most ~1x the total bytes ever
    // queued; assert a generous 3x ceiling. A per-write drain(..n) memmove copies
    // a multi-KiB..MiB suffix on each of the >5000 writes and exceeds this by
    // orders of magnitude.
    let bound = total_appended.saturating_mul(3);
    assert!(
        backlog.compacted_bytes <= bound,
        "compaction copy work {} must stay within the linear bound {} (3x total \
         {}); a per-write drain(..n) memmove blows this",
        backlog.compacted_bytes,
        bound,
        total_appended,
    );
}

/// Correctness: bytes handed to the socket (the `pending()` prefixes consumed by
/// `advance`) must equal the appended input exactly — in order, none dropped,
/// duplicated, or reordered — across interleaved appends and short partial
/// writes that exercise compaction while the backlog both grows and shrinks.
#[test]
fn partial_write_backlog_preserves_byte_order_4974() {
    let mut backlog = WriteBacklog::with_capacity(16);
    let mut produced: Vec<u8> = Vec::new();
    let mut consumed: Vec<u8> = Vec::new();

    let mut next: u32 = 0;
    for round in 0..2_000u32 {
        // Append 1..=3 "frames" of unique, monotonically increasing bytes.
        let n_frames = (round % 3) + 1;
        for _ in 0..n_frames {
            let mut frame = [0u8; 7];
            for b in frame.iter_mut() {
                *b = (next & 0xFF) as u8;
                next = next.wrapping_add(1);
            }
            backlog.extend_from_slice(&frame);
            produced.extend_from_slice(&frame);
        }
        // Consume up to 5 bytes via a short write (the slow-reader partial write).
        if !backlog.is_empty() {
            let take = 5.min(backlog.pending_len());
            consumed.extend_from_slice(&backlog.pending()[..take]);
            backlog.advance(take);
        }
    }
    // Drain whatever remains.
    while !backlog.is_empty() {
        let take = 5.min(backlog.pending_len());
        consumed.extend_from_slice(&backlog.pending()[..take]);
        backlog.advance(take);
    }

    assert_eq!(
        consumed.len(),
        produced.len(),
        "no bytes may be lost or duplicated"
    );
    assert_eq!(consumed, produced, "bytes must emerge in order, unmodified");
    assert!(backlog.is_empty(), "backlog fully drained");
    assert_eq!(
        backlog.pending_len(),
        0,
        "pending length is zero when empty"
    );
}

/// `pending_len()` (unwritten bytes), not the raw Vec length, is the value the
/// `WRITE_BACKLOG_MAX_BYTES` cap measures. After a partial write advances the
/// cursor, pending_len must drop by exactly the written amount even though the
/// consumed prefix is still physically resident until the next compaction.
#[test]
fn pending_len_tracks_unwritten_bytes_not_raw_vec_4974() {
    let mut backlog = WriteBacklog::with_capacity(64);
    backlog.extend_from_slice(&[1u8; 100]);
    assert_eq!(backlog.pending_len(), 100);

    // A short write of 10 bytes: cursor advances, 10 fewer unwritten bytes. The
    // written prefix is not yet reclaimed, but the cap-facing length must be 90.
    backlog.advance(10);
    assert_eq!(
        backlog.pending_len(),
        90,
        "cap accounting must count only unwritten bytes"
    );
    assert!(!backlog.is_empty());

    // Fully drain: pending_len falls to 0 and the backlog resets without a copy.
    backlog.advance(90);
    assert_eq!(backlog.pending_len(), 0);
    assert!(backlog.is_empty());
}
