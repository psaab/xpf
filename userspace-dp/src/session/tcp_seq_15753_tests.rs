use super::tests::{install_forward_reverse_pair, key_v4};
use super::*;
use crate::tcp_flags::{TCP_ACK, TCP_RST, TCP_SYN};

#[test]
fn in_window_rst_valid_blind_rst_invalid_15753() {
    let forward = key_v4();
    let mut table = SessionTable::new();
    let t0 = 10_000_000_000u64;
    let _rev = install_forward_reverse_pair(&mut table, &forward, t0, TCP_SYN);
    table.note_tcp_seq(&forward, 1000, 0, 4096, 0, TCP_SYN, 0);
    table.note_tcp_seq(&forward, 1001, 0, 4096, 100, TCP_ACK, 0);
    assert_eq!(table.tcp_closing_seq_verdict(&forward, 1050), SeqVerdict::Valid);
    assert_eq!(table.tcp_closing_seq_verdict(&forward, 0), SeqVerdict::Invalid, "blind seq=0 must not close");
    // Entry must not be closing from verdict alone (poll drops invalid).
    let e = table.entry_by_key(&forward).unwrap();
    assert!(!e.closing);
    let _ = TCP_RST;
}

#[test]
fn scaled_window_and_receiver_window_verdict_15947() {
    // #15947 (H29-02 arms 1-2): SYN WSOPT scale 7 + window 8192 (scaled
    // 1,048,576) under maximum-window 256K, then a legitimate FIN beyond
    // +65535. Pre-fix the tracked window was the raw u16 (8192) checked
    // against the sender's own window, so the verdict logic could not
    // honour the scaled receiver window.
    let forward = key_v4();
    let mut table = SessionTable::new();
    let t0 = 10_000_000_000u64;
    let reverse = install_forward_reverse_pair(&mut table, &forward, t0, TCP_SYN);
    // Forward SYN: seq 1000, unscaled window 8192, scale 7.
    table.note_tcp_seq_scaled(&forward, 1000, 0, 8192, Some(7), 0, TCP_SYN, 256 * 1024);
    // Reverse SYN-ACK: receiver advertises window 8192 at scale 7 too.
    table.note_tcp_seq_scaled(&reverse, 5000, 1001, 8192, Some(7), 0, TCP_SYN | TCP_ACK, 256 * 1024);
    // Forward data: seq 1001 + 100 bytes -> rcv_nxt 1101.
    table.note_tcp_seq_scaled(&forward, 1001, 5001, 8192, None, 100, TCP_ACK, 256 * 1024);
    let fwd_entry = table.entry_by_key(&forward).unwrap();
    // Non-SYN windows are scaled (8192 << 7 = 1,048,576), capped at 256K.
    assert_eq!(fwd_entry.tcp_rcv_wnd, 256 * 1024, "scaled window must honour maximum-window above 64K");
    // The receiver (reverse) entry's tracked window governs: it noted
    // only its SYN-ACK (window field never scaled per RFC 7323), so a
    // seq 100k behind rcv_nxt is outside it — the sender's own scaled
    // 256K window must NOT rescue it. Pre-fix the verdict used the
    // sender entry's own window and returned Valid here.
    let behind_100k = 1101u32.wrapping_sub(100_000);
    assert_eq!(
        table.tcp_closing_seq_verdict(&forward, behind_100k),
        SeqVerdict::Invalid,
        "receiver window (unscaled SYN-ACK field) governs, not the sender's scaled window"
    );
    assert_eq!(table.tcp_closing_seq_verdict(&forward, 1050), SeqVerdict::Valid);
    // Grow the receiver window with a non-SYN segment at scale: window
    // 8192 << 7 capped at the 64K default (max_window=0).
    table.note_tcp_seq_scaled(&reverse, 5001, 1101, 8192, None, 0, TCP_ACK, 0);
    assert_eq!(
        table.tcp_closing_seq_verdict(&forward, 1101u32.wrapping_sub(50_000)),
        SeqVerdict::Valid,
        "scaled receiver window (64K cap) admits 50k-behind closing seq"
    );
    assert_eq!(
        table.tcp_closing_seq_verdict(&forward, behind_100k),
        SeqVerdict::Invalid,
        "100k behind exceeds the 64K-capped receiver window"
    );
    // Asymmetric windows: shrink the receiver (reverse) window to 10
    // (raw field 10 at scale 7 = 1280, still < 5000): a seq 5000 behind
    // must be Invalid even though the sender's own window is 256K.
    table.note_tcp_seq_scaled(&reverse, 5001, 1101, 10, None, 0, TCP_ACK, 0);
    assert_eq!(
        table.tcp_closing_seq_verdict(&forward, 1101u32.wrapping_sub(5000)),
        SeqVerdict::Invalid,
        "verdict must use the receiver (companion) window, not the sender's own"
    );
    let _ = TCP_RST;
}
