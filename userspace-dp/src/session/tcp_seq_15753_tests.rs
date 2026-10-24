use super::tests::{install_forward_reverse_pair, key_v4};
use super::*;
use crate::tcp_flags::{TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};

#[test]
fn in_window_rst_valid_blind_rst_invalid_15753() {
    let forward = key_v4();
    let mut table = SessionTable::new();
    let t0 = 10_000_000_000u64;
    let _rev = install_forward_reverse_pair(&mut table, &forward, t0, TCP_SYN);
    table.note_tcp_seq(&forward, 1000, 0, 4096, 0, TCP_SYN, 0);
    table.note_tcp_seq(&forward, 1001, 0, 4096, 100, TCP_ACK, 0);
    // #16040: rcv_nxt is 1101 after 100 payload bytes. In-window FIN
    // stays valid; exact RST is the only RST that may close.
    assert_eq!(table.tcp_closing_seq_verdict(&forward, 1050, TCP_FIN), SeqVerdict::Valid);
    assert_eq!(table.tcp_closing_seq_verdict(&forward, 1050, TCP_RST), SeqVerdict::Invalid, "in-window non-exact RST must not close");
    assert_eq!(table.tcp_closing_seq_verdict(&forward, 1101, TCP_RST), SeqVerdict::Valid, "exact RST must close");
    assert_eq!(table.tcp_closing_seq_verdict(&forward, 0, TCP_RST), SeqVerdict::Invalid, "blind seq=0 must not close");
    assert_eq!(table.tcp_closing_seq_verdict(&forward, 0, TCP_FIN), SeqVerdict::Valid, "FIN seq=0 inside advertised window is accepted (window check, #15753)");
    // Entry must not be closing from verdict alone (poll drops invalid).
    let e = table.entry_by_key(&forward).unwrap();
    assert!(!e.closing);
}

#[test]
fn pptp_data_seq_verdict_in_out_unknown_16037() {
    let forward = key_v4();
    let mut table = SessionTable::new();
    let t0 = 10_000_000_000u64;
    let _rev = install_forward_reverse_pair(&mut table, &forward, t0, TCP_SYN);
    // No seq noted yet (HA-synced import shape, tcp_seq_seen=false):
    // Unknown, and the caller must learn nothing — even though the
    // segment carries payload. Sequence state can only bind a
    // segment once the stream has been tracked here.
    assert_eq!(
        table.tcp_data_seq_verdict(&forward, 1001, 10),
        SeqVerdict::Unknown,
        "synced unknown-seq must not teach"
    );
    assert_eq!(
        table.tcp_data_seq_verdict(&forward, 1001, 0),
        SeqVerdict::Unknown,
        "no state and no payload must not teach"
    );
    table.note_tcp_seq(&forward, 1000, 0, 4096, 0, TCP_SYN, 0);
    // SYN advanced rcv_nxt to 1001; receiver window 4096.
    assert_eq!(
        table.tcp_data_seq_verdict(&forward, 1001, 100),
        SeqVerdict::Valid,
        "in-window OCR segment must teach"
    );
    assert_eq!(
        table.tcp_data_seq_verdict(&forward, 50_000, 100),
        SeqVerdict::Invalid,
        "out-of-window OCR must not teach"
    );
    assert_eq!(
        table.tcp_data_seq_verdict(&forward, 1001u32.wrapping_sub(5000), 100),
        SeqVerdict::Invalid,
        "far-behind segment must not teach"
    );
    // Advance with a legitimate 100-byte segment: rcv_nxt 1101.
    table.note_tcp_seq(&forward, 1001, 0, 4096, 100, TCP_ACK, 0);
    assert_eq!(
        table.tcp_data_seq_verdict(&forward, 1001, 100),
        SeqVerdict::Valid,
        "retransmission inside receiver window stays teachable"
    );
    assert_eq!(
        table.tcp_data_seq_verdict(&forward, 1101, 32),
        SeqVerdict::Valid,
        "next in-window segment stays teachable"
    );
    // A long segment spilling past the window end is not teachable as a whole.
    assert_eq!(
        table.tcp_data_seq_verdict(&forward, 5000, 200),
        SeqVerdict::Invalid
    );
}

/// #16037 production-site guard: the poll descriptor must snapshot the
/// teach verdict BEFORE it notes this segment, and the capture arm
/// must consume that snapshot. A verdict taken after
/// `note_tcp_seq_scaled` for the same segment would validate an
/// out-of-window payload against its own mutated `rcv_nxt` — the
/// fold defect this guards. This reads the production source because
/// the descriptor loop needs a live UMEM/binding to drive (the same
/// reason #6664/#13079 use source guards).
#[test]
fn pptp_teach_verdict_is_snapshotted_before_the_note_16037() {
    let poll = include_str!("../afxdp/poll_descriptor/mod.rs");
    let snapshot_at = poll
        .find("pending_pptp_data_seq_verdict = Some(sessions.tcp_data_seq_verdict(")
        .expect("poll must snapshot the teach verdict pre-note");
    let note_at = poll
        .find("sessions.note_tcp_seq_scaled(")
        .expect("poll must note seq at the Owner site");
    assert!(
        snapshot_at < note_at,
        "teach verdict must be computed before this segment is noted"
    );
    // The capture arm must not re-derive the verdict post-note.
    let capture_at = poll
        .find("capture_pptp_control_segment_at_epoch(")
        .expect("capture site");
    assert!(
        !poll[capture_at.saturating_sub(800)..capture_at].contains("tcp_data_seq_verdict("),
        "capture arm must not recompute the verdict after the note"
    );
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
        table.tcp_closing_seq_verdict(&forward, behind_100k, TCP_FIN),
        SeqVerdict::Invalid,
        "receiver window (unscaled SYN-ACK field) governs, not the sender's scaled window"
    );
    assert_eq!(table.tcp_closing_seq_verdict(&forward, 1050, TCP_FIN), SeqVerdict::Valid);
    // Grow the receiver window with a non-SYN segment at scale: window
    // 8192 << 7 capped at the 64K default (max_window=0).
    table.note_tcp_seq_scaled(&reverse, 5001, 1101, 8192, None, 0, TCP_ACK, 0);
    assert_eq!(
        table.tcp_closing_seq_verdict(&forward, 1101u32.wrapping_sub(50_000), TCP_FIN),
        SeqVerdict::Valid,
        "scaled receiver window (64K cap) admits 50k-behind closing seq"
    );
    assert_eq!(
        table.tcp_closing_seq_verdict(&forward, behind_100k, TCP_FIN),
        SeqVerdict::Invalid,
        "100k behind exceeds the 64K-capped receiver window"
    );
    // Asymmetric windows: shrink the receiver (reverse) window to 10
    // (raw field 10 at scale 7 = 1280, still < 5000): a seq 5000 behind
    // must be Invalid even though the sender's own window is 256K.
    table.note_tcp_seq_scaled(&reverse, 5001, 1101, 10, None, 0, TCP_ACK, 0);
    assert_eq!(
        table.tcp_closing_seq_verdict(&forward, 1101u32.wrapping_sub(5000), TCP_FIN),
        SeqVerdict::Invalid,
        "verdict must use the receiver (companion) window, not the sender's own"
    );
    let _ = TCP_RST;
}

#[test]
fn seed_tcp_window_scale_from_initial_syn_15947() {
    // The ordinary first SYN installs; seeding its parsed WSOPT is what
    // lets a later non-SYN segment use the negotiated scale without a
    // session-hit note having manually supplied Some(scale) again.
    let forward = key_v4();
    let mut table = SessionTable::new();
    let t0 = 10_000_000_000u64;
    let _rev = install_forward_reverse_pair(&mut table, &forward, t0, TCP_SYN);
    table.seed_tcp_window_scale(&forward, Some(7));
    assert_eq!(
        table.entry_by_key(&forward).unwrap().tcp_window_scale,
        Some(7)
    );
    // Bilateral offer is required before the seed drives scaling; this
    // seed-only cell records the offer and its later unscaled behaviour
    // is covered by unilateral_wsopt_not_applied_15947.
    assert!(!table.entry_by_key(&forward).unwrap().tcp_ws_negotiated);
    table.note_tcp_seq_scaled(
        &forward,
        1001,
        0,
        8192,
        None,
        0,
        TCP_ACK,
        256 * 1024,
    );
    assert_eq!(
        table.entry_by_key(&forward).unwrap().tcp_rcv_wnd,
        8192,
        "unilateral seed must not scale later windows"
    );
}

#[test]
fn unilateral_wsopt_not_applied_15947() {
    // RFC 7323 requires both SYNs to offer WSOPT. One-sided offer keeps
    // later windows unscaled; both-sided offer scales to the cap.
    let build = |both: bool| {
        let forward = key_v4();
        let mut table = SessionTable::new();
        let t0 = 10_000_000_000u64;
        let reverse = install_forward_reverse_pair(&mut table, &forward, t0, TCP_SYN);
        table.seed_tcp_window_scale(&forward, Some(7));
        if both {
            table.seed_tcp_window_scale(&reverse, Some(7));
        }
        table.note_tcp_seq(&forward, 1001, 0, 8192, 0, TCP_ACK, 256 * 1024);
        table.entry_by_key(&forward).unwrap().tcp_rcv_wnd
    };
    assert_eq!(build(false), 8192, "unilateral WSOPT must not scale");
    assert_eq!(build(true), 256 * 1024, "bilateral WSOPT scales to cap");
}

#[test]
fn rst_requires_exact_seq_16040() {
    // #16040 (S2-03 leg2): rcv_nxt=1101 after SYN(1000)+100 payload.
    // Every non-exact RST — in-window, ahead, blind, RST|FIN — is
    // Invalid; only seq==rcv_nxt is Valid. FIN keeps in-window validity.
    let forward = key_v4();
    let mut table = SessionTable::new();
    let t0 = 10_000_000_000u64;
    let _rev = install_forward_reverse_pair(&mut table, &forward, t0, TCP_SYN);
    table.note_tcp_seq(&forward, 1000, 0, 4096, 0, TCP_SYN, 0);
    table.note_tcp_seq(&forward, 1001, 0, 4096, 100, TCP_ACK, 0);
    assert_eq!(table.entry_by_key(&forward).unwrap().tcp_rcv_nxt, 1101);
    assert_eq!(table.tcp_closing_seq_verdict(&forward, 1100, TCP_RST), SeqVerdict::Invalid, "one-behind RST must not close");
    assert_eq!(table.tcp_closing_seq_verdict(&forward, 1050, TCP_RST), SeqVerdict::Invalid, "in-window RST must not close");
    assert_eq!(table.tcp_closing_seq_verdict(&forward, 1102, TCP_RST), SeqVerdict::Invalid, "one-ahead RST must not close");
    assert_eq!(table.tcp_closing_seq_verdict(&forward, 1050, TCP_RST | TCP_FIN), SeqVerdict::Invalid, "RST|FIN is driven by the RST bit");
    assert_eq!(table.tcp_closing_seq_verdict(&forward, 1101, TCP_RST), SeqVerdict::Valid, "exact RST must close");
    assert_eq!(table.tcp_closing_seq_verdict(&forward, 1101, TCP_RST | TCP_ACK), SeqVerdict::Valid);
    // FIN behaviour per fix spec: in-window retained, exact also valid.
    assert_eq!(table.tcp_closing_seq_verdict(&forward, 1050, TCP_FIN), SeqVerdict::Valid, "in-window FIN retained");
    assert_eq!(table.tcp_closing_seq_verdict(&forward, 1101, TCP_FIN), SeqVerdict::Valid);
    assert_eq!(table.tcp_closing_seq_verdict(&forward, 1102, TCP_FIN), SeqVerdict::Invalid, "FIN ahead of the advertised window rejected");
}
