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
