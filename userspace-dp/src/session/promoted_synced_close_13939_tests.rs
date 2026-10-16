use super::tests::{decision, key_v4, metadata};
use super::*;
use crate::tcp_flags::{TCP_ACK, TCP_FIN, TCP_RST};

const NOW_NS: u64 = 10_000_000_000;

fn peer_synced_pair(close_flags: u8) -> (SessionTable, SessionKey, SessionKey) {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let reverse = reverse_session_key(&forward, NatDecision::default());
    let mut reverse_metadata = metadata();
    reverse_metadata.is_reverse = true;

    for (key, row_metadata) in [
        (forward.clone(), metadata()),
        (reverse.clone(), reverse_metadata.clone()),
    ] {
        assert!(table.install_with_protocol_with_origin(
            key,
            decision(),
            row_metadata,
            SessionOrigin::SyncImport,
            NOW_NS,
            PROTO_TCP,
            TCP_ACK,
        ));
    }
    let _ = table.drain_deltas(8);

    // Reproduce the owner-hit ordering: promotion consumes the packet flags
    // before the deferred close is applied by poll_descriptor.
    assert!(table.promote_synced_with_origin(SessionUpdate {
        key: &reverse,
        decision: decision(),
        metadata: reverse_metadata,
        origin: SessionOrigin::SharedPromote,
        now_ns: NOW_NS + 1,
        protocol: PROTO_TCP,
        tcp_flags: close_flags,
    }));
    table.apply_deferred_owner_close(&reverse, NOW_NS + 1, close_flags);
    (table, forward, reverse)
}

#[test]
fn promoted_synced_rst_closes_both_halves_13939() {
    let (table, forward, reverse) = peer_synced_pair(TCP_RST);
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let entry = table
            .entry_by_key(key)
            .expect("both pair halves remain live");
        assert!(entry.closing, "{label}: RST must close both halves");
        assert!(
            entry.reset,
            "{label}: RST must place both halves on reset window"
        );
        assert_eq!(
            entry.expires_after_ns, 2_000_000_000,
            "{label}: reset window"
        );
    }
}

#[test]
fn promoted_synced_fin_closes_both_halves_13939() {
    let (table, forward, reverse) = peer_synced_pair(TCP_FIN);
    let fwd = table.entry_by_key(&forward).expect("forward half");
    let rev = table.entry_by_key(&reverse).expect("reverse half");
    assert!(fwd.closing && rev.closing, "FIN must close both halves");
    assert!(
        fwd.fin_peer,
        "companion must record the promoted half's FIN"
    );
    assert!(!rev.fin_peer, "matched half has not seen a peer FIN");
    assert_eq!(fwd.expires_after_ns, TCP_CLOSING_TIMEOUT_NS);
    assert_eq!(rev.expires_after_ns, TCP_CLOSING_TIMEOUT_NS);
}
