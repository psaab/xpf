// Fail-on-revert coverage for #10889: a first UDP packet does not earn the
// application's long inactivity timeout until a genuine reverse packet arrives.
use super::tests::{decision, key_v4, metadata};
use super::*;

const APP_TIMEOUT_NS: u64 = 86_400_000_000_000;
const GLOBAL_UDP_TIMEOUT_NS: u64 = DEFAULT_UDP_SESSION_TIMEOUT_NS;

fn install_udp_pair(table: &mut SessionTable, forward: &SessionKey, install_ns: u64) -> SessionKey {
    let reverse = reverse_session_key(forward, NatDecision::default());
    let mut forward_metadata = metadata();
    forward_metadata.inactivity_timeout_ns = Some(APP_TIMEOUT_NS);
    assert!(table.install_with_protocol(
        forward.clone(),
        decision(),
        forward_metadata,
        install_ns,
        PROTO_UDP,
        0,
    ));
    let mut reverse_metadata = metadata();
    reverse_metadata.is_reverse = true;
    reverse_metadata.inactivity_timeout_ns = Some(APP_TIMEOUT_NS);
    assert!(table.install_with_protocol(
        reverse.clone(),
        decision(),
        reverse_metadata,
        install_ns,
        PROTO_UDP,
        0,
    ));
    let _ = table.drain_deltas(8);
    reverse
}

#[test]
fn unreplied_udp_session_uses_global_timeout_10889() {
    let mut table = SessionTable::new();
    let mut forward = key_v4();
    forward.protocol = PROTO_UDP;
    let install_ns = 1_000_000_000;
    let reverse = install_udp_pair(&mut table, &forward, install_ns);

    for key in [&forward, &reverse] {
        assert_eq!(
            table
                .entry_by_key(key)
                .expect("installed half")
                .expires_after_ns,
            GLOBAL_UDP_TIMEOUT_NS,
            "an unreplied datagram must not inherit the 24-hour application timeout"
        );
    }

    // No reverse packet: both halves must be physically reaped on the global
    // UDP idle window, not merely reject a lookup while retaining the pinhole.
    let reap_ns = install_ns + GLOBAL_UDP_TIMEOUT_NS + 5_000_000_000;
    table.last_gc_ns = reap_ns - SESSION_GC_INTERVAL_NS;
    let _ = table.expire_stale_entries(reap_ns);
    assert!(
        table.entry_by_key(&forward).is_none(),
        "unreplied forward half reaped"
    );
    assert!(
        table.entry_by_key(&reverse).is_none(),
        "unreplied reverse half reaped"
    );
}

#[test]
fn genuine_reverse_udp_packet_promotes_app_timeout_10889() {
    let mut table = SessionTable::new();
    let mut forward = key_v4();
    forward.protocol = PROTO_UDP;
    let install_ns = 1_000_000_000;
    let reverse = install_udp_pair(&mut table, &forward, install_ns);

    let reply_ns = install_ns + 10_000_000_000;
    assert!(
        table.lookup(&reverse, reply_ns, 0).is_some(),
        "genuine reverse packet hits"
    );
    for key in [&forward, &reverse] {
        let entry = table.entry_by_key(key).expect("promoted half");
        assert!(
            entry.established,
            "reply promotion must be mirrored to both halves"
        );
        assert_eq!(
            entry.last_seen_ns, reply_ns,
            "reply starts the shared app idle clock"
        );
        assert_eq!(
            entry.expires_after_ns, APP_TIMEOUT_NS,
            "reply earns app timeout"
        );
    }

    let global_deadline = reply_ns + GLOBAL_UDP_TIMEOUT_NS + 5_000_000_000;
    table.last_gc_ns = global_deadline - SESSION_GC_INTERVAL_NS;
    assert!(
        table.expire_stale_entries(global_deadline).is_empty(),
        "a genuine reply promotes both halves beyond the global UDP window"
    );
    assert!(table.entry_by_key(&forward).is_some());
    assert!(table.entry_by_key(&reverse).is_some());

    let app_deadline = reply_ns + APP_TIMEOUT_NS + 5_000_000_000;
    table.last_gc_ns = app_deadline - SESSION_GC_INTERVAL_NS;
    let _ = table.expire_stale_entries(app_deadline);
    assert!(
        table.entry_by_key(&forward).is_none(),
        "promoted forward half reaped at app timeout"
    );
    assert!(
        table.entry_by_key(&reverse).is_none(),
        "promoted reverse half reaped at app timeout"
    );
}

#[test]
fn synced_udp_import_requires_local_reverse_reply_10889() {
    let mut table = SessionTable::new();
    let mut forward = key_v4();
    forward.protocol = PROTO_UDP;
    let reverse = reverse_session_key(&forward, NatDecision::default());
    let install_ns = 1_000_000_000;

    let mut forward_metadata = metadata();
    forward_metadata.inactivity_timeout_ns = Some(APP_TIMEOUT_NS);
    assert!(table.upsert_synced(
        forward.clone(),
        decision(),
        forward_metadata,
        install_ns,
        PROTO_UDP,
        0,
        false,
    ));
    let mut reverse_metadata = metadata();
    reverse_metadata.is_reverse = true;
    reverse_metadata.inactivity_timeout_ns = Some(APP_TIMEOUT_NS);
    assert!(table.upsert_synced(
        reverse.clone(),
        decision(),
        reverse_metadata,
        install_ns,
        PROTO_UDP,
        0,
        false,
    ));

    for key in [&forward, &reverse] {
        let entry = table.entry_by_key(key).expect("synced half");
        assert!(
            !entry.established,
            "HA import has no reply-promotion evidence"
        );
        assert_eq!(entry.expires_after_ns, GLOBAL_UDP_TIMEOUT_NS);
    }

    let reply_ns = install_ns + 1_000_000_000;
    assert!(table.lookup(&reverse, reply_ns, 0).is_some());
    for key in [&forward, &reverse] {
        let entry = table.entry_by_key(key).expect("promoted synced half");
        assert!(entry.established);
        assert_eq!(entry.expires_after_ns, APP_TIMEOUT_NS);
    }
}
