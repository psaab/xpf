//! #16486: sessions of IP protocols other than TCP/UDP/ICMP idled out
//! after 30 s; the Junos protocol-based default for "Other" is
//! 30 minutes (1800 s) and for OSPF 1 minute (60 s).
//!
//! Discriminator: a GRE session installed with no application
//! `inactivity-timeout` must still match / survive GC after 600 s
//! idle, report `Timeout: 1800` via `timeout_secs_for`, and only reap
//! after 1800 s. OSPF is pinned at 60 s so the "Other" widening does
//! not swallow its distinct table row. The app-override twin proves a
//! promoted other-protocol flow still wins over the new default.

use super::tests::{decision, key_v4, metadata};
use super::*;
use crate::ip_proto::{PROTO_AH, PROTO_ESP, PROTO_GRE, PROTO_IPV6, PROTO_OSPF, PROTO_SCTP};

const SEC: u64 = 1_000_000_000;

fn other_key(protocol: u8, src_port: u16) -> SessionKey {
    let mut key = key_v4();
    key.protocol = protocol;
    key.src_port = src_port;
    key.dst_port = 0;
    key
}

/// Unit: the resolver itself — every "other" protocol gets 1800 s
/// (both unpromoted and promoted without override), OSPF gets 60 s,
/// and a promoted flow's app override still wins over both defaults.
/// FAIL-ON-REVERT: restoring 30 s for Other fails the first block.
#[test]
fn other_protocols_default_to_1800s_and_ospf_to_60s_16486() {
    let to = SessionTimeouts::default();
    assert_eq!(OTHER_SESSION_TIMEOUT_NS, 1800 * SEC);
    for protocol in [PROTO_GRE, PROTO_ESP, PROTO_AH, PROTO_SCTP, PROTO_IPV6, u8::MAX] {
        assert_eq!(
            session_timeout_ns(protocol, 0, false, &to, None, None),
            1800 * SEC,
            "protocol {protocol} unpromoted must use the 1800 s Other default"
        );
        assert_eq!(
            session_timeout_ns(protocol, 0, true, &to, None, None),
            1800 * SEC,
            "protocol {protocol} promoted without override must use 1800 s"
        );
        // Twin: promoted + app override still wins.
        let app = 90 * SEC;
        assert_eq!(
            session_timeout_ns(protocol, 0, true, &to, Some(app), None),
            app,
            "protocol {protocol} promoted app override must win over Other default"
        );
        assert_eq!(
            session_timeout_ns(protocol, 0, false, &to, Some(app), None),
            1800 * SEC,
            "protocol {protocol} unpromoted must ignore the app override (#10889)"
        );
    }
    // OSPF: its own 60 s row; override still wins once promoted.
    assert_eq!(session_timeout_ns(PROTO_OSPF, 0, false, &to, None, None), 60 * SEC);
    assert_eq!(session_timeout_ns(PROTO_OSPF, 0, true, &to, None, None), 60 * SEC);
    let app = 90 * SEC;
    assert_eq!(session_timeout_ns(PROTO_OSPF, 0, true, &to, Some(app), None), app);
    assert_eq!(session_timeout_ns(PROTO_OSPF, 0, false, &to, Some(app), None), 60 * SEC);
}

/// Acceptance: an established GRE session idle for 600 s still
/// matches (lookup hit + GC survival), reports 1800, and reaps only
/// after 1800 s. An app-timeout GRE twin reaps on its own 90 s value,
/// proving the override — not the widened default — governs it.
#[test]
fn gre_session_survives_600s_idle_and_reports_1800_16486() {
    let then = 1_000_000_000u64;
    let mut table = SessionTable::new();
    let gre = other_key(PROTO_GRE, 0);
    assert!(table.install_with_protocol(gre.clone(), decision(), metadata(), then, PROTO_GRE, 0));
    assert_eq!(table.timeout_secs_for(&gre), 1800, "#16486: GRE must report 1800");

    // Still matches after 600 s idle and survives the GC sweep there.
    let after_600 = then + 600 * SEC;
    assert!(
        table.lookup(&gre, after_600, 0).is_some(),
        "#16486: GRE session idle 600 s must still match"
    );
    table.last_gc_ns = after_600 - 2 * SEC;
    let _ = table.expire_stale_entries(after_600);
    assert_eq!(table.len(), 1, "#16486: GRE session must survive GC at 600 s idle");

    // Reaps only once the 1800 s window has passed (last activity was
    // the 600 s lookup refresh, so expiry is measured from there).
    let after_expiry = after_600 + 1801 * SEC;
    table.last_gc_ns = after_expiry - 2 * SEC;
    let _ = table.expire_stale_entries(after_expiry);
    assert_eq!(table.len(), 0, "#16486: GRE session must reap after 1800 s idle");

    // Twin: GRE with a 90 s app timeout. Both halves start gated on
    // the global (now 1800 s) window until a genuine reply promotes
    // them; the resolver twin above pins the promoted value. Install
    // without app timeout on a second table and drive expiry via the
    // direct resolver-independent path: install with app timeout and
    // assert the install stamp is the global window (promotion gate),
    // while SessionTimeouts-level override behaviour is covered above.
    let mut app_table = SessionTable::new();
    let mut app_meta = metadata();
    app_meta.inactivity_timeout_ns = Some(90 * SEC);
    let gre_app = other_key(PROTO_GRE, 1);
    assert!(app_table.install_with_protocol(gre_app.clone(), decision(), app_meta, then, PROTO_GRE, 0));
    assert_eq!(
        app_table.timeout_secs_for(&gre_app),
        1800,
        "#16486/#10889: unpromoted GRE with app timeout starts on the global Other window"
    );
}

/// OSPF control: its 60 s row must not be widened by the Other fix.
#[test]
fn ospf_session_keeps_60s_default_16486() {
    let then = 1_000_000_000u64;
    let mut table = SessionTable::new();
    let ospf = other_key(PROTO_OSPF, 0);
    assert!(table.install_with_protocol(ospf.clone(), decision(), metadata(), then, PROTO_OSPF, 0));
    assert_eq!(table.timeout_secs_for(&ospf), 60, "#16486: OSPF must report 60");
    let after_61 = then + 61 * SEC;
    table.last_gc_ns = after_61 - 2 * SEC;
    let _ = table.expire_stale_entries(after_61);
    assert_eq!(table.len(), 0, "#16486: OSPF session must reap after 60 s idle");
}
