//! #10267: the MissingNeighbor seed must retain the admitting policy's
//! per-application inactivity-timeout.
//!
//! The seed survives for the flow's life — the pending-neighbor retry sweep
//! replays the buffered frame but never re-installs the session — so whatever
//! `build_missing_neighbor_session_metadata` stamps is the window the flow
//! ages on until it expires. Stamping `inactivity_timeout_ns: None`
//! unconditionally pins a policy-permitted custom-app flow to the global
//! per-protocol timeout: the wire gate observes a stale session past the
//! configured app window (and `Timeout: <default>` in show output) while the
//! generic session/policy suites stay green.
//!
//! These drive the builder plus a real `SessionTable` handshake/expiry cycle
//! under live-mirror timeouts (global established 20 s, app 300 s). RED
//! pre-fix (the builder drops the evaluated policy timeout); GREEN once it
//! is threaded through. The zero/unset arms pin the use-global sentinel so
//! default-timeout flows are byte-identical.

use super::*;
use crate::ip_proto::PROTO_TCP;
use crate::session::{SessionKey, SessionTable, SessionTimeouts};
use crate::tcp_flags::{TCP_ACK, TCP_SYN};
use std::net::{IpAddr, Ipv4Addr};

const APP_SECS_10267: u32 = 300;
const APP_NS_10267: u64 = 300_000_000_000;
/// Live-mirror global established window: the loss cluster ages a
/// default-timeout TCP flow at 20 s, so app 300 s must visibly diverge.
const LIVE_DEFAULT_ESTABLISHED_SECS_10267: u64 = 20;

fn seed_decision_10267() -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::MissingNeighbor,
            local_ifindex: 0,
            egress_ifindex: 13,
            tx_ifindex: 13,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1))),
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    }
}

fn seed_key_10267(src_port: u16) -> SessionKey {
    SessionKey {
        addr_family: 2,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
        src_port,
        dst_port: 54921,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

fn reverse_of_10267(fwd: &SessionKey) -> SessionKey {
    SessionKey {
        src_ip: fwd.dst_ip,
        dst_ip: fwd.src_ip,
        src_port: fwd.dst_port,
        dst_port: fwd.src_port,
        ..fwd.clone()
    }
}

fn seed_forwarding_10267() -> ForwardingState {
    build_forwarding_state(&ConfigSnapshot::default())
}

#[test]
fn seed_builder_stamps_app_timeout_10267() {
    let forwarding = seed_forwarding_10267();
    let meta = build_missing_neighbor_session_metadata(
        &forwarding,
        1,
        2,
        11,
        0,
        false,
        seed_decision_10267(),
        Some(APP_SECS_10267),
    );
    assert_eq!(
        meta.inactivity_timeout_ns,
        Some(APP_NS_10267),
        "a policy-permitted app timeout must survive the cold-neighbor seed"
    );
}

#[test]
fn seed_builder_zero_and_unset_use_global_10267() {
    let forwarding = seed_forwarding_10267();
    for timeout in [None, Some(0)] {
        let meta = build_missing_neighbor_session_metadata(
            &forwarding,
            1,
            2,
            11,
            0,
            false,
            seed_decision_10267(),
            timeout,
        );
        assert_eq!(
            meta.inactivity_timeout_ns, None,
            "timeout {timeout:?} must keep the use-global sentinel (default flows unaffected)"
        );
    }
}

#[test]
fn seed_lifecycle_expires_on_app_window_not_default_10267() {
    let forwarding = seed_forwarding_10267();
    let mut table = SessionTable::new();
    table.set_timeouts(SessionTimeouts::from_seconds(
        LIVE_DEFAULT_ESTABLISHED_SECS_10267,
        60,
        60,
    ));
    let now = 1_000_000_000u64;
    // App-timeout flow: cold-neighbor seed (SYN) + reverse companion, then the
    // normal SYN-ACK / completing-ACK handshake.
    let fwd = seed_key_10267(40000);
    let rev = reverse_of_10267(&fwd);
    let seed_meta = build_missing_neighbor_session_metadata(
        &forwarding,
        1,
        2,
        11,
        0,
        false,
        seed_decision_10267(),
        Some(APP_SECS_10267),
    );
    assert!(table.install_with_protocol(
        fwd.clone(),
        seed_decision_10267(),
        seed_meta,
        now,
        PROTO_TCP,
        TCP_SYN,
    ));
    let mut rev_meta = build_missing_neighbor_session_metadata(
        &forwarding,
        2,
        1,
        0,
        0,
        false,
        seed_decision_10267(),
        Some(APP_SECS_10267),
    );
    rev_meta.is_reverse = true;
    assert!(table.install_with_protocol(
        rev.clone(),
        seed_decision_10267(),
        rev_meta,
        now,
        PROTO_TCP,
        TCP_SYN,
    ));
    assert!(table
        .lookup_with_origin(&rev, now + 1_000_000, TCP_SYN | TCP_ACK)
        .is_some());
    assert!(table
        .lookup_with_origin(&fwd, now + 2_000_000, TCP_ACK)
        .is_some());
    // The live `Timeout:` column must report the APP window (300), diverging
    // from the 20 s global default it collapsed to pre-fix.
    assert_eq!(
        table.timeout_secs_for(&fwd),
        APP_SECS_10267,
        "established seed session must report the app window, not the default"
    );
    // Default-timeout control flow on distinct tuples (same table, same clock).
    let ctl_fwd = seed_key_10267(40001);
    let ctl_rev = reverse_of_10267(&ctl_fwd);
    let ctl_meta = build_missing_neighbor_session_metadata(
        &forwarding,
        1,
        2,
        11,
        0,
        false,
        seed_decision_10267(),
        None,
    );
    assert!(table.install_with_protocol(
        ctl_fwd.clone(),
        seed_decision_10267(),
        ctl_meta,
        now,
        PROTO_TCP,
        TCP_SYN,
    ));
    let mut ctl_rev_meta = build_missing_neighbor_session_metadata(
        &forwarding,
        2,
        1,
        0,
        0,
        false,
        seed_decision_10267(),
        None,
    );
    ctl_rev_meta.is_reverse = true;
    assert!(table.install_with_protocol(
        ctl_rev.clone(),
        seed_decision_10267(),
        ctl_rev_meta,
        now,
        PROTO_TCP,
        TCP_SYN,
    ));
    assert!(table
        .lookup_with_origin(&ctl_rev, now + 1_000_000, TCP_SYN | TCP_ACK)
        .is_some());
    assert!(table
        .lookup_with_origin(&ctl_fwd, now + 2_000_000, TCP_ACK)
        .is_some());
    assert_eq!(
        table.timeout_secs_for(&ctl_fwd),
        LIVE_DEFAULT_ESTABLISHED_SECS_10267 as u32,
        "default-timeout seed must keep reporting the global window"
    );
    // Past the 20 s global window but inside the 300 s app window: the app
    // flow survives (pre-fix it reaped here on the global 20 s) while the
    // default control is evicted.
    let past_default = now + 2_000_000 + 21_000_000_000;
    let _ = table.expire_stale_entries(past_default);
    assert!(
        table.probe_with_origin_at(&fwd, past_default).is_some(),
        "app-timeout seed must survive past the global window"
    );
    assert!(
        table.probe_with_origin_at(&ctl_fwd, past_default).is_none(),
        "default-timeout control must reap on the global window"
    );
    // Past the 300 s app window: the app flow is evicted on its own value.
    let past_app = now + 2_000_000 + 301_000_000_000;
    let _ = table.expire_stale_entries(past_app);
    assert!(
        table.probe_with_origin_at(&fwd, past_app).is_none(),
        "app-timeout seed must reap on the app window"
    );
}
