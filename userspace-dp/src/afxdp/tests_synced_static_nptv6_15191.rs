// #15191 (D03-01) — a peer-synced static-NAT or NPTv6 session whose
// translated source no pool owns must NOT be booked into the interface
// registry. Before the fix, every distinct static external / NPTv6
// external address imported created one retained interface allocator;
// past 256 distinct addresses further imports were refused and local
// interface-SNAT admissions failed with InterfaceRegistryCap.
//
// The fixtures go through `build_forwarding_state` so the forwarding
// state's static table and NPTv6 state are built exactly as production
// builds them. Each import goes through the production synced-reserve
// entry with the active's zone pair resolved, carrying the provenance
// the HA wire carries (`source_nat_static` / `nptv6`).

use super::ForwardingState;
use super::forwarding_build::build_forwarding_state;
use super::test_fixtures::nat_snapshot;
use crate::nat::SourceNatLookup;
use crate::protocol::{
    ConfigSnapshot, Nptv6RuleSnapshot, SourceNATRuleSnapshot, StaticNATRuleSnapshot,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const E: &str = "172.16.80.8";
const SRV: &str = "93.184.216.34";
const TCP: u8 = 6;

fn static_snapshot(external: &str, internal: &str) -> ConfigSnapshot {
    let mut snap = nat_snapshot();
    snap.static_nat_rules = vec![StaticNATRuleSnapshot {
        name: "static-1".into(),
        from_zone: "wan".into(),
        external_ip: external.into(),
        internal_ip: internal.into(),
        ..Default::default()
    }];
    snap
}

fn nptv6_snapshot() -> ConfigSnapshot {
    let mut snap = nat_snapshot();
    snap.nptv6_rules = vec![Nptv6RuleSnapshot {
        name: "npt".into(),
        from_zone: String::new(),
        internal_prefix: "fd00:1::/48".into(),
        external_prefix: "2001:db8:1::/48".into(),
    }];
    snap
}

fn snat_key(src: IpAddr, src_port: u16, dst: IpAddr) -> crate::session::SessionKey {
    crate::session::SessionKey {
        addr_family: if src.is_ipv6() {
            libc::AF_INET6 as u8
        } else {
            libc::AF_INET as u8
        },
        protocol: TCP,
        src_ip: src,
        dst_ip: dst,
        src_port,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

/// Import `nat` as a peer-synced SNAT session through the production
/// synced-reserve entry, with the synced `source_nat_static`
/// provenance threaded exactly as the coordinator/worker import does.
fn import_synced(
    state: &ForwardingState,
    key: &crate::session::SessionKey,
    nat: crate::nat::NatDecision,
    source_nat_static: Option<bool>,
) -> bool {
    let static_externals = state.static_nat.external_identities();
    let nptv6_prefixes = state.nptv6.external_prefixes();
    crate::nat::reserve_synced_source_nat_allocation_untracked(
        &state.iface_nat_allocators,
        &state.source_nat_rules,
        key,
        nat,
        false,
        Some(("lan", "wan")),
        0,
        crate::nat::SyncedSourceNatDomains {
            source_nat_static,
            static_externals: Some(&static_externals),
            nptv6_external_prefixes: &nptv6_prefixes,
        },
    )
}

fn retained(state: &ForwardingState) -> usize {
    state.iface_nat_allocators.retained_len()
}

/// Local interface-SNAT admission through the production mint (control:
/// must stay `Matched` no matter how many synced static/NPTv6 sessions
/// were imported before it).
fn local_iface_admit(state: &ForwardingState) -> SourceNatLookup {
    let mut c = None;
    crate::nat::match_source_nat_result_for_tuple(
        &state.iface_nat_allocators,
        &state.source_nat_rules,
        &crate::nat::NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.0.9".parse().unwrap(),
        SRV.parse().unwrap(),
        Some(TCP),
        40001,
        443,
        Some(E.parse::<Ipv4Addr>().unwrap()),
        None,
        1_000,
        false,
        false,
        crate::nat::NatHolder::Untracked,
        &mut c,
    )
}

// ---------------------------------------------------------------------------
// Static-NAT leg
// ---------------------------------------------------------------------------

/// THE DEFECT (static): one synced static-NAT session must not create
/// an interface allocator for its external address.
#[test]
fn a_synced_static_nat_import_creates_no_interface_allocator_15191() {
    let state = build_forwarding_state(&static_snapshot("203.0.113.10", "192.168.1.10"));
    let key = snat_key("192.168.1.10".parse().unwrap(), 5000, SRV.parse().unwrap());
    let nat = crate::nat::NatDecision {
        rewrite_src: Some("203.0.113.10".parse().unwrap()),
        ..Default::default()
    };
    assert!(
        import_synced(&state, &key, nat, Some(true)),
        "static import must be admitted (nothing to reserve)"
    );
    assert_eq!(
        retained(&state),
        0,
        "a static-NAT external must not retain an interface allocator"
    );
}

/// THE DEFECT (static, cap): 257 distinct static externals must all
/// import, retain nothing, and leave local interface admission working.
#[test]
fn synced_static_imports_past_the_registry_cap_still_admit_15191() {
    // 257 distinct externals, octet-safe: 203.0.x.10 / 203.1.0.10.
    let ext = |i: u32| format!("203.{}.{}.10", i / 256, i % 256);
    let int = |i: u32| format!("192.168.{}.10", i % 256);
    let mut snap = nat_snapshot();
    snap.static_nat_rules = (0..257u32)
        .map(|i| StaticNATRuleSnapshot {
            name: format!("static-{i}"),
            from_zone: "wan".into(),
            external_ip: ext(i),
            internal_ip: int(i),
            ..Default::default()
        })
        .collect();
    let state = build_forwarding_state(&snap);
    for i in 0..257u32 {
        let key = snat_key(int(i).parse().unwrap(), 5000, SRV.parse().unwrap());
        let nat = crate::nat::NatDecision {
            rewrite_src: Some(ext(i).parse().unwrap()),
            ..Default::default()
        };
        assert!(
            import_synced(&state, &key, nat, Some(true)),
            "static import {i} past the 256 cap must still be admitted"
        );
    }
    assert_eq!(
        retained(&state),
        0,
        "no interface allocator may be retained"
    );
    assert!(
        matches!(local_iface_admit(&state), SourceNatLookup::Matched(_)),
        "local interface-SNAT admission must stay Matched after 257 static imports"
    );
}

// ---------------------------------------------------------------------------
// NPTv6 leg
// ---------------------------------------------------------------------------

/// THE DEFECT (NPTv6): one synced NPTv6 session must not create an
/// interface allocator for its external address.
#[test]
fn a_synced_nptv6_import_creates_no_interface_allocator_15191() {
    let state = build_forwarding_state(&nptv6_snapshot());
    let key = snat_key(
        "fd00:1::10".parse().unwrap(),
        5000,
        "2001:db8:9::1".parse().unwrap(),
    );
    let nat = crate::nat::NatDecision {
        rewrite_src: Some("2001:db8:1::10".parse().unwrap()),
        nptv6: true,
        ..Default::default()
    };
    assert!(
        import_synced(&state, &key, nat, None),
        "NPTv6 import must be admitted (nothing to reserve)"
    );
    assert_eq!(
        retained(&state),
        0,
        "an NPTv6 external must not retain an interface allocator"
    );
}

/// THE DEFECT (NPTv6, cap): 257 distinct NPTv6 externals (one /48,
/// distinct host parts) must all import and retain nothing.
#[test]
fn synced_nptv6_imports_past_the_registry_cap_still_admit_15191() {
    let state = build_forwarding_state(&nptv6_snapshot());
    for i in 1..=257u32 {
        let key = snat_key(
            format!("fd00:1::{i:x}").parse().unwrap(),
            5000,
            "2001:db8:9::1".parse().unwrap(),
        );
        let nat = crate::nat::NatDecision {
            rewrite_src: Some(format!("2001:db8:1::{i:x}").parse().unwrap()),
            nptv6: true,
            ..Default::default()
        };
        assert!(
            import_synced(&state, &key, nat, None),
            "NPTv6 import {i} past the 256 cap must still be admitted"
        );
    }
    assert_eq!(
        retained(&state),
        0,
        "no interface allocator may be retained"
    );
}

// ---------------------------------------------------------------------------
// Controls — the interface arm must keep working for genuine interface SNAT
// ---------------------------------------------------------------------------

/// CONTROL: a genuine interface-mode import (translated source is the
/// egress address E, dynamic provenance) still books its identity.
#[test]
fn a_synced_interface_import_still_books_its_identity_15191() {
    let state = build_forwarding_state(&nat_snapshot());
    let key = snat_key("10.0.0.9".parse().unwrap(), 40001, SRV.parse().unwrap());
    let nat = crate::nat::NatDecision {
        rewrite_src: Some(E.parse().unwrap()),
        ..Default::default()
    };
    assert!(import_synced(&state, &key, nat, Some(false)));
    assert_eq!(
        retained(&state),
        1,
        "a genuine interface import must retain its egress allocator"
    );
}

/// CONTROL: an unknown-provenance import whose translated source is a
/// configured static external still books nothing (the local static
/// table is the authority when the wire provenance is absent).
#[test]
fn an_unknown_provenance_static_import_still_books_nothing_15191() {
    let state = build_forwarding_state(&static_snapshot("203.0.113.10", "192.168.1.10"));
    let key = snat_key("192.168.1.10".parse().unwrap(), 5000, SRV.parse().unwrap());
    let nat = crate::nat::NatDecision {
        rewrite_src: Some("203.0.113.10".parse().unwrap()),
        ..Default::default()
    };
    assert!(import_synced(&state, &key, nat, None));
    assert_eq!(retained(&state), 0);
}

/// CONTROL: a dynamic-provenance import naming an address no pool,
/// static entry, or NPTv6 prefix owns still falls through to the
/// interface arm (#7581/#6751 graceful-drift behaviour preserved).
#[test]
fn a_dynamic_import_to_an_unowned_address_still_books_interface_15191() {
    let state = build_forwarding_state(&nat_snapshot());
    let key = snat_key("10.0.0.9".parse().unwrap(), 40001, SRV.parse().unwrap());
    let nat = crate::nat::NatDecision {
        rewrite_src: Some("198.51.100.7".parse().unwrap()),
        ..Default::default()
    };
    assert!(import_synced(&state, &key, nat, Some(false)));
    assert_eq!(retained(&state), 1);
}
