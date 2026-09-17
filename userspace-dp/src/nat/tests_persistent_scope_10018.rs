// #10018: the persistent-NAT lease key must carry the routing scope.
//
// `SourceNatFlowKey` carries `routing_scope` (#9062), but
// `persistent_source_key()` built `PersistentSourceKey { protocol, src_ip,
// src_port, remote }` WITHOUT it, and the allocators are deliberately NOT
// routing-domain-partitioned (#9389: one pool is one shared resource of wire
// identities). Two tenants in different VRFs with overlapping subscriber IP
// space and `permit any-remote-host` persistent NAT therefore shared ONE
// translation lease: the second tenant's flow reused the first tenant's
// translated tuple (PAT) or was denied on a reverse identity the shared lease
// already owned (address-only).
//
// These cells bind the fix at three levels: the key itself, the allocator
// behaviour (PAT + address-only), and the #8121 idle-lease sync path. Each
// one REDS on the unscoped key and greens once the scope is carried. The
// same-VRF arms are guards, not decoration: scoping must partition by routing
// domain and NOTHING else, or persistence breaks for the single-VRF
// deployments that are the entire installed base.
//
// What is deliberately NOT scoped here: `AddressOnlyReverseKey` stays GLOBAL.
// The reverse identity is a wire identity — the return packet carries nothing
// that tells two VRFs apart — so two flows that would produce the same one
// cannot coexist whatever scope they came from. The single-address cell below
// pins that: if someone ever scopes the reverse key, the second VRF's flow is
// ADMITTED onto the same address and that cell reds.

use super::allocator::{NS_PER_SEC, NatHolder, PoolAddressFamily, PortAllocator, TranslatedTuple};
use super::source::{PersistentNatPermit, SourceNatFailureReason, SourceNatFlowKey};
use crate::ip_proto::PROTO_GRE;
use std::net::{IpAddr, Ipv4Addr};

const TCP: u8 = 6;
const TIMEOUT_NS: u64 = 300 * 1_000_000_000;

fn tcp_flow(src: &str, sport: u16, dst: &str, dport: u16, scope: u32) -> SourceNatFlowKey {
    SourceNatFlowKey {
        protocol: TCP,
        src_ip: src.parse().expect("src"),
        dst_ip: dst.parse().expect("dst"),
        src_port: sport,
        dst_port: dport,
        routing_scope: scope,
    }
}

/// A PORT-LESS GRE flow: `src_port`/`dst_port` are 0, so the reverse identity
/// is `(47, translated_ip, 0, dst_ip, 0)` — the degenerate key on which the
/// address-only arms turn.
fn gre_flow(src: &str, dst: &str, scope: u32) -> SourceNatFlowKey {
    SourceNatFlowKey {
        protocol: PROTO_GRE,
        src_ip: src.parse().expect("src"),
        dst_ip: dst.parse().expect("dst"),
        src_port: 0,
        dst_port: 0,
        routing_scope: scope,
    }
}

fn allocate_pat(
    alloc: &PortAllocator,
    pool: &[Ipv4Addr],
    flow: SourceNatFlowKey,
    permit: PersistentNatPermit,
    now_ns: u64,
) -> Result<TranslatedTuple, SourceNatFailureReason> {
    alloc.allocate_translation(
        flow,
        PoolAddressFamily::V4(pool),
        0,
        false,
        true,
        permit,
        TIMEOUT_NS,
        now_ns,
        NatHolder::Untracked,
    )
}

fn reserve_addr_only(
    alloc: &PortAllocator,
    pool: &[Ipv4Addr],
    flow: SourceNatFlowKey,
) -> Result<TranslatedTuple, SourceNatFailureReason> {
    alloc.reserve_address_only_persistent(
        flow,
        PoolAddressFamily::V4(pool),
        0,
        false,
        PersistentNatPermit::AnyRemoteHost,
        TIMEOUT_NS,
        NS_PER_SEC,
        NatHolder::Untracked,
    )
}

/// THE KEY CELL. One subscriber 5-tuple in two routing scopes must be two
/// persistent leases under EVERY permit shape — the scope is orthogonal to
/// the #2823 remote folding, not a substitute for one arm of it.
///
/// RED pre-#10018: all three `assert_ne!` fail (the keys are identical).
#[test]
fn persistent_source_key_separates_routing_scopes_10018() {
    let a = tcp_flow("10.0.0.1", 1234, "8.8.8.8", 443, 1);
    let b = SourceNatFlowKey {
        routing_scope: 2,
        ..a
    };
    assert_ne!(a, b, "fixture: #9062 already separates the FLOW keys");
    for permit in [
        PersistentNatPermit::AnyRemoteHost,
        PersistentNatPermit::TargetHost,
        PersistentNatPermit::TargetHostPort,
    ] {
        assert_ne!(
            a.persistent_source_key(permit),
            b.persistent_source_key(permit),
            "an identical subscriber tuple in two routing scopes must be two \
             leases under {permit:?}; sharing one is the cross-VRF lease \
             collision (#10018)"
        );
    }

    // The default/unscoped domain is 0, and it is a scope like any other: a
    // scoped tenant must not share with it either.
    let unscoped = SourceNatFlowKey {
        routing_scope: 0,
        ..a
    };
    assert_ne!(
        unscoped.persistent_source_key(PersistentNatPermit::AnyRemoteHost),
        a.persistent_source_key(PersistentNatPermit::AnyRemoteHost),
        "domain 0 and domain 1 are different scopes"
    );

    // REFERENCE ARM: the same flow in the same scope is still one lease, or
    // every packet mints and the pool drains.
    let a2 = SourceNatFlowKey { ..a };
    assert_eq!(
        a.persistent_source_key(PersistentNatPermit::AnyRemoteHost),
        a2.persistent_source_key(PersistentNatPermit::AnyRemoteHost),
        "the same subscriber in the same scope must be one lease"
    );
}

/// OVER-PARTITIONING GUARD. Within ONE scope the #2823 permit shapes keep
/// their exact meaning: scoping partitions by routing domain and NOTHING
/// else.
///
/// GREEN pre- and post-#10018; RED under a fix that re-keys by flow or by
/// remote where the permit says not to.
#[test]
fn same_scope_keeps_permit_sharing_10018() {
    let base = tcp_flow("10.0.0.1", 1234, "8.8.8.8", 443, 1);
    // `AnyRemoteHost`: any remote reuses the mapping.
    let other_remote = tcp_flow("10.0.0.1", 1234, "9.9.9.9", 53, 1);
    assert_eq!(
        base.persistent_source_key(PersistentNatPermit::AnyRemoteHost),
        other_remote.persistent_source_key(PersistentNatPermit::AnyRemoteHost),
        "any-remote-host must still share across remote hosts in one scope"
    );
    // `TargetHost`: the remote IP is folded in, the port is dropped.
    let other_port = tcp_flow("10.0.0.1", 1234, "8.8.8.8", 80, 1);
    assert_eq!(
        base.persistent_source_key(PersistentNatPermit::TargetHost),
        other_port.persistent_source_key(PersistentNatPermit::TargetHost),
        "target-host must still share across remote ports on one host"
    );
    assert_ne!(
        base.persistent_source_key(PersistentNatPermit::TargetHost),
        other_remote.persistent_source_key(PersistentNatPermit::TargetHost),
        "target-host must still separate remote hosts"
    );
    // `TargetHostPort`: the full remote endpoint is folded in.
    assert_ne!(
        base.persistent_source_key(PersistentNatPermit::TargetHostPort),
        other_port.persistent_source_key(PersistentNatPermit::TargetHostPort),
        "target-host-port must still separate remote ports"
    );
    assert_ne!(
        base.persistent_source_key(PersistentNatPermit::TargetHostPort),
        other_remote.persistent_source_key(PersistentNatPermit::TargetHostPort),
        "target-host-port must still separate remote hosts"
    );
}

/// VRFs, one shared single-address pool, `permit any-remote-host`: two leases,
/// two ports. The single address is load-bearing twice over: it proves the
/// leases are distinct (one lease would reuse the one port) AND that #9389's
/// shared port occupancy is retained (both ports come from the one address).
///
/// RED pre-#10018: the second flow reuses the first's tuple.
#[test]
fn cross_vrf_overlapping_subscribers_get_distinct_pat_leases_10018() {
    let pool = ["203.0.113.1".parse().unwrap()];
    let alloc = PortAllocator::new(pool.len(), 1024, 65535);

    let vrf1 = tcp_flow("10.0.0.1", 1234, "8.8.8.8", 443, 1);
    let vrf2 = SourceNatFlowKey {
        routing_scope: 2,
        ..vrf1
    };
    let t1 = allocate_pat(&alloc, &pool, vrf1, PersistentNatPermit::AnyRemoteHost, 1_000)
        .expect("the first VRF must mint");
    let t2 = allocate_pat(&alloc, &pool, vrf2, PersistentNatPermit::AnyRemoteHost, 1_000)
        .expect("the second VRF must mint rather than reuse");
    assert_ne!(
        (t1.ip, t1.port),
        (t2.ip, t2.port),
        "overlapping subscribers in two VRFs must hold distinct translations; \
         sharing one is the cross-tenant lease collision (#10018)"
    );
    assert_eq!(
        t1.ip, t2.ip,
        "control: one pool address serves both, so the distinction is two \
         PORTS from the shared occupancy (#9389 retained), not two allocators"
    );
    assert_eq!(
        alloc.debug_live().persistent_by_source.len(),
        2,
        "two scopes hold two leases"
    );

    // REFERENCE ARM: the same subscriber's second flow in the SAME VRF still
    // reuses its VRF's lease.
    let vrf1_second_remote = tcp_flow("10.0.0.1", 1234, "9.9.9.9", 53, 1);
    let t1_again = allocate_pat(
        &alloc,
        &pool,
        vrf1_second_remote,
        PersistentNatPermit::AnyRemoteHost,
        1_000,
    )
    .expect("same-VRF reuse must keep working");
    assert_eq!(
        (t1_again.ip, t1_again.port),
        (t1.ip, t1.port),
        "same-VRF any-remote-host must still reuse the VRF's lease"
    );
}

/// HA AGREEMENT. Four sites build the lease key — the match path, the synced
/// reserve, and the release path (all from `SessionKey.routing_domain`, per
/// the #9062 docs), plus the #8121 import — and the standby's must be
/// byte-identical to the active's for the same scope and distinct across
/// scopes. The flow-key half of that agreement is pinned by the #9062/#9388
/// cells; this cell binds the lease half through the single helper every site
/// calls, and through a real active-mint/standby-reserve round trip.
///
/// RED pre-#10018: the cross-scope assertions fail (one shared lease).
#[test]
fn active_standby_and_release_agree_on_the_scoped_key_10018() {
    let session_domain = 7u32;
    // What the match path builds from the scope...
    let active_flow = tcp_flow("10.0.0.1", 1234, "8.8.8.8", 443, session_domain);
    // ...what the synced reserve and the release path build FROM the session
    // key (`synced.rs` / `release.rs`: `routing_scope: key.routing_domain`).
    let session_key = crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: TCP,
        src_ip: "10.0.0.1".parse().unwrap(),
        dst_ip: "8.8.8.8".parse().unwrap(),
        src_port: 1234,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: session_domain,
    };
    let synced_flow = SourceNatFlowKey {
        protocol: session_key.protocol,
        src_ip: session_key.src_ip,
        dst_ip: session_key.dst_ip,
        src_port: session_key.src_port,
        dst_port: session_key.dst_port,
        routing_scope: session_key.routing_domain,
    };
    assert_eq!(
        active_flow, synced_flow,
        "fixture: the active and the standby build the same flow"
    );
    let active_key = active_flow.persistent_source_key(PersistentNatPermit::AnyRemoteHost);
    let standby_key = synced_flow.persistent_source_key(PersistentNatPermit::AnyRemoteHost);
    assert_eq!(
        active_key, standby_key,
        "the standby's lease must be keyed identically to the active's"
    );
    let other_domain_flow = SourceNatFlowKey {
        routing_scope: 9,
        ..active_flow
    };
    assert_ne!(
        active_key,
        other_domain_flow.persistent_source_key(PersistentNatPermit::AnyRemoteHost),
        "a different routing domain must key a different lease"
    );

    // Through the real round trip: the active mints, the standby reserves the
    // synced flow into the SAME lease, and a same-tuple flow from another VRF
    // mints its OWN.
    let pool = ["203.0.113.1".parse().unwrap()];
    let active = PortAllocator::new(pool.len(), 1024, 65535);
    let standby = PortAllocator::new(pool.len(), 1024, 65535);
    let t = allocate_pat(
        &active,
        &pool,
        active_flow,
        PersistentNatPermit::AnyRemoteHost,
        1_000,
    )
    .expect("the active must mint");
    assert!(
        standby.reserve_flow_maybe_persistent(
            synced_flow,
            t,
            0,
            false,
            1_000,
            NatHolder::Untracked,
            Some((standby_key, TIMEOUT_NS)),
        ),
        "the standby must reserve the synced flow into the active's lease"
    );
    assert_eq!(
        standby
            .debug_live_flow_translated(&synced_flow)
            .expect("the synced flow must be live on the standby"),
        t,
        "the standby's reservation joins the lease, not a fresh tuple"
    );
    let other_vrf = allocate_pat(
        &standby,
        &pool,
        other_domain_flow,
        PersistentNatPermit::AnyRemoteHost,
        1_000,
    )
    .expect("the other VRF must mint on the standby");
    assert_ne!(
        (other_vrf.ip, other_vrf.port),
        (t.ip, t.port),
        "the other VRF must not join the synced lease on the standby"
    );
}

/// THE #8121 CELL. Two same-subscriber leases in two scopes are exported as
/// TWO scoped records and import as two leases: each scope's next flow reuses
/// ITS scope's port. No record literal appears here — the scope is asserted
/// through reuse behaviour, so this cell compiles and REDS pre-fix.
///
/// RED pre-#10018: one shared lease is exported (`len == 1`), and the scope-2
/// flow reuses the scope-1 port.
#[test]
fn idle_lease_sync_carries_scope_and_matches_it_on_import_10018() {
    let addrs: [Ipv4Addr; 3] = [
        "203.0.113.1".parse().unwrap(),
        "203.0.113.2".parse().unwrap(),
        "203.0.113.3".parse().unwrap(),
    ];
    let active = PortAllocator::new(1, 1024, 65535);
    let scope1 = tcp_flow("10.0.61.50", 40000, "8.8.8.8", 443, 1);
    let scope2 = SourceNatFlowKey {
        routing_scope: 2,
        ..scope1
    };
    let t1 = allocate_pat(&active, &addrs, scope1, PersistentNatPermit::AnyRemoteHost, 1_000)
        .expect("scope 1 must mint");
    let t2 = allocate_pat(&active, &addrs, scope2, PersistentNatPermit::AnyRemoteHost, 1_000)
        .expect("scope 2 must mint");
    assert_ne!(
        (t1.ip, t1.port),
        (t2.ip, t2.port),
        "fixture: the two scopes hold distinct translations"
    );
    assert!(active.release_flow(scope1, t1, 2_000, NatHolder::Untracked));
    assert!(active.release_flow(scope2, t2, 2_000, NatHolder::Untracked));

    let exported = active.export_idle_leases(3_000);
    assert_eq!(
        exported.len(),
        2,
        "two scoped leases must export as two records; one shared record is \
         the unscoped key (#10018)"
    );

    // The standby's clock is unrelated to the active's — the #8121 discipline.
    let standby = PortAllocator::new(1, 1024, 65535);
    let standby_pool: Vec<IpAddr> = addrs.iter().copied().map(IpAddr::V4).collect();
    let standby_now = 9_000_000_000_000u64;
    for rec in &exported {
        assert_eq!(
            standby.import_idle_lease(rec, &standby_pool, standby_now),
            super::idle_lease_sync_8121::IdleLeaseImport::Installed,
            "each scoped record must install"
        );
    }
    assert_eq!(
        standby.debug_live().persistent_by_source.len(),
        2,
        "the standby holds two leases, one per scope"
    );
    let r1 = allocate_pat(
        &standby,
        &addrs,
        scope1,
        PersistentNatPermit::AnyRemoteHost,
        standby_now + 1,
    )
    .expect("scope 1 must reuse its imported lease");
    let r2 = allocate_pat(
        &standby,
        &addrs,
        scope2,
        PersistentNatPermit::AnyRemoteHost,
        standby_now + 1,
    )
    .expect("scope 2 must reuse its imported lease");
    assert_eq!(
        (r1.ip, r1.port),
        (t1.ip, t1.port),
        "scope 1 reuses the scope-1 port it held on the active"
    );
    assert_eq!(
        (r2.ip, r2.port),
        (t2.ip, t2.port),
        "scope 2 reuses the scope-2 port it held on the active"
    );
}

/// THE ADDRESS-ONLY CELLS. Port-less GRE, same subscriber in two scopes.
///
/// Two-address pool: the second scope's flow mints a FRESH lease and probes
/// onto the free sibling — pre-fix it reused the shared lease and was DENIED
/// on the first scope's reverse identity (the availability half of #10018).
/// One-address pool: the second scope is still DENIED, pre and post — with no
/// sibling the reverse identity is genuinely ambiguous on the return path, and
/// that refusal is what pins `AddressOnlyReverseKey` as scope-global. If the
/// reverse key is ever scoped, this cell reds by ADMITTING.
///
/// RED pre-#10018: the two-address second flow is denied.
#[test]
fn address_only_cross_vrf_probes_the_free_sibling_10018() {
    let pool = [
        Ipv4Addr::new(203, 0, 113, 1),
        Ipv4Addr::new(203, 0, 113, 2),
    ];
    let alloc = PortAllocator::new(pool.len(), 1024, 65535);
    let scope1 = gre_flow("10.0.1.100", "8.8.8.8", 1);
    let scope2 = SourceNatFlowKey {
        routing_scope: 2,
        ..scope1
    };
    let t1 = reserve_addr_only(&alloc, &pool, scope1).expect("scope 1 must mint");
    assert_eq!(t1.ip, IpAddr::V4(pool[0]), "fixture: index 0");
    let t2 = reserve_addr_only(&alloc, &pool, scope2).expect(
        "the second scope holds its own lease and must probe onto the free \
         sibling; denying it is the shared-lease availability loss (#10018)",
    );
    assert_eq!(
        t2.ip,
        IpAddr::V4(pool[1]),
        "the second scope's lease pins the sibling it actually used"
    );
    assert_eq!(
        alloc.debug_live().persistent_by_source.len(),
        2,
        "two scopes hold two leases"
    );
}

#[test]
fn address_only_cross_vrf_single_address_still_denies_10018() {
    let pool = [Ipv4Addr::new(203, 0, 113, 1)];
    let alloc = PortAllocator::new(pool.len(), 1024, 65535);
    let scope1 = gre_flow("10.0.1.100", "8.8.8.8", 1);
    let scope2 = SourceNatFlowKey {
        routing_scope: 2,
        ..scope1
    };
    reserve_addr_only(&alloc, &pool, scope1).expect("scope 1 must mint");
    assert_eq!(
        reserve_addr_only(&alloc, &pool, scope2).err(),
        Some(SourceNatFailureReason::AllocatorExhausted),
        "with one address the second scope's reverse identity is genuinely \
         ambiguous on the return path — the refusal stays fail-CLOSED, and it \
         is what pins the reverse key as scope-global"
    );
    assert_eq!(
        alloc.debug_live().persistent_by_source.len(),
        1,
        "the denied flow must not create a lease or mutate the incumbent"
    );
}
