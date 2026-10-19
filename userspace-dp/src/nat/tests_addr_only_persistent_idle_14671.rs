// #14671: same-allocator address-only admission ignored idle persistent
// address-only leases (persistent_address_only_owner_counts).
//
// Scenario: H1 mints an address-only persistent lease (translated A1, preserved
// port P) to remote R, then releases its only flow. The lease stays idle for
// its 300s timeout and persistent_by_translated still maps (proto,A1,P) -> H1,
// permitted for R. Before the fix the three same-allocator address-only
// admission paths only consulted LIVE address_only_owners / pat_owners, so a
// second subscriber H2 with the same source port to the same remote was minted
// the same (A1,P). persistent_by_translated then held two source keys for one
// wire identity and persistent_inbound_lookup returned Denied for BOTH.
//
// Fix: route same-allocator address-only admission through
// address_only_owns_wire_identity, which consults
// persistent_address_only_owner_counts scoped by the lease's recorded
// permissions (Exact/Host/HostWildcard/AnyWildcard).
//
// Controls that must stay admissible:
//  - different preserved source port on the idle lease's address
//  - same port to a remote the idle lease does NOT permit (TargetHostPort)
//  - same subscriber re-joining its own idle lease (reuse, not a collision)

use super::allocator::{
    NS_PER_SEC, NatHolder, PersistentInbound, PoolAddressFamily, PortAllocator, TranslatedTuple,
};
use super::source::{PersistentNatPermit, SourceNatFailureReason, SourceNatFlowKey};
use crate::ip_proto::PROTO_TCP;
use std::net::{IpAddr, Ipv4Addr};

const A1: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
const A2: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 2);
const REMOTE: &str = "8.8.8.8";
const REMOTE2: &str = "9.9.9.9";
const TIMEOUT_NS: u64 = 300 * NS_PER_SEC;
const NOW: u64 = NS_PER_SEC;
const NOW2: u64 = 2 * NS_PER_SEC;

fn tcp_flow(src: &str, sport: u16, dst: &str, dport: u16) -> SourceNatFlowKey {
    SourceNatFlowKey {
        protocol: PROTO_TCP,
        src_ip: src.parse().expect("src"),
        dst_ip: dst.parse().expect("dst"),
        src_port: sport,
        dst_port: dport,
        routing_scope: 0,
    }
}

fn reserve_persistent(
    alloc: &PortAllocator,
    pool: &[Ipv4Addr],
    flow: SourceNatFlowKey,
    permit: PersistentNatPermit,
    now_ns: u64,
) -> Result<TranslatedTuple, SourceNatFailureReason> {
    alloc.reserve_address_only_persistent(
        flow,
        PoolAddressFamily::V4(pool),
        0,
        false,
        permit,
        TIMEOUT_NS,
        now_ns,
        NatHolder::Untracked,
        0,
    )
}

fn h1_idle(permit: PersistentNatPermit) -> (PortAllocator, Vec<Ipv4Addr>, TranslatedTuple) {
    let pool = vec![A1, A2];
    let alloc = PortAllocator::new(pool.len(), 1024, 65535);
    let h1 = tcp_flow("10.0.1.1", 4000, REMOTE, 443);
    let t1 = reserve_persistent(&alloc, &pool, h1, permit, NOW).expect("H1 mints");
    assert_eq!(t1.ip, IpAddr::V4(A1), "fixture: first mint is round-robin A1");
    assert_eq!(t1.port, 4000);
    assert!(
        alloc.release_flow(h1, t1, NOW2, NatHolder::Untracked),
        "H1 flow releases; lease goes idle but unexpired"
    );
    // Fixture: idle lease counted, inbound still permitted for H1.
    assert!(
        alloc.debug_persistent_address_only_owner_count() > 0,
        "idle address-only lease must populate persistent owner counts"
    );
    let inbound = alloc.persistent_inbound_lookup(
        PROTO_TCP,
        t1.ip,
        t1.port,
        REMOTE.parse().unwrap(),
        443,
        NOW2,
        "",
        "",
    );
    assert!(
        matches!(
            inbound,
            PersistentInbound::Permitted {
                internal_ip,
                internal_port: 4000,
                address_only: true, lease_key: _
            } if internal_ip == "10.0.1.1".parse::<IpAddr>().unwrap()
        ),
        "fixture: idle H1 lease must permit inbound before H2, got {inbound:?}"
    );
    (alloc, pool, t1)
}

#[test]
fn idle_persistent_address_only_blocks_duplicate_wire_persistent_14671() {
    let (alloc, pool, t1) = h1_idle(PersistentNatPermit::TargetHostPort);
    // H2: different subscriber, SAME preserved source port, same remote.
    // Round-robin would pick A2, but its own fresh lease must not reuse A1's
    // idle identity either way; the strong assertions are distinctness and
    // that inbound still resolves to exactly H1 (not Denied for both).
    let h2 = tcp_flow("10.0.2.2", 4000, REMOTE, 443);
    if let Ok(t2) = reserve_persistent(&alloc, &pool, h2, PersistentNatPermit::TargetHostPort, NOW2)
    {
        assert_ne!(
            (t2.ip, t2.port),
            (t1.ip, t1.port),
            "H2 must not be minted H1's idle (translated_ip, port)"
        );
    }
    let inbound = alloc.persistent_inbound_lookup(
        PROTO_TCP,
        t1.ip,
        t1.port,
        REMOTE.parse().unwrap(),
        443,
        NOW2,
        "",
        "",
    );
    assert!(
        matches!(
            inbound,
            PersistentInbound::Permitted {
                internal_ip,
                internal_port: 4000,
                ..
            } if internal_ip == "10.0.1.1".parse::<IpAddr>().unwrap()
        ),
        "inbound to H1's idle tuple must stay Permitted(H1), got {inbound:?} \
         (Denied = duplicate lease blackholed both subscribers)"
    );
}

#[test]
fn idle_persistent_address_only_blocks_duplicate_wire_single_addr_14671() {
    // Deterministic single-address form of the decisive check: no sibling to
    // rotate to, so H2 must be refused rather than duplicated.
    let pool = vec![A1];
    let alloc = PortAllocator::new(1, 1024, 65535);
    let h1 = tcp_flow("10.0.1.1", 4000, REMOTE, 443);
    let t1 = reserve_persistent(&alloc, &pool, h1, PersistentNatPermit::TargetHostPort, NOW)
        .expect("H1 mints");
    assert!(alloc.release_flow(h1, t1, NOW2, NatHolder::Untracked));
    let h2 = tcp_flow("10.0.2.2", 4000, REMOTE, 443);
    assert!(
        reserve_persistent(&alloc, &pool, h2, PersistentNatPermit::TargetHostPort, NOW2).is_err(),
        "single-address pool: H2 with H1's idle (ip,port) to same remote must be refused"
    );
    let inbound = alloc.persistent_inbound_lookup(
        PROTO_TCP,
        t1.ip,
        t1.port,
        REMOTE.parse().unwrap(),
        443,
        NOW2,
        "",
        "",
    );
    assert!(
        matches!(inbound, PersistentInbound::Permitted { .. }),
        "H1 inbound must remain Permitted, got {inbound:?}"
    );
}

#[test]
fn idle_persistent_address_only_blocks_roundrobin_and_synced_14671() {
    // Non-persistent roundrobin sibling on a single-address pool.
    {
        let pool = vec![A1];
        let alloc = PortAllocator::new(1, 1024, 65535);
        let h1 = tcp_flow("10.0.1.1", 4000, REMOTE, 443);
        let t1 = reserve_persistent(&alloc, &pool, h1, PersistentNatPermit::TargetHostPort, NOW)
            .expect("H1 mints");
        assert!(alloc.release_flow(h1, t1, NOW2, NatHolder::Untracked));
        let h2 = tcp_flow("10.0.2.2", 4000, REMOTE, 443);
        let res = alloc.reserve_address_only_roundrobin(
            h2,
            PoolAddressFamily::V4(&pool),
            0,
            0,
            false,
            NatHolder::Untracked,
        );
        assert!(
            res.is_err(),
            "roundrobin must refuse H1's idle identity, got {res:?}"
        );
    }
    // Synced pinned-address path (reserve_address_only).
    {
        let (alloc, _pool, t1) = h1_idle(PersistentNatPermit::TargetHostPort);
        let h2 = tcp_flow("10.0.2.2", 4000, REMOTE, 443);
        let res = alloc.reserve_address_only(h2, t1.ip, 0, NatHolder::Untracked);
        assert!(
            res.is_err(),
            "synced reserve_address_only must refuse H1's idle identity, got {res:?}"
        );
    }
}

#[test]
fn idle_persistent_address_only_controls_stay_admissible_14671() {
    let (alloc, pool, t1) = h1_idle(PersistentNatPermit::TargetHostPort);
    // Different preserved port on same address: distinct wire identity.
    let other_port = tcp_flow("10.0.2.2", 4001, REMOTE, 443);
    let t = reserve_persistent(
        &alloc,
        &pool,
        other_port,
        PersistentNatPermit::TargetHostPort,
        NOW2,
    )
    .expect("different source port must stay admissible");
    assert_ne!((t.ip, t.port), (t1.ip, t1.port));
    assert_eq!(t.port, 4001);

    // Same port to a remote H1's TargetHostPort lease does not permit.
    let (alloc2, pool2, t1b) = h1_idle(PersistentNatPermit::TargetHostPort);
    let other_remote = tcp_flow("10.0.2.2", 4000, REMOTE2, 443);
    let t = reserve_persistent(
        &alloc2,
        &pool2,
        other_remote,
        PersistentNatPermit::TargetHostPort,
        NOW2,
    )
    .expect("unpermitted remote must stay admissible (distinct reverse tuple)");
    // Distinct reverse tuple even if it happens to land on A1: (A1,4000,R2)
    // is not H1's (A1,4000,R). Success is the assertion.
    assert_eq!(t.port, 4000);

    // Same subscriber re-joins its own idle lease (reuse).
    let (alloc3, pool3, t1c) = h1_idle(PersistentNatPermit::TargetHostPort);
    let h1_again = tcp_flow("10.0.1.1", 4000, REMOTE, 443);
    let t = reserve_persistent(
        &alloc3,
        &pool3,
        h1_again,
        PersistentNatPermit::TargetHostPort,
        NOW2,
    )
    .expect("same subscriber must reuse its idle lease");
    assert_eq!((t.ip, t.port), (t1c.ip, t1c.port));
}
