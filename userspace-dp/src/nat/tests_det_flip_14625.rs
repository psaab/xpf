// #14625: removing `port deterministic` strands deterministic ports in the
// reused allocator.
//
// The allocator is reused across config generations because
// `SourceNatPoolAllocatorKey` excludes allocation mode. Ports claimed
// deterministically while the pool was in deterministic mode were released
// with `free_no_recycle` (the occupancy bit is the only reuse gate, and
// `claim_in_block` scans the bitmap directly). But round-robin PAT
// `claim()` never scans the bitmap once its fresh cursor is spent -- it
// only drains the recycle FIFO. A deterministic port freed without a
// recycle token after a deterministic -> PAT mode flip was therefore
// unreachable for PAT even though its bit is clear and
// `show security nat source pool` reports it free. #14625: every free now
// recycles (bounded ring; `claim_in_block` ignores it).
//
// Acceptance (verifier): a PAT claim after the flip returns the freed
// deterministic port while the PAT control is unchanged.
//
// RED on current master: the probe PAT claim returns
// `Err(AllocatorExhausted)` despite the clear bit.

use super::allocator::{DeterministicV4, NatHolder, PoolAddressFamily, PortAllocator};
use super::source::{PersistentNatPermit, SourceNatFailureReason, SourceNatFlowKey};
use std::net::{IpAddr, Ipv4Addr};

const POOL: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
const PORT_LOW: u16 = 20000;
const PORT_HIGH: u16 = 20003;

fn flow(src_port: u16, dst: Ipv4Addr) -> SourceNatFlowKey {
    SourceNatFlowKey {
        protocol: 6,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        dst_ip: IpAddr::V4(dst),
        src_port,
        dst_port: 443,
        routing_scope: 0,
    }
}

fn pat_claim(alloc: &PortAllocator, src_port: u16) -> Result<u16, SourceNatFailureReason> {
    let addrs = [POOL];
    alloc
        .allocate_translation(
            flow(src_port, Ipv4Addr::new(8, 8, 8, 8)),
            PoolAddressFamily::V4(&addrs),
            0,
            false,
            false,
            PersistentNatPermit::TargetHostPort,
            0,
            1_000,
            NatHolder::Untracked,
            // #14802: non-persistent PAT claim; egress scope only buckets
            // persistent grants, so the unscoped sentinel (0) is correct.
            0,
        )
        .map(|t| t.port)
}

/// Ports 20000..=20003, one address. Deterministic params: block_size 4,
/// one block covering the whole range for subscriber 100.64.0.0.
fn det_params() -> DeterministicV4 {
    DeterministicV4 {
        block_size: 4,
        blocks_per_ip: 1,
        host_base: u32::from(Ipv4Addr::new(100, 64, 0, 0)),
        host_count: 1,
    }
}

#[test]
fn det_release_after_flip_is_reclaimable_14625() {
    let alloc = PortAllocator::new(1, PORT_LOW, PORT_HIGH);
    let pool = [POOL];
    let subscriber = Ipv4Addr::new(100, 64, 0, 0);

    // --- Deterministic phase (pool has `port deterministic`): claim all
    // four ports through the deterministic block probe. This also spends
    // no PAT cursor; the cursor is advanced below to model PAT claims
    // that happened while deterministic flows occupied low ports (the
    // narrowed condition: cursor must pass the freed offsets).
    let mut det_flows = Vec::new();
    let mut det_tuples = Vec::new();
    for n in 0..4u16 {
        let f = flow(40_000 + n, Ipv4Addr::new(8, 8, 8, 8));
        let t = alloc
            .allocate_deterministic_v4(f, &pool, det_params(), subscriber, NatHolder::Untracked)
            .expect("deterministic claim must succeed");
        det_flows.push(f);
        det_tuples.push(t);
    }
    assert_eq!(
        det_tuples.iter().map(|t| t.port).collect::<Vec<_>>(),
        vec![20000, 20001, 20002, 20003],
        "fixture: deterministic block must claim the whole range in order"
    );

    // Spend the PAT fresh cursor, as PAT allocations interleaved with /
    // preceding the deterministic occupancy would. After this, PAT can
    // only be served from the recycle FIFO.
    alloc.debug_set_cursor(0, 4);

    // --- Mode flip: `port deterministic` removed. The allocator is
    // reused (same key), deterministic sessions drain. Release ONE
    // deterministic flow through the real release path (#14625: its port
    // now recycles like any other).
    let released_port = det_tuples[0].port;
    assert_eq!(released_port, 20000);
    assert!(
        alloc.release_flow(det_flows[0], det_tuples[0], 2_000, NatHolder::Untracked),
        "deterministic release must succeed"
    );
    assert!(
        !alloc.debug_is_port_occupied(0, released_port),
        "fixture: released deterministic port bit must be clear"
    );

    // The freed deterministic port must be claimable by PAT now that the
    // pool serves round-robin. Pre-fix this is Err(AllocatorExhausted).
    let reclaimed = pat_claim(&alloc, 50_000);
    assert_eq!(
        reclaimed,
        Ok(20000),
        "a deterministic port freed after a deterministic->PAT flip must be \
         reclaimable by PAT; a clear bit that claim() cannot reach is stranded \
         capacity (#14625)"
    );

    // --- PAT control: release the just-reclaimed PAT flow and claim
    // again. The recycle FIFO holds exactly the re-freed 20000 (20001 and
    // 20003 are still held by live deterministic flows, 20002 was never
    // claimed by PAT here), so the next PAT claim returns 20000 through
    // the FIFO — the same oldest-first recycle PAT always had (#3011).
    let pat_flow = flow(50_000, Ipv4Addr::new(8, 8, 8, 8));
    let pat_tuple = super::allocator::TranslatedTuple {
        ip: IpAddr::V4(POOL),
        port: 20000,
    };
    assert!(alloc.release_flow(pat_flow, pat_tuple, 3_000, NatHolder::Untracked));
    let control = pat_claim(&alloc, 50_001);
    assert_eq!(
        control,
        Ok(20000),
        "PAT control: a PAT port freed through the recycle path must be \
         reclaimable through the FIFO, unchanged by #14625"
    );
}

#[test]
fn pat_control_recycles_without_flip_14625() {
    // Control with no deterministic history at all: PAT claim, release,
    // reclaim returns the freed port. This must pass before and after.
    let alloc = PortAllocator::new(1, PORT_LOW, PORT_HIGH);
    let first = pat_claim(&alloc, 60_000).expect("first PAT claim");
    assert_eq!(first, 20000);
    let f = flow(60_000, Ipv4Addr::new(8, 8, 8, 8));
    let t = super::allocator::TranslatedTuple {
        ip: IpAddr::V4(POOL),
        port: first,
    };
    assert!(alloc.release_flow(f, t, 2_000, NatHolder::Untracked));
    // Cursor has only advanced by one, so the next claim takes a fresh
    // port -- that is the pre-existing PAT behaviour, pinned here so the
    // flip test's cursor-spent fixture is not confused with it.
    let second = pat_claim(&alloc, 60_001).expect("second PAT claim");
    assert_eq!(second, 20001);
}
