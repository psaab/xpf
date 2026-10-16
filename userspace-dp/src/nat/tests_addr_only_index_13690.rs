// #13690: `reserve_address_only_roundrobin` stored `addr_index: 0` on every
// address-only `LiveAllocation` record, regardless of which pool address the
// probe loop actually selected. The guarded twin
// `reserve_address_only_persistent` binds `(ip, family_offset + rel, rkey)`
// from the same probe and stores that index on both its lease and its live
// record; the synced path (`reserve_address_only_maybe_persistent`) receives
// the true absolute index from `pool_index_of`. Only the round-robin path
// discarded the selected index.
//
// The stored index is load-bearing in `reseed_retained_from`: a config-apply
// pool re-seed filters and remaps carried live records by `addr_index`
// (`index_map.contains_key(&a.addr_index)`), so a record placed on pool
// address 1 but stamped 0 is dropped when address 0 leaves the pool and is
// carried (under the wrong remap) when address 1 leaves — silently losing
// the #5269 reverse-identity guard for a still-forwarding session.

use super::allocator::{PoolAddressFamily, PortAllocator};
use super::source::SourceNatFlowKey;
use super::*;
use crate::ip_proto::PROTO_GRE;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const A1: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
const A2: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 2);
const B1: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
const B2: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
const REMOTE_R: &str = "8.8.8.8";

fn gre_flow(src: &str, dst: &str) -> SourceNatFlowKey {
    SourceNatFlowKey {
        protocol: PROTO_GRE,
        src_ip: src.parse().expect("src"),
        dst_ip: dst.parse().expect("dst"),
        src_port: 0,
        dst_port: 0,
        routing_scope: 0,
    }
}

fn gre_flow_v6(src: &str, dst: &str) -> SourceNatFlowKey {
    SourceNatFlowKey {
        protocol: PROTO_GRE,
        src_ip: src.parse().expect("src"),
        dst_ip: dst.parse().expect("dst"),
        src_port: 0,
        dst_port: 0,
        routing_scope: 0,
    }
}

/// Allocate a flow whose probe starts at `start_abs` (absolute index over the
/// combined pool) so it deterministically lands on a non-zero pool index,
/// then assert the live record's `addr_index` names that same address.
#[test]
fn address_only_roundrobin_records_selected_addr_index_v4_13690() {
    let pool = [A1, A2];
    let alloc = PortAllocator::new(pool.len(), 1024, 65535);
    let flow = gre_flow("10.0.1.100", REMOTE_R);

    let translated = alloc
        .reserve_address_only_roundrobin(
            flow,
            PoolAddressFamily::V4(&pool),
            0,
            1, // start at the SECOND pool address
            false,
            NatHolder::Untracked,
        )
        .expect("allocation on the second pool address must succeed");
    assert_eq!(
        translated.ip,
        IpAddr::V4(A2),
        "fixture: the probe must land on pool[1]"
    );
    let stored_index = alloc
        .debug_live_flow_addr_index(&flow)
        .expect("the allocated flow must have a live record");
    assert_eq!(
        translated.ip,
        IpAddr::V4(pool[stored_index]),
        "addr_index {stored_index} must index the address the record actually holds"
    );
    assert_eq!(stored_index, 1, "the selected address is pool index 1");
}

/// V6 twin: the family offset folds v6 after v4, so a v6 record's
/// `addr_index` is the ABSOLUTE index (`family_offset + rel`), matching what
/// `reserve_address_only_persistent` stores and what `reseed_retained_from`'s
/// index map is keyed on.
#[test]
fn address_only_roundrobin_records_selected_addr_index_v6_13690() {
    let pool = [B1, B2];
    let v6_offset = 2; // two v4 addresses precede this family in the pool
    let alloc = PortAllocator::new(4, 1024, 65535);
    let flow = gre_flow_v6("fd00::100", "2001:db8:ffff::1");

    let translated = alloc
        .reserve_address_only_roundrobin(
            flow,
            PoolAddressFamily::V6(&pool),
            v6_offset,
            v6_offset + 1, // start at the SECOND v6 address (absolute)
            false,
            NatHolder::Untracked,
        )
        .expect("allocation on the second v6 pool address must succeed");
    assert_eq!(
        translated.ip,
        IpAddr::V6(B2),
        "fixture: the probe must land on pool[1] of the v6 family"
    );
    let stored_index = alloc
        .debug_live_flow_addr_index(&flow)
        .expect("the allocated flow must have a live record");
    assert_eq!(
        stored_index,
        v6_offset + 1,
        "addr_index must be the absolute index of the selected v6 address, \
         not the hardcoded 0"
    );
    assert_eq!(
        translated.ip,
        IpAddr::V6(pool[stored_index - v6_offset]),
        "addr_index must resolve back to the address the record holds"
    );
}
