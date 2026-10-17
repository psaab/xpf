// #14622 (Y23-01): an address-only reseed carry re-stamped `addr_index 0`,
// and the deterministic address-only mint did the same.
//
// `LiveAllocation.addr_index` must name the pool address the record holds.
// `reseed_retained_from` filters and remaps carried records on it
// (`index_map.contains_key(&a.addr_index)` / `index_map.get(&a.addr_index)`),
// so a record truly on pool[1] but stamped 0 survives a first pool edit under
// the wrong remap and is then DROPPED by a second edit that removes pool[0]
// — silently losing the #5269 reverse-identity guard for a still-forwarding
// GRE/ESP/`port no-translation` session, so a colliding arrival is ADMITTED
// instead of refused.
//
// #13690 fixed the round-robin mint (`reserve_address_only_roundrobin`
// stores `family_offset + rel`). Two siblings were left stamping 0:
//   * the reseed carry in `reseed_retained_from`, which computed `new_index`
//     for the port-bearing arm but called `reserve_address_only` (hardcoded
//     0) for the address-only arm (#8597 K11 carry);
//   * the deterministic-CGNAT address-only mint in `match_rules.rs`, which
//     computed `ip_idx` to choose the pool address but discarded it when
//     minting via `reserve_address_only`.
//
// The fix threads the selected index through `reserve_address_only`'s new
// `addr_index` parameter at every call site (interface-mode allocators are
// single-address, so 0 is their true index).

use super::allocator::{PoolAddressFamily, PortAllocator};
use super::source::{SourceNatFailureReason, SourceNatFlowKey, SourceNatLookup};
use super::*;
use crate::ip_proto::{PROTO_GRE, PROTO_TCP};
use crate::SourceNATRuleSnapshot;
use std::net::{IpAddr, Ipv4Addr};

fn expect_snat_decision(lookup: SourceNatLookup) -> NatDecision {
    match lookup {
        SourceNatLookup::Matched(decision) => decision,
        other => panic!("expected matched SNAT decision, got {other:?}"),
    }
}

const A1: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
const A2: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 2);
const A3: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 3);

fn gre_flow(src: &str, src_port: u16, dst: &str) -> SourceNatFlowKey {
    SourceNatFlowKey {
        protocol: PROTO_GRE,
        src_ip: src.parse().expect("src"),
        dst_ip: dst.parse().expect("dst"),
        src_port,
        dst_port: 0,
        routing_scope: 0,
    }
}

fn tcp_flow(src: &str, src_port: u16, dst: &str, dst_port: u16) -> SourceNatFlowKey {
    SourceNatFlowKey {
        protocol: PROTO_TCP,
        src_ip: src.parse().expect("src"),
        dst_ip: dst.parse().expect("dst"),
        src_port,
        dst_port,
        routing_scope: 0,
    }
}

/// Mint an address-only record on pool[1] of `alloc` via the round-robin
/// path (the #13690-correct mint), so the fixture starts from a correctly
/// stamped gen1 record.
fn mint_on_pool1(alloc: &PortAllocator, flow: SourceNatFlowKey) {
    let pool = [A1, A2];
    let translated = alloc
        .reserve_address_only_roundrobin(
            flow,
            PoolAddressFamily::V4(&pool),
            0,
            1, // start at the SECOND pool address
            false,
            NatHolder::Untracked,
        )
        .expect("fixture: allocation on pool[1] must succeed");
    assert_eq!(
        translated.ip,
        IpAddr::V4(A2),
        "fixture: the probe must land on pool[1]"
    );
    assert_eq!(
        alloc.debug_live_flow_addr_index(&flow),
        Some(1),
        "fixture: gen1 must start correctly stamped at index 1"
    );
}

/// THE BINDER (Y23-01): two ordinary pool edits must not drop the #5269
/// guard.
///
/// gen1 pool `[A1, A2]`, flow on A2 (index 1).
/// Edit 1 adds A3: `[A1, A2, A3]` — A2 retained 1 -> 1. The carried record
/// must STILL be stamped 1 (pre-fix it was re-stamped 0).
/// Edit 2 removes A1: `[A2, A3]` — A2 retained 1 -> 0. The record must be
/// carried (pre-fix its stamped 0 is not in the map, so it is dropped:
/// `reseeded=0`), and a collider on the same public reverse identity must
/// be REFUSED (pre-fix it is admitted).
///
/// FAIL-ON-REVERT: reverting the reseed arm to `reserve_address_only`
/// without the index (or to the old 0-stamping signature) makes the gen2
/// stamp assertion fail with `Some(0)`.
#[test]
fn two_pool_edits_keep_address_only_guard_14622() {
    let flow = gre_flow("10.0.1.100", 0, "8.8.8.8");
    // A different subscriber whose GRE flow would claim the SAME public
    // reverse identity (proto, A2, 0, 8.8.8.8, 0) if the guard is gone.
    let collider = gre_flow("10.0.2.100", 0, "8.8.8.8");

    // gen1: [A1, A2]
    let gen1 = PortAllocator::new(2, 1024, 65535);
    mint_on_pool1(&gen1, flow);

    // Edit 1: [A1, A2] -> [A1, A2, A3]; retained map {0->0, 1->1, } (A3 new).
    let gen2 = PortAllocator::new(3, 1024, 65535);
    let mut map1 = rustc_hash::FxHashMap::default();
    map1.insert(0usize, 0usize);
    map1.insert(1usize, 1usize);
    let out1 = gen2.reseed_retained_from(&gen1, &map1, 1_000);
    assert_eq!(out1.reseeded, 1, "edit 1 must carry the address-only flow");
    assert_eq!(
        gen2.debug_live_flow_addr_index(&flow),
        Some(1),
        "gen2 record holds A2 at pool index 1 and must be stamped 1; \
         Some(0) means the reseed carry re-stamped 0 and the next edit \
         will drop the #5269 guard (#14622)"
    );
    assert_eq!(
        gen2.debug_address_only_owners().len(),
        1,
        "edit 1 must carry the reverse-identity token"
    );

    // Edit 2: [A1, A2, A3] -> [A2, A3]; retained map {1->0, 2->1}.
    let gen3 = PortAllocator::new(2, 1024, 65535);
    let mut map2 = rustc_hash::FxHashMap::default();
    map2.insert(1usize, 0usize);
    map2.insert(2usize, 1usize);
    let out2 = gen3.reseed_retained_from(&gen2, &map2, 2_000);
    assert_eq!(
        out2.reseeded, 1,
        "edit 2 must carry the flow whose address A2 is retained (now \
         index 0); reseeded=0 means the gen2 stamp lied and the carry \
         filter dropped a still-forwarding session's guard (#14622)"
    );
    assert_eq!(
        gen3.debug_live_flow_addr_index(&flow),
        Some(0),
        "gen3 record holds A2 at its new pool index 0"
    );
    assert_eq!(
        gen3.debug_address_only_owners().len(),
        1,
        "the #5269 token must survive both edits"
    );

    // The guard bites: a collider on the same public reverse identity is
    // refused as exhaustion, not admitted as a duplicate.
    let pool3 = [A2, A3];
    let admitted = gen3.reserve_address_only_roundrobin(
        collider,
        PoolAddressFamily::V4(&pool3),
        0,
        0,
        true, // sticky single-probe on A2: the exact identity in question
        NatHolder::Untracked,
    );
    // Single-probe sticky starts at address_index(collider.src) — not
    // guaranteed to be A2 — so assert via the direct token mint on A2
    // instead if the probe landed elsewhere.
    match admitted {
        Err(reason) => assert_eq!(
            reason,
            SourceNatFailureReason::AllocatorExhausted,
            "collider on the carried identity must fail closed"
        ),
        Ok(translated) => {
            assert_ne!(
                translated.ip,
                IpAddr::V4(A2),
                "collider must not receive the carried flow's address A2"
            );
            // Direct probe of the exact identity on A2 must refuse.
            let direct = gre_flow("10.0.3.100", 0, "8.8.8.8");
            assert!(
                gen3.reserve_address_only(direct, IpAddr::V4(A2), 0, NatHolder::Untracked)
                    .is_err(),
                "a second flow claiming (GRE, A2, 8.8.8.8) must be refused \
                 after two pool edits — the #5269 guard is gone (#14622)"
            );
        }
    }
}

/// CONTROL: a single reseed from a correctly stamped gen1, `[A1,A2] -> [A2]`,
/// carries the flow and refuses the collider. This passed before the fix
/// too (the stamped index happens to be consulted only once) — it pins
/// that the fix does not break the single-edit carry.
#[test]
fn single_pool_edit_control_keeps_guard_14622() {
    let flow = gre_flow("10.0.1.100", 0, "8.8.8.8");
    let gen1 = PortAllocator::new(2, 1024, 65535);
    mint_on_pool1(&gen1, flow);

    // [A1, A2] -> [A2]; retained map {1->0}.
    let gen2 = PortAllocator::new(1, 1024, 65535);
    let mut map = rustc_hash::FxHashMap::default();
    map.insert(1usize, 0usize);
    let out = gen2.reseed_retained_from(&gen1, &map, 1_000);
    assert_eq!(out.reseeded, 1, "single-edit control must carry the flow");
    assert_eq!(gen2.debug_live_flow_addr_index(&flow), Some(0));

    let collider = gre_flow("10.0.2.100", 0, "8.8.8.8");
    assert!(
        gen2.reserve_address_only(collider, IpAddr::V4(A2), 0, NatHolder::Untracked)
            .is_err(),
        "control: collider on the carried identity must be refused"
    );
}

/// The deterministic-CGNAT address-only mint must store `ip_idx`, not 0.
///
/// Fixture mirrors `deterministic_notrans_rule` in tests_pool.rs:
/// blocks_per_ip=126, so subscriber 100.64.1.0 (sub_idx 256) maps to
/// ip_idx 2 -> pool[2] = 203.0.113.3, while 100.64.0.5 maps to ip_idx 0.
///
/// FAIL-ON-REVERT: reverting the deterministic arm to the old
/// 0-stamping `reserve_address_only` call makes the stamp assertion fail
/// with `Some(0)`.
#[test]
fn deterministic_address_only_mint_stores_ip_idx_14622() {
    let host_base = u32::from(Ipv4Addr::new(100, 64, 0, 0));
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "cgnat-notrans-14622".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["100.64.0.0/22".to_string()],
        pool_name: "cgn-pool-14622".to_string(),
        pool_addresses: vec![
            "203.0.113.1/32".to_string(),
            "203.0.113.2/32".to_string(),
            "203.0.113.3/32".to_string(),
            "203.0.113.4/32".to_string(),
        ],
        port_low: 1024,
        port_high: 65535,
        pool_no_translation: true,
        deterministic_mode: 1,
        deterministic_block_size: 512,
        deterministic_blocks_per_ip: 126,
        deterministic_host_base: host_base,
        deterministic_host_count: 1024,
        ..SourceNATRuleSnapshot::default()
    }]);
    assert!(
        rules[0].deterministic_v4.is_some(),
        "fixture: mode-1 deterministic rule must build"
    );

    // Subscriber mapping to ip_idx 2 -> 203.0.113.3.
    let mut counter = None;
    let decision = expect_snat_decision(match_source_nat_result_for_tuple(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "100.64.1.0".parse().expect("src"),
        "8.8.8.8".parse().expect("dst"),
        Some(PROTO_TCP),
        12345,
        443,
        None,
        None,
        0,
        false,
        false,
        NatHolder::Untracked,
        &mut counter,
    ));
    assert_eq!(
        decision.rewrite_src,
        Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 3))),
        "fixture: subscriber must land on deterministic pool[2]"
    );
    assert_eq!(
        decision.rewrite_src_port, None,
        "no-translation preserves port"
    );

    let flow = tcp_flow("100.64.1.0", 12345, "8.8.8.8", 443);
    assert_eq!(
        rules[0].pool_allocator.debug_live_flow_addr_index(&flow),
        Some(2),
        "deterministic address-only mint must store ip_idx=2; Some(0) \
         means the mint discarded ip_idx and a later pool edit will \
         mis-filter this record (#14622)"
    );

    // Control at ip_idx 0: subscriber 100.64.0.5 -> pool[0], stamp 0.
    let mut counter0 = None;
    let d0 = expect_snat_decision(match_source_nat_result_for_tuple(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "100.64.0.5".parse().expect("src"),
        "8.8.8.8".parse().expect("dst"),
        Some(PROTO_TCP),
        12345,
        443,
        None,
        None,
        0,
        false,
        false,
        NatHolder::Untracked,
        &mut counter0,
    ));
    assert_eq!(
        d0.rewrite_src,
        Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
        "control fixture: subscriber must land on pool[0]"
    );
    let flow0 = tcp_flow("100.64.0.5", 12345, "8.8.8.8", 443);
    assert_eq!(
        rules[0].pool_allocator.debug_live_flow_addr_index(&flow0),
        Some(0),
        "control: pool[0] mint correctly stamps 0"
    );
}
