//! #19034: a full-snapshot refresh advances a neighbor shard's #3048/#5147
//! MAC epoch only when that neighbor's resolution changed.
//!
//! `refresh_runtime_snapshot_inner` moves the previous snapshot's manager
//! rows out of the dynamic map (the new snapshot's rows live in the static
//! table, which `lookup_neighbor_entry` reads first). It used
//! `bulk_replace_neighbors(&old_manager_keys, &[])`, which counts every
//! removal as a change, so every routes-only republish of an RG move
//! advanced the shard of every manager-owned neighbor although the new
//! snapshot named the same MAC. The cells drive the real refresh path
//! (`Coordinator::refresh_runtime_snapshot`) and Go's neighbor push
//! (`apply_manager_neighbors`), and read the shard epoch the flow cache
//! validates against (`mac_change_epoch_for`).
#![allow(unused_imports)]

use super::test_fixtures::*;
use super::tests_support::*;
use super::*;
use crate::NeighborSnapshot;

const GW_IFINDEX: i32 = 13;
const MAC_A: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
const MAC_B: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x66];

fn gw() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))
}

fn key() -> (i32, IpAddr) {
    (GW_IFINDEX, gw())
}

fn mac_str(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// A snapshot naming the gateway with `mac`, or no neighbor at all.
fn snap(mac: Option<[u8; 6]>, generation: u64) -> crate::ConfigSnapshot {
    crate::ConfigSnapshot {
        neighbors: mac
            .map(|mac| {
                vec![NeighborSnapshot {
                    interface: "ge-0-0-2".to_string(),
                    ifindex: GW_IFINDEX,
                    family: "inet".to_string(),
                    ip: gw().to_string(),
                    mac: mac_str(mac),
                    state: "reachable".to_string(),
                    ..Default::default()
                }]
            })
            .unwrap_or_default(),
        generation,
        fib_generation: 3,
        ..Default::default()
    }
}

/// The steady state before a move: a snapshot installed the gateway, and
/// Go's neighbor push made it a manager row in the dynamic map too.
fn coordinator_with_manager_gateway() -> Coordinator {
    let mut coordinator = Coordinator::new();
    coordinator
        .refresh_runtime_snapshot(&snap(Some(MAC_A), 1))
        .expect("first apply");
    assert!(
        coordinator.apply_manager_neighbors(true, 1, &[(GW_IFINDEX, gw(), NeighborEntry { mac: MAC_A })]),
        "premise: the neighbor push is accepted"
    );
    assert_eq!(
        coordinator.dynamic_neighbors_ref().get(&key()).map(|e| e.mac),
        Some(MAC_A),
        "premise: the gateway is a manager row in the dynamic map"
    );
    coordinator
}

fn epoch(coordinator: &Coordinator) -> u32 {
    coordinator.dynamic_neighbors_ref().mac_change_epoch_for(&key())
}

/// The defect cell. A routes-only republish names the same gateway MAC. The
/// manager row still leaves the dynamic map (the static table resolves it),
/// but the shard epoch must not move: every flow-cache entry resolved
/// through that shard is still correct. At cd9adfaca4 the refresh bumped it.
#[test]
fn refresh_naming_the_same_mac_keeps_the_neighbor_epoch_19034() {
    let mut coordinator = coordinator_with_manager_gateway();
    let before = epoch(&coordinator);

    coordinator
        .refresh_runtime_snapshot(&snap(Some(MAC_A), 2))
        .expect("routes-only republish");

    assert_eq!(
        epoch(&coordinator),
        before,
        "a refresh that leaves the neighbor's MAC unchanged must not advance its shard epoch"
    );
    assert_eq!(
        coordinator.static_neighbor_mac_for_test(GW_IFINDEX, gw()),
        Some(MAC_A),
        "the static table still resolves the gateway"
    );
    assert!(
        coordinator.dynamic_neighbors_ref().get(&key()).is_none(),
        "the previous snapshot's manager row still leaves the dynamic map, as before"
    );
}

/// Fail-closed control: the neighbor vanished from the new snapshot. Cached
/// flows hold a MAC nothing resolves any more, so the shard must advance.
#[test]
fn refresh_dropping_the_neighbor_advances_its_epoch_19034() {
    let mut coordinator = coordinator_with_manager_gateway();
    let before = epoch(&coordinator);

    coordinator
        .refresh_runtime_snapshot(&snap(None, 2))
        .expect("refresh without the gateway");

    assert_ne!(
        epoch(&coordinator),
        before,
        "a neighbor the refresh removes must advance its shard epoch"
    );
}

/// Fail-closed control for a genuine MAC change. The monitor saw the
/// gateway move to MAC_B (its own insert bumps the shard), and cached flows
/// seeded after that still resolved through the OLD static table (MAC_A,
/// static first). The refresh then installs MAC_B in the static table: the
/// resolution changes again and the shard must advance again. A comparison
/// against the removed dynamic row alone (MAC_B == MAC_B) would miss it.
#[test]
fn refresh_changing_the_resolved_mac_advances_its_epoch_19034() {
    let mut coordinator = coordinator_with_manager_gateway();
    assert!(
        coordinator
            .dynamic_neighbors_ref()
            .insert_if_changed(key(), NeighborEntry { mac: MAC_B }),
        "premise: the monitor's MAC replacement is installed"
    );
    assert_eq!(
        coordinator.static_neighbor_mac_for_test(GW_IFINDEX, gw()),
        Some(MAC_A),
        "premise: the static table still names the old MAC, and lookups read it first"
    );
    let before = epoch(&coordinator);

    coordinator
        .refresh_runtime_snapshot(&snap(Some(MAC_B), 2))
        .expect("refresh naming the new MAC");

    assert_eq!(
        coordinator.static_neighbor_mac_for_test(GW_IFINDEX, gw()),
        Some(MAC_B),
        "premise: the dynamic-confirmed new MAC replaces the static row"
    );
    assert_ne!(
        epoch(&coordinator),
        before,
        "a refresh that changes the resolved MAC must advance the shard epoch"
    );
}
