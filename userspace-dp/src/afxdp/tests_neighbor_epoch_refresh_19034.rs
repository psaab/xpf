//! #19034: a neighbor shard's #3048/#5147 MAC epoch advances exactly when a
//! write changes what the dataplane resolves for one of its keys (the static
//! table first, then the dynamic map: `lookup_neighbor_entry`).
//!
//! Two coordinator writers move the static table under live workers:
//! - `refresh_runtime_snapshot_inner` moves the previous snapshot's manager
//!   rows out of the dynamic map (the new snapshot's rows live in the static
//!   table). It used `bulk_replace_neighbors(&old_manager_keys, &[])`, which
//!   counts every removal of a present row as a change. So every routes-only
//!   republish of an RG move advanced the shard of every manager-owned
//!   neighbor although the new snapshot named the same MAC, and a key only
//!   the static table carried never advanced when the snapshot withdrew it.
//! - `apply_manager_neighbors` (Go's neighbor push) bumped only for dynamic
//!   row changes. A static-table MAC change or withdrawal behind a fresh or
//!   absent dynamic row moved nothing, and only the refresh's blanket bump
//!   later hid that.
//!
//! A dynamic row never leaves the map without a bump (Codex review of
//! 1f6c9fa7f1). A later learn of the key is a first insert, which does not
//! bump, and a later DELNEIGH finds nothing to remove; both rules assume the
//! removal already advanced the shard. So the refresh keeps the row of a
//! manager key it resolves the same way, and every removal it does make
//! bumps. Fabric links are a second resolution source: a cached
//! FabricRedirect takes its MACs from the link, so a link replacement bumps
//! the shard the flow stamped.
//!
//! The cells drive the real paths (`Coordinator::refresh_runtime_snapshot`,
//! `apply_manager_neighbors`) and read the shard epoch the flow cache
//! validates against (`mac_change_epoch_for` / `shard_mac_epoch`).
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
    assert_eq!(
        coordinator.dynamic_neighbors_ref().get(&key()).map(|entry| entry.mac),
        Some(MAC_A),
        "an unchanged manager row stays in the dynamic map, so a later learn or DELNEIGH finds it"
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

/// A key only the static table carried (the snapshot installed it and no
/// neighbor push or monitor learn put it in the dynamic map) is withdrawn by
/// the next snapshot. Flows cached through it hold a MAC nothing resolves any
/// more, so its shard must advance. At 93d699ce62 the refresh bumped only for
/// a dynamic row it removed, and this key had none.
#[test]
fn refresh_withdrawing_a_static_only_neighbor_advances_its_epoch_19034() {
    let mut coordinator = Coordinator::new();
    coordinator
        .refresh_runtime_snapshot(&snap(Some(MAC_A), 1))
        .expect("first apply");
    assert!(
        coordinator.dynamic_neighbors_ref().get(&key()).is_none(),
        "premise: only the static table carries the gateway"
    );
    let before = epoch(&coordinator);

    coordinator
        .refresh_runtime_snapshot(&snap(None, 2))
        .expect("refresh without the gateway");

    assert_eq!(
        coordinator.static_neighbor_mac_for_test(GW_IFINDEX, gw()),
        None,
        "premise: the gateway left the static table"
    );
    assert_ne!(
        epoch(&coordinator),
        before,
        "a static-only neighbor the refresh withdraws must advance its shard epoch"
    );
}

/// Codex scenario 2 (review of the withdrawn F1, ea1187b017), as a tunnel
/// cell. Two interfaces carry a neighbor with the same IP and the same MAC.
/// The GRE tunnel's outer next hop resolves on one of them. The refresh
/// withdraws that interface's neighbor and keeps the other one. A cached
/// tunnel flow keeps transmitting on the withdrawn interface (its outer
/// ifindex is part of the cached decision), so its entry must go stale. F1
/// re-resolved the outer interface while verifying and could accept the
/// surviving twin. F2 never re-resolves on the held path. A held pass only
/// asks `neighbor_mac_epoch_stale` about the shard the entry stamped, so the
/// cell checks that the refresh advances exactly that shard. The key is the
/// one the flow cache stamps for a tunnel: `outer_neighbor_ifindex(.., None,
/// ..)` with the resolution's next hop (`flow_cache.rs`, pinned by
/// `tunnel_flow_cache_keys_mac_change_shard_on_outer_neighbor_not_logical_ifindex`).
/// The held pass's PostHitNeighborMac drop on a stale shard is the next cell
/// (`held_pass_drops_after_a_genuine_mac_change_and_a_refresh_19034`).
#[test]
fn refresh_withdrawing_a_tunnel_outer_neighbor_advances_its_shard_19034() {
    tunnel_outer_withdrawal_19034(true);
}

/// Cell (e) with the outer neighbors only in the static table (no Go push
/// yet). The withdrawn key has no dynamic row to remove, so only the
/// refresh's resolution comparison can advance its shard. An ifindex-blind
/// comparison ("the same IP still resolves to the same MAC on the twin")
/// passes the rows variant above, because removing a present row bumps by
/// itself. It fails here.
#[test]
fn refresh_withdrawing_a_static_only_tunnel_outer_neighbor_advances_its_shard_19034() {
    tunnel_outer_withdrawal_19034(false);
}

fn tunnel_outer_withdrawal_19034(manager_rows: bool) {
    use crate::afxdp::sharded_neighbor::ShardedNeighborMap;
    let outer_nh: IpAddr = "2001:559:8585:80::1".parse().expect("outer next hop");
    let outer_mac = MAC_A;
    let withdrawn = (12, outer_nh);
    // A twin interface whose key hashes to a different shard, so an
    // ifindex-blind comparison cannot pass by bumping the twin's shard.
    let twin_ifindex = (13..256)
        .find(|ifindex| {
            ShardedNeighborMap::shard_index(&(*ifindex, outer_nh))
                != ShardedNeighborMap::shard_index(&withdrawn)
        })
        .expect("some ifindex hashes to another shard");
    let twin = (twin_ifindex, outer_nh);
    let mut both = native_gre_snapshot(true);
    assert_eq!(
        both.neighbors.len(),
        1,
        "premise: the GRE fixture names one outer neighbor"
    );
    both.neighbors[0].mac = mac_str(outer_mac);
    let mut twin_row = both.neighbors[0].clone();
    twin_row.interface = "ge-0-0-1".to_string();
    twin_row.ifindex = twin_ifindex;
    both.neighbors.push(twin_row);
    both.generation = 1;

    let mut coordinator = Coordinator::new();
    coordinator
        .refresh_runtime_snapshot(&both)
        .expect("first apply");
    if manager_rows {
        assert!(
            coordinator.apply_manager_neighbors(
                true,
                1,
                &[
                    (withdrawn.0, outer_nh, NeighborEntry { mac: outer_mac }),
                    (twin_ifindex, outer_nh, NeighborEntry { mac: outer_mac }),
                ],
            ),
            "premise: Go's push makes both outer neighbors manager rows"
        );
    } else {
        assert!(
            coordinator.dynamic_neighbors_ref().get(&withdrawn).is_none(),
            "premise: the withdrawn key has no dynamic row"
        );
    }
    let resolution = crate::afxdp::forwarding::resolve_tunnel_forwarding_resolution(
        &coordinator.forwarding,
        Some(coordinator.dynamic_neighbors_ref()),
        1,
        0,
    );
    assert_eq!(
        resolution.disposition,
        ForwardingDisposition::ForwardCandidate,
        "premise: the tunnel resolves"
    );
    let stamped = (
        crate::afxdp::forwarding::outer_neighbor_ifindex(&coordinator.forwarding, None, &resolution),
        resolution.next_hop.expect("premise: the tunnel resolution carries the outer next hop"),
    );
    assert_eq!(
        stamped, withdrawn,
        "premise: a tunnel flow stamps the outer interface's neighbor key"
    );
    let stamped_shard = ShardedNeighborMap::shard_index(&stamped);
    let stamped_before = coordinator.dynamic_neighbors_ref().shard_mac_epoch(stamped_shard);
    let twin_before = coordinator.dynamic_neighbors_ref().mac_change_epoch_for(&twin);

    let mut withdrawing = both.clone();
    withdrawing.neighbors.retain(|row| row.ifindex != withdrawn.0);
    withdrawing.generation = 2;
    coordinator
        .refresh_runtime_snapshot(&withdrawing)
        .expect("refresh withdrawing the outer neighbor");

    assert_eq!(
        coordinator.static_neighbor_mac_for_test(withdrawn.0, outer_nh),
        None,
        "premise: the outer interface's neighbor is gone"
    );
    assert_eq!(
        coordinator.static_neighbor_mac_for_test(twin_ifindex, outer_nh),
        Some(outer_mac),
        "premise: the twin still resolves the same IP to the same MAC"
    );
    assert_ne!(
        coordinator.dynamic_neighbors_ref().shard_mac_epoch(stamped_shard),
        stamped_before,
        "the tunnel flow's stamped shard must advance: its outer neighbor is gone, whatever another interface resolves"
    );
    assert_eq!(
        coordinator.dynamic_neighbors_ref().mac_change_epoch_for(&twin),
        twin_before,
        "the twin's resolution did not change, so its shard must not advance"
    );
}

/// Go's neighbor push changes the static MAC behind a fresh dynamic row. The
/// monitor learned MAC_B while the dynamic map held no row for the gateway
/// (the state right after any snapshot refresh). That insert does not bump,
/// correctly: lookups still read MAC_A from the static table. The push then
/// names MAC_B, which the fence accepts because the dynamic map confirms it,
/// so the static table, and the resolution, move A→B. No dynamic row
/// changes. At 93d699ce62 nothing bumped, and only the next refresh's blanket
/// bump evicted flows still sending to MAC_A.
#[test]
fn manager_push_changing_the_static_mac_advances_its_epoch_19034() {
    let mut coordinator = Coordinator::new();
    coordinator
        .refresh_runtime_snapshot(&snap(Some(MAC_A), 1))
        .expect("first apply");
    let before = epoch(&coordinator);
    assert!(
        coordinator
            .dynamic_neighbors_ref()
            .insert_if_changed(key(), NeighborEntry { mac: MAC_B }),
        "premise: the monitor installs MAC_B"
    );
    assert_eq!(
        epoch(&coordinator),
        before,
        "premise: a fresh dynamic row behind the static entry does not bump"
    );

    assert!(
        coordinator.apply_manager_neighbors(true, 1, &[(GW_IFINDEX, gw(), NeighborEntry { mac: MAC_B })]),
        "premise: the push is accepted"
    );

    assert_eq!(
        coordinator.static_neighbor_mac_for_test(GW_IFINDEX, gw()),
        Some(MAC_B),
        "premise: the dynamic-confirmed MAC replaces the static row"
    );
    assert_ne!(
        epoch(&coordinator),
        before,
        "a push that changes the resolved MAC must advance the shard epoch"
    );
}

/// Go's authoritative push withdraws a key only the static table carried
/// (the snapshot installed it, no dynamic row). The replace removes it from
/// the static table, so the key now resolves to nothing, and its shard must
/// advance. At 93d699ce62 the push bumped only for a dynamic row it removed.
#[test]
fn manager_push_withdrawing_a_static_only_neighbor_advances_its_epoch_19034() {
    let mut coordinator = Coordinator::new();
    coordinator
        .refresh_runtime_snapshot(&snap(Some(MAC_A), 1))
        .expect("first apply");
    assert!(
        coordinator.dynamic_neighbors_ref().get(&key()).is_none(),
        "premise: only the static table carries the gateway"
    );
    let before = epoch(&coordinator);
    let other = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 201));

    assert!(
        coordinator.apply_manager_neighbors(true, 1, &[(GW_IFINDEX, other, NeighborEntry { mac: MAC_B })]),
        "premise: the replace is accepted"
    );

    assert_eq!(
        coordinator.static_neighbor_mac_for_test(GW_IFINDEX, gw()),
        None,
        "premise: the replace withdrew the gateway from the static table"
    );
    assert_ne!(
        epoch(&coordinator),
        before,
        "a push that withdraws a resolved neighbor must advance its shard epoch"
    );
}

/// The push-path twin of the defect cell: Go re-pushes the MAC the snapshot
/// already installed. Nothing resolves differently, so the shard must keep its
/// epoch, with or without a dynamic row behind the static one.
#[test]
fn manager_push_naming_the_same_mac_keeps_the_neighbor_epoch_19034() {
    let mut coordinator = Coordinator::new();
    coordinator
        .refresh_runtime_snapshot(&snap(Some(MAC_A), 1))
        .expect("first apply");
    let before = epoch(&coordinator);

    assert!(
        coordinator.apply_manager_neighbors(true, 1, &[(GW_IFINDEX, gw(), NeighborEntry { mac: MAC_A })]),
        "premise: the push is accepted"
    );
    assert_eq!(epoch(&coordinator), before, "a fresh same-MAC manager row must not advance the shard epoch");

    assert!(
        coordinator.apply_manager_neighbors(true, 2, &[(GW_IFINDEX, gw(), NeighborEntry { mac: MAC_A })]),
        "premise: the re-push is accepted"
    );
    assert_eq!(epoch(&coordinator), before, "a same-MAC re-push must not advance the shard epoch");
}

/// Codex P1 (review of 1f6c9fa7f1), monitor arm. A same-MAC refresh leaves
/// the manager row where it was, so when the monitor later sees the gateway
/// move to MAC_B it REPLACES MAC_A and bumps. At 1f6c9fa7f1 the refresh
/// removed the row without a bump, the learn was then a first insert, and
/// nothing bumped. A retained view with no static row for the gateway
/// resolves it through the dynamic map, and its cached flows kept MAC_A.
#[test]
fn monitor_change_after_a_same_neighbor_refresh_advances_the_epoch_19034() {
    let mut coordinator = coordinator_with_manager_gateway();
    coordinator
        .refresh_runtime_snapshot(&snap(Some(MAC_A), 2))
        .expect("routes-only republish");
    let before = epoch(&coordinator);

    assert!(
        coordinator
            .dynamic_neighbors_ref()
            .insert_if_changed(key(), NeighborEntry { mac: MAC_B }),
        "premise: the monitor installs MAC_B"
    );

    assert_ne!(
        epoch(&coordinator),
        before,
        "the monitor's MAC change after a same-MAC refresh must advance the shard epoch"
    );
}

/// Codex P1, DELNEIGH arm: after a same-MAC refresh the kernel withdraws the
/// gateway. The monitor's removal must find the row and bump. At 1f6c9fa7f1
/// the refresh had already removed it without a bump, so the DELNEIGH
/// removed nothing and bumped nothing.
#[test]
fn delneigh_after_a_same_neighbor_refresh_advances_the_epoch_19034() {
    let mut coordinator = coordinator_with_manager_gateway();
    coordinator
        .refresh_runtime_snapshot(&snap(Some(MAC_A), 2))
        .expect("routes-only republish");
    let before = epoch(&coordinator);

    let _ = coordinator.dynamic_neighbors_ref().remove_if_present(&key());

    assert_ne!(
        epoch(&coordinator),
        before,
        "a DELNEIGH after a same-MAC refresh must advance the shard epoch"
    );
}

/// R7 NIT 1 (review of 1f6c9fa7f1): a key that enters the static table
/// without having been a manager key is judged too. The monitor learned
/// MAC_A for the gateway (a dynamic-only row). The next snapshot names it
/// NUD_PERMANENT with MAC_B, which the fence lets through, so the
/// resolution moves A→B. 1f6c9fa7f1 judged only old manager keys, and master
/// bumped only for removed rows. Neither bumped here.
#[test]
fn refresh_installing_a_permanent_mac_over_a_learned_one_advances_its_epoch_19034() {
    let mut coordinator = Coordinator::new();
    coordinator
        .refresh_runtime_snapshot(&snap(None, 1))
        .expect("first apply without the gateway");
    assert!(
        coordinator
            .dynamic_neighbors_ref()
            .insert_if_changed(key(), NeighborEntry { mac: MAC_A }),
        "premise: the monitor learns MAC_A"
    );
    let before = epoch(&coordinator);
    let mut permanent = snap(Some(MAC_B), 2);
    permanent.neighbors[0].state = "permanent".to_string();

    coordinator
        .refresh_runtime_snapshot(&permanent)
        .expect("refresh naming a permanent MAC_B");

    assert_eq!(
        coordinator.static_neighbor_mac_for_test(GW_IFINDEX, gw()),
        Some(MAC_B),
        "premise: the permanent row passes the fence"
    );
    assert_ne!(
        epoch(&coordinator),
        before,
        "a refresh that moves a learned resolution to a permanent MAC must advance the shard epoch"
    );
}

/// The `(egress_ifindex, next_hop)` key a cached FabricRedirect stamps, from
/// the coordinator's live fabric links and the flow cache's own expression
/// (`flow_cache.rs`: `outer_neighbor_ifindex(.., None, ..)`).
fn fabric_stamp(coordinator: &Coordinator) -> (i32, IpAddr) {
    let resolution = crate::afxdp::forwarding::resolve_fabric_redirect(&coordinator.forwarding)
        .expect("premise: the fabric redirect resolves");
    assert_eq!(
        resolution.disposition,
        ForwardingDisposition::FabricRedirect,
        "premise: a fabric redirect"
    );
    (
        crate::afxdp::forwarding::outer_neighbor_ifindex(&coordinator.forwarding, None, &resolution),
        resolution.next_hop.expect("premise: the redirect carries the peer address"),
    )
}

fn fabric_coordinator() -> (Coordinator, crate::ConfigSnapshot) {
    let snapshot = nat_snapshot_with_fabric();
    let mut coordinator = Coordinator::new();
    coordinator
        .refresh_runtime_snapshot(&snapshot)
        .expect("first apply with fab0");
    (coordinator, snapshot)
}

const FABRIC_PEER_MAC_B: &str = "00:aa:bb:cc:dd:ef";

/// Codex P1 (review of 1f6c9fa7f1), fabric arm. A cached FabricRedirect
/// takes its next-hop MAC from `FabricLink.peer_mac`, not from the neighbor
/// tables, and the seed's live-MAC check exempts it. A refresh that moves
/// the fabric peer MAC while the peer's neighbor row stays the same changes
/// what such a flow sends to. The neighbor comparison cannot see it, so the
/// fabric comparison must advance the shard the flow stamped.
#[test]
fn refresh_changing_the_fabric_peer_mac_advances_its_shard_19034() {
    let (mut coordinator, mut snapshot) = fabric_coordinator();
    let stamped = fabric_stamp(&coordinator);
    let before = coordinator.dynamic_neighbors_ref().mac_change_epoch_for(&stamped);
    let neighbor_before = coordinator.static_neighbor_mac_for_test(101, stamped.1);

    snapshot.fabrics[0].peer_mac = FABRIC_PEER_MAC_B.to_string();
    snapshot.generation += 1;
    coordinator
        .refresh_runtime_snapshot(&snapshot)
        .expect("refresh with a new fabric peer MAC");

    let resolution = crate::afxdp::forwarding::resolve_fabric_redirect(&coordinator.forwarding)
        .expect("premise: the fabric redirect still resolves");
    assert_eq!(
        resolution.neighbor_mac,
        Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xef]),
        "premise: the redirect now sends to the new peer MAC"
    );
    assert_eq!(
        coordinator.static_neighbor_mac_for_test(101, stamped.1),
        neighbor_before,
        "premise: the peer's neighbor row did not change"
    );
    assert_ne!(
        coordinator.dynamic_neighbors_ref().mac_change_epoch_for(&stamped),
        before,
        "a fabric peer MAC change must advance the shard a cached FabricRedirect stamped"
    );
}

/// The fabric arm's no-spurious-bump control: the routes-only republish of
/// an RG move carries the same fabric link, so FabricRedirect flows keep
/// their entries.
#[test]
fn refresh_keeping_the_fabric_link_keeps_its_shard_19034() {
    let (mut coordinator, mut snapshot) = fabric_coordinator();
    let stamped = fabric_stamp(&coordinator);
    let before = coordinator.dynamic_neighbors_ref().mac_change_epoch_for(&stamped);

    snapshot.generation += 1;
    coordinator
        .refresh_runtime_snapshot(&snapshot)
        .expect("routes-only republish");

    assert_eq!(
        coordinator.dynamic_neighbors_ref().mac_change_epoch_for(&stamped),
        before,
        "an unchanged fabric link must not advance the shard"
    );
}

/// A same-parent peer replacement supersedes the old link (#5686): flows
/// cached toward the old peer must go stale even though the new link is a
/// different key.
#[test]
fn refresh_replacing_the_fabric_peer_advances_the_old_peers_shard_19034() {
    let (mut coordinator, mut snapshot) = fabric_coordinator();
    let stamped = fabric_stamp(&coordinator);
    let before = coordinator.dynamic_neighbors_ref().mac_change_epoch_for(&stamped);

    snapshot.fabrics[0].peer_address = "10.99.13.3".to_string();
    snapshot.fabrics[0].peer_mac = FABRIC_PEER_MAC_B.to_string();
    snapshot.generation += 1;
    coordinator
        .refresh_runtime_snapshot(&snapshot)
        .expect("refresh replacing the fabric peer");

    assert_ne!(
        fabric_stamp(&coordinator),
        stamped,
        "premise: the redirect now targets the new peer"
    );
    assert_ne!(
        coordinator.dynamic_neighbors_ref().mac_change_epoch_for(&stamped),
        before,
        "the replaced peer's stamped shard must advance"
    );
}

/// `up` picks the link (#4082): a parent that loses carrier must not keep
/// serving cached FabricRedirect flows through it.
#[test]
fn refresh_marking_the_fabric_down_advances_its_shard_19034() {
    let (mut coordinator, mut snapshot) = fabric_coordinator();
    let stamped = fabric_stamp(&coordinator);
    let before = coordinator.dynamic_neighbors_ref().mac_change_epoch_for(&stamped);

    snapshot.fabrics[0].up = false;
    snapshot.generation += 1;
    coordinator
        .refresh_runtime_snapshot(&snapshot)
        .expect("refresh with fab0 down");

    assert!(
        coordinator.forwarding.fabrics.iter().all(|link| !link.up),
        "premise: the link is down"
    );
    assert_ne!(
        coordinator.dynamic_neighbors_ref().mac_change_epoch_for(&stamped),
        before,
        "a fabric whose parent went down must advance its stamped shard"
    );
}

/// The other fabric writer: Go's refreshFabricFwd (`refresh_fabric_links`)
/// re-resolves the peer MAC outside a snapshot. A changed MAC there must
/// invalidate the cached FabricRedirect flows too. Master never bumped
/// here.
#[test]
fn fabric_refresh_changing_the_peer_mac_advances_its_shard_19034() {
    let (mut coordinator, snapshot) = fabric_coordinator();
    let stamped = fabric_stamp(&coordinator);
    let before = coordinator.dynamic_neighbors_ref().mac_change_epoch_for(&stamped);
    let mut fabric = snapshot.fabrics[0].clone();
    fabric.peer_mac = FABRIC_PEER_MAC_B.to_string();

    coordinator.refresh_fabric_links(&[fabric]);

    assert_eq!(
        crate::afxdp::forwarding::resolve_fabric_redirect(&coordinator.forwarding)
            .and_then(|resolution| resolution.neighbor_mac),
        Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xef]),
        "premise: the refreshed link carries the new peer MAC"
    );
    assert_ne!(
        coordinator.dynamic_neighbors_ref().mac_change_epoch_for(&stamped),
        before,
        "a fabric refresh that changes the peer MAC must advance the stamped shard"
    );
}

/// A cached FabricRedirect also carries the link's local MAC as its source
/// MAC (`src_mac = local_mac`), so a parent whose MAC changes invalidates it
/// too.
#[test]
fn refresh_changing_the_fabric_local_mac_advances_its_shard_19034() {
    let (mut coordinator, mut snapshot) = fabric_coordinator();
    let stamped = fabric_stamp(&coordinator);
    let before = coordinator.dynamic_neighbors_ref().mac_change_epoch_for(&stamped);

    snapshot.fabrics[0].local_mac = "02:bf:72:ff:00:02".to_string();
    snapshot.generation += 1;
    coordinator
        .refresh_runtime_snapshot(&snapshot)
        .expect("refresh with a new fabric local MAC");

    assert_eq!(
        crate::afxdp::forwarding::resolve_fabric_redirect(&coordinator.forwarding)
            .and_then(|resolution| resolution.src_mac),
        Some([0x02, 0xbf, 0x72, 0xff, 0x00, 0x02]),
        "premise: the redirect now sends from the new local MAC"
    );
    assert_ne!(
        coordinator.dynamic_neighbors_ref().mac_change_epoch_for(&stamped),
        before,
        "a fabric local MAC change must advance the stamped shard"
    );
}

/// #19034 (R4 reviews of b5a55949e3 and 57dbf877ff): what the
/// `refresh_fabric_links` half of the straddle fix pins at this level. The
/// writer advances the shard that a FabricRedirect resolved through the OLD
/// links stamps (`(parent_ifindex, peer_addr)`). So any stamp taken before
/// the refresh is stale afterwards, including the tick snapshot a worker
/// took before loading the old view.
///
/// This cell does NOT run a seed. It computes the stamp itself, so it stays
/// green if the seed site stops stamping from the tick snapshot (arm T1).
/// The T1 guard for that shared stamp site, which FabricRedirect seeds use
/// too, is the end-to-end push cell
/// `seed_straddling_a_neighbor_push_cannot_keep_the_old_mac_19034`.
///
/// A pass-level FabricRedirect straddle was judged disproportionate. It
/// needs a session that resolves FabricRedirect (a peer-owned RG), seeded in
/// one pass and hit in a later one on the same binding and neighbor map.
/// The only pass-level FabricRedirect harness (`tests_split_rg_failback_18531`)
/// builds fresh bindings and its own neighbor map for every packet.
#[test]
fn fabric_refresh_bumps_the_shard_its_old_links_stamped_19034() {
    let (mut coordinator, snapshot) = fabric_coordinator();
    let dynamic = Arc::clone(coordinator.dynamic_neighbors_ref());
    // The worker's tick: the epoch snapshot first, then the view's links.
    let tick = dynamic.snapshot_shard_epochs();
    let v0_links = coordinator.forwarding.fabrics.clone();

    let mut fabric = snapshot.fabrics[0].clone();
    fabric.peer_mac = FABRIC_PEER_MAC_B.to_string();
    coordinator.refresh_fabric_links(&[fabric]);

    // Later in the tick, a FabricRedirect seed resolves through V0's links.
    let v0 = crate::afxdp::forwarding::resolve_fabric_redirect_from_list(&v0_links)
        .expect("premise: V0 redirects");
    assert_eq!(
        v0.neighbor_mac,
        Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
        "premise: the straddling seed resolves the old peer MAC"
    );
    let stamped = (
        crate::afxdp::forwarding::outer_neighbor_ifindex(&coordinator.forwarding, None, &v0),
        v0.next_hop.expect("premise: the redirect carries the peer address"),
    );
    assert_ne!(
        tick.epoch_for(&stamped),
        dynamic.mac_change_epoch_for(&stamped),
        "the seed's stamp (the tick's snapshot) must already be stale once the refresh bumped"
    );
}

const GW6_LL: &str = "fe80::1";

fn gw6() -> IpAddr {
    GW6_LL.parse().expect("link-local gateway")
}

fn key6() -> (i32, IpAddr) {
    (GW_IFINDEX, gw6())
}

/// R4 F2: a snapshot naming an IPv6 link-local gateway with `mac`. Keys are
/// `(ifindex, IpAddr)` for both families, so the link-local next hop is keyed
/// on its egress ifindex like any other.
fn snap6(mac: Option<[u8; 6]>, generation: u64) -> crate::ConfigSnapshot {
    let mut snapshot = snap(None, generation);
    if let Some(mac) = mac {
        snapshot.neighbors.push(NeighborSnapshot {
            interface: "ge-0-0-2".to_string(),
            ifindex: GW_IFINDEX,
            family: "inet6".to_string(),
            ip: GW6_LL.to_string(),
            mac: mac_str(mac),
            state: "reachable".to_string(),
            router: true,
            link_local: true,
            ..Default::default()
        });
    }
    snapshot
}

fn epoch6(coordinator: &Coordinator) -> u32 {
    coordinator.dynamic_neighbors_ref().mac_change_epoch_for(&key6())
}

/// The IPv6 link-local twin of the defect cell: a same-MAC republish keeps
/// the gateway's row and its shard epoch.
#[test]
fn refresh_naming_the_same_link_local_v6_mac_keeps_the_neighbor_epoch_19034() {
    let mut coordinator = Coordinator::new();
    coordinator
        .refresh_runtime_snapshot(&snap6(Some(MAC_A), 1))
        .expect("first apply");
    assert!(
        coordinator.apply_manager_neighbors(true, 1, &[(GW_IFINDEX, gw6(), NeighborEntry { mac: MAC_A })]),
        "premise: the neighbor push is accepted"
    );
    let before = epoch6(&coordinator);

    coordinator
        .refresh_runtime_snapshot(&snap6(Some(MAC_A), 2))
        .expect("routes-only republish");

    assert_eq!(epoch6(&coordinator), before, "a same-MAC v6 refresh must not advance the shard epoch");
    assert_eq!(
        coordinator.dynamic_neighbors_ref().get(&key6()).map(|entry| entry.mac),
        Some(MAC_A),
        "the unchanged v6 manager row stays"
    );
}

/// The IPv6 link-local twin of `refresh_changing_the_resolved_mac_advances_its_epoch_19034`.
#[test]
fn refresh_changing_a_link_local_v6_mac_advances_its_epoch_19034() {
    let mut coordinator = Coordinator::new();
    coordinator
        .refresh_runtime_snapshot(&snap6(Some(MAC_A), 1))
        .expect("first apply");
    assert!(
        coordinator.apply_manager_neighbors(true, 1, &[(GW_IFINDEX, gw6(), NeighborEntry { mac: MAC_A })]),
        "premise: the neighbor push is accepted"
    );
    assert!(
        coordinator
            .dynamic_neighbors_ref()
            .insert_if_changed(key6(), NeighborEntry { mac: MAC_B }),
        "premise: the monitor (NDP) installs MAC_B"
    );
    assert_eq!(
        coordinator.static_neighbor_mac_for_test(GW_IFINDEX, gw6()),
        Some(MAC_A),
        "premise: the static table still names the old MAC"
    );
    let before = epoch6(&coordinator);

    coordinator
        .refresh_runtime_snapshot(&snap6(Some(MAC_B), 2))
        .expect("refresh naming the new MAC");

    assert_eq!(
        coordinator.static_neighbor_mac_for_test(GW_IFINDEX, gw6()),
        Some(MAC_B),
        "premise: the dynamic-confirmed new MAC replaces the static row"
    );
    assert_ne!(epoch6(&coordinator), before, "a v6 refresh that changes the resolved MAC must advance the shard epoch");
}

/// The IPv6 link-local twin of `manager_push_changing_the_static_mac_advances_its_epoch_19034`.
#[test]
fn manager_push_changing_a_link_local_v6_static_mac_advances_its_epoch_19034() {
    let mut coordinator = Coordinator::new();
    coordinator
        .refresh_runtime_snapshot(&snap6(Some(MAC_A), 1))
        .expect("first apply");
    let before = epoch6(&coordinator);
    assert!(
        coordinator
            .dynamic_neighbors_ref()
            .insert_if_changed(key6(), NeighborEntry { mac: MAC_B }),
        "premise: the monitor (NDP) installs MAC_B"
    );
    assert_eq!(epoch6(&coordinator), before, "premise: a fresh dynamic row behind the static entry does not bump");

    assert!(
        coordinator.apply_manager_neighbors(true, 1, &[(GW_IFINDEX, gw6(), NeighborEntry { mac: MAC_B })]),
        "premise: the push is accepted"
    );

    assert_eq!(
        coordinator.static_neighbor_mac_for_test(GW_IFINDEX, gw6()),
        Some(MAC_B),
        "premise: the dynamic-confirmed MAC replaces the static row"
    );
    assert_ne!(epoch6(&coordinator), before, "a v6 push that changes the resolved MAC must advance the shard epoch");
}
