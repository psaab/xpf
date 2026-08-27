// #4983 PRODUCER binding: end-to-end fail-on-revert coverage for the
// session ingress-interface STAMP, driven through the REAL
// `poll_binding_process_descriptor` control flow.
//
// The feature is a chain of three links and the other two were already
// pinned: `bpf_map_tests.rs` binds the MIRROR (build_conntrack_value_v4/v6
// copy `metadata.ingress_*` onto the on-map row) with a hand-set
// `SessionMetadata`, and `pkg/cli/session_filter_ingress_identity_4983_test.go`
// binds the CONSUMER with a hand-built `dataplane.SessionValue`. Neither can
// see the PRODUCER — the handful of lines inside the 5000-line poll body that
// are the only place a REAL packet's binding ever reaches `SessionMetadata`.
// Replacing those with `0` left the whole Rust suite green, and the
// observable effect would be silent: every session would carry
// `ingress_ifindex 0`, the Go filter would fall back to the zone for all of
// them, and `show/clear security flow session interface X` would revert to
// exact pre-#4983 behaviour with CI green and no counter or log to notice.
//
// The fixture puts the ingress on a VLAN unit of a TRUNK NIC whose PARENT
// carries a DIFFERENT zone, and whose SIBLING unit on that same parent is the
// egress. That is the project's own loss-cluster wiring (reth0.50 / reth0.80
// share the physical WAN NIC) and it is the case the two halves of the stamp
// have to separate: the ifindex alone names the parent — shared by both units
// — so only the {ifindex, VLAN} PAIR names the unit the flow arrived on.
//
// THREE production stamp sites reach this file, plus the deliberate zero on
// the fourth:
//   - the TRANSIT forward install (`poll_descriptor` ForwardFlow arm), covered
//     TWICE — once on the chassis-cluster fixture and once on a STANDALONE
//     (redundancy-group 0) one. The second arm is not redundancy: with only
//     the cluster fixture, gating the stamp on `owner_rg_id > 0` leaves every
//     test here green while silently dropping the identity on every
//     non-clustered firewall;
//   - the HOST-INBOUND install (`poll_descriptor` LocalMiss arm) — the flows
//     addressed to the firewall itself (management, BGP, syslog), driven on a
//     THIRD binding whose numbers are disjoint from the transit fixture's, so
//     no single constant satisfies both;
//   - the MISSING-NEIGHBOR seed (`build_missing_neighbor_session_metadata`);
//   - and the REVERSE companion, whose 0 is asserted as an over-reach guard.
//
// SCOPE, stated plainly because it is easy to over-read: these tests bind what
// the poll body STAMPS onto the installed session. They do not, and cannot,
// assert that a TRANSIT session's identity reaches the operator-visible BPF
// conntrack map — the transit install does not publish there at all (it calls
// `publish_live_session_entry`, which writes shim steering KEYS into a
// different map, plus `publish_shared_session`). Only the LocalMiss and
// missing-neighbor-seed installs call `publish_bpf_conntrack_entry`, and their
// tests below DO drive that call. The transit gap predates #4983 — it dates to
// `fab9230c5`, the commit that first added the conntrack mirror and wired only
// those sites — and is tracked as #6965. Read these tests as "the stamp is
// correct", not "the operator can see it for every session".
//
// Sibling `#[path]` test module loaded from afxdp/mod.rs, mirroring the #4840
// split; helpers come from afxdp/tests_support.rs.
#![allow(unused_imports)]

use super::test_fixtures::*;
use super::tests_support::*;
use super::*;
use crate::test_zone_ids::*;
use crate::{InterfaceAddressSnapshot, NeighborSnapshot, PolicyRuleSnapshot, ZoneSnapshot};

/// The ingress unit under test: `reth0.50`, VLAN 50 on the physical trunk
/// `ge-0-0-0` (parent ifindex 11), in zone `lan`. Its SIBLING unit on the
/// same parent is `nat_snapshot`'s `reth0.80` (VLAN 80, ifindex 12, zone
/// `wan`) — the egress of the flow driven below.
const INGRESS_PARENT_IFINDEX: i32 = 11;
const INGRESS_VLAN_ID: u16 = 50;
const INGRESS_LOGICAL_IFINDEX: i32 = 13;

/// `nat_snapshot()` (lan -> wan permit, interface-mode SNAT, default route via
/// a REACHABLE 172.16.80.1 gateway on reth0.80) plus a second LAN interface:
/// `reth0.50`, a VLAN unit riding the SAME physical parent as the WAN egress
/// unit reth0.80.
///
/// Two properties make this fixture bind rather than pass for free:
///   - zone `lan` now holds TWO interfaces (reth1.0 ifindex 24 and reth0.50),
///     so "the session's ingress zone" no longer identifies an interface —
///     which is the entire premise of #4983;
///   - the ingress parent ifindex 11 is SHARED with the egress unit and
///     resolves to `wan` on its own (reth0.80 is its first sub-interface), so
///     an implementation that stamped only the parent, or re-derived from the
///     zone, produces a visibly different answer.
fn ingress_identity_snapshot() -> crate::ConfigSnapshot {
    let mut snapshot = nat_snapshot();
    snapshot.interfaces.push(crate::InterfaceSnapshot {
        name: "reth0.50".to_string(),
        zone: "lan".to_string(),
        linux_name: "ge-0-0-0.50".to_string(),
        ifindex: INGRESS_LOGICAL_IFINDEX,
        parent_ifindex: INGRESS_PARENT_IFINDEX,
        vlan_id: INGRESS_VLAN_ID as i32,
        // RG 1, matching `nat_snapshot`'s reth0.80 — its SIBLING unit on this
        // same parent. It must match: RG is a BASE-interface property, and the
        // snapshot builder resolves it once per base and stamps that one value
        // onto every unit (`pkg/dataplane/userspace/interfaces.go:214-218`
        // resolves `rg`, `:302` writes it into each unit). Two units of one
        // parent with DIFFERENT RGs is therefore a shape production cannot
        // emit. An earlier revision used RG 2 here and justified it as "same
        // RG as the fixture's other LAN interface" — true of reth1.0, but
        // reth1.0 is a different base; the unit that constrains this one is
        // reth0.80 (#6928 review, Codex #9). Behaviour is unchanged either way:
        // ownership derives from the EGRESS resolution (reth0.80, RG 1) at
        // `forwarding/ha.rs`, not from the ingress unit's RG, and RG 1 is
        // forwarding-active in the shared `txn_ha_state()`.
        redundancy_group: 1,
        hardware_addr: "02:bf:72:00:50:08".to_string(),
        addresses: vec![InterfaceAddressSnapshot {
            family: "inet".to_string(),
            address: "10.0.62.1/24".to_string(),
            scope: 0,
        }],
        ..Default::default()
    });
    snapshot
}

/// Push ONE LAN -> WAN TCP SYN through the real poll body, ingressing on
/// `reth0.50` ({parent 11, VLAN 50}) and egressing on its sibling reth0.80
/// toward the reachable default gateway. Returns the session table the poll
/// installed into.
///
/// Asserts the fixture is live before returning: the ingress must resolve to
/// the LAN logical unit (not the parent's wan zone) and the poll must have
/// installed BOTH halves of the flow. Without those, a fixture that quietly
/// stopped admitting the flow would make every metadata assertion below
/// vacuous instead of RED.
fn run_ingress_identity_flow() -> SessionTable {
    run_ingress_identity_flow_on(&ingress_identity_snapshot(), &txn_ha_state())
}

/// `run_ingress_identity_flow` against a CALLER-SUPPLIED snapshot and HA
/// runtime state, so the same driven flow can be replayed on a topology that
/// differs in exactly one dimension (see the standalone arm at the bottom of
/// this file). The fixture-liveness assertions travel with the driver, so every
/// caller gets them.
///
/// The two travel TOGETHER on purpose: `enforce_ha_resolution_snapshot`
/// (forwarding/ha.rs) turns a resolution whose `owner_rg_id <= 0` into
/// `HAInactive` when `ha_state` is NON-empty — that combination means "a
/// cluster node whose snapshot predates the RETH RG propagation fix", and it
/// installs nothing. A genuine standalone box has neither, so a caller wanting
/// the RG-0 case must clear both or it gets an empty session table and a
/// vacuous test.
fn run_ingress_identity_flow_on(
    snapshot: &crate::ConfigSnapshot,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
) -> SessionTable {
    let forwarding = build_forwarding_state(snapshot);
    assert_eq!(
        crate::afxdp::forwarding::resolve_ingress_logical_ifindex(
            &forwarding,
            INGRESS_PARENT_IFINDEX,
            INGRESS_VLAN_ID
        ),
        Some(INGRESS_LOGICAL_IFINDEX),
        "fixture must map parent 11 / VLAN 50 -> the reth0.50 logical unit"
    );
    assert_eq!(
        forwarding
            .ifindex_to_zone_id
            .get(&INGRESS_LOGICAL_IFINDEX)
            .copied(),
        Some(TEST_LAN_ZONE_ID),
        "reth0.50 is in zone lan"
    );
    assert_eq!(
        forwarding
            .ifindex_to_zone_id
            .get(&INGRESS_PARENT_IFINDEX)
            .copied(),
        Some(TEST_WAN_ZONE_ID),
        "the SHARED physical parent resolves to wan on its own, so stamping \
         the parent's zone instead of the packet's binding is observable"
    );

    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 62, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        TCP_FLAG_SYN,
    );
    // The shim strips the 802.1Q tag and conveys the VID out of band in
    // `meta.ingress_vlan_id`, so the frame stays untagged and l3 is at 14 —
    // the same shape the #3021/#3022 VLAN pins use.
    let mut meta = txn_meta_v4(
        INGRESS_PARENT_IFINDEX as u32,
        TCP_FLAG_SYN,
        frame.len() as u16,
    );
    meta.ingress_vlan_id = INGRESS_VLAN_ID;

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, INGRESS_PARENT_IFINDEX, 0);
    binding.interface = Arc::<str>::from("ge-0-0-0");
    let mut sessions = SessionTable::new();
    txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        ha_state,
        &frame,
        meta,
    );

    assert_eq!(
        sessions.len(),
        2,
        "the permitted lan -> wan SYN must install the forward session and its \
         reverse companion; without both, the metadata assertions are vacuous"
    );
    sessions
}

/// Every session-table entry's metadata, split into (forward, reverse) by the
/// `is_reverse` flag. Reading through `iter_with_origin` avoids reconstructing
/// the SNAT-translated reverse key by hand — a hand-built key that missed
/// would silently return an EMPTY set and make an assertion pass for free.
fn split_forward_reverse(sessions: &SessionTable) -> (Vec<SessionMetadata>, Vec<SessionMetadata>) {
    let mut forward = Vec::new();
    let mut reverse = Vec::new();
    sessions.iter_with_origin(|_key, _decision, metadata, _origin| {
        if metadata.is_reverse {
            reverse.push(metadata.clone());
        } else {
            forward.push(metadata.clone());
        }
    });
    (forward, reverse)
}

/// #4983 PRODUCER fail-on-revert (transit forward install). The FORWARD
/// session the poll installs must carry the {ifindex, VLAN} of the binding
/// the SYN actually arrived on — parent 11, VLAN 50 — not 0, not the parent
/// alone, and not anything re-derived from a zone.
///
/// RED on reverting `poll_descriptor/mod.rs` transit install to
/// `ingress_ifindex: 0` / `ingress_vlan_id: 0`.
///
/// WHAT THIS DOES NOT ASSERT, and why there is no assertion to add: it stays
/// GREEN if you "omit the full conntrack publication" for this install,
/// because the transit install HAS no conntrack publication to omit (#6965).
/// It writes the shim steering table (`publish_live_session_entry`) and the
/// shared maps, never `publish_bpf_conntrack_entry`. An assertion that this
/// stamp reaches the operator-visible map would be asserting a call that does
/// not exist on this path — it would fail today and would be testing #6965's
/// fix, not #4983's. This test binds the STAMP; the mirror is #6965's to bind.
/// The sibling `..._without_an_rg_4983` covers the other scope hole (a stamp
/// conditioned on `owner_rg_id`), which IS real and IS closed here.
#[test]
fn poll_descriptor_transit_install_stamps_ingress_binding_4983() {
    let sessions = run_ingress_identity_flow();
    let (forward, _reverse) = split_forward_reverse(&sessions);
    assert_eq!(
        forward.len(),
        1,
        "exactly one forward session for the driven flow"
    );
    let metadata = &forward[0];
    assert_eq!(
        metadata.ingress_ifindex, INGRESS_PARENT_IFINDEX as u32,
        "the forward session must record the ifindex of the binding its first \
         packet arrived on (RED on revert: the transit install stamps 0 and the \
         Go filter falls back to the zone for every session)"
    );
    assert_eq!(
        metadata.ingress_vlan_id, INGRESS_VLAN_ID,
        "the forward session must record the ingress 802.1Q VID (RED on revert: \
         stamping 0 aliases reth0.50 onto its trunk-sibling reth0.80, which is \
         the cross-interface match #4983 removes)"
    );
    // The ingress ZONE is unchanged by this PR. Pinned here so a future change
    // that "fixed" the ifindex by rewriting the zone stamp is not mistaken for
    // this one.
    assert_eq!(
        metadata.ingress_zone, TEST_LAN_ZONE_ID,
        "the ingress zone still resolves from the LOGICAL unit (#3021)"
    );
}

/// #4983 OVER-REACH guard, forward/reverse arm separation. The REVERSE
/// companion installed by the SAME poll call must keep carrying NO ingress
/// identity: its own ingress has not been OBSERVED yet. The forward flow's
/// egress is resolved by then (`resolution.egress_ifindex`), so this is not an
/// availability problem — that value predicts where the reply will arrive
/// rather than recording where it did, and routing may be asymmetric, so
/// stamping it (or the forward frame's own ingress) would name a binding
/// nothing observed.
///
/// This is what makes the pair a distinguishing fixture rather than a
/// restatement: 11/50 on one entry and 0/0 on the other cannot both be
/// satisfied by any single constant. It stays GREEN under the revert that
/// turns the sibling test RED, and goes RED if the reverse install starts
/// copying `meta.ingress_*`.
#[test]
fn poll_descriptor_reverse_companion_carries_no_ingress_identity_4983() {
    let sessions = run_ingress_identity_flow();
    let (_forward, reverse) = split_forward_reverse(&sessions);
    assert_eq!(
        reverse.len(),
        1,
        "exactly one reverse companion for the driven flow"
    );
    let metadata = &reverse[0];
    assert_eq!(
        metadata.ingress_ifindex, 0,
        "the reverse companion must carry NO ingress ifindex — stamping the \
         forward frame's binding here would name the flow's client side as the \
         reverse entry's ingress"
    );
    assert_eq!(
        metadata.ingress_vlan_id, 0,
        "the reverse companion must carry NO ingress VLAN for the same reason"
    );
    // The reverse companion's zone pair IS inverted (that is pre-existing and
    // deliberate); pinning it here keeps "carries no identity" from being read
    // as "carries nothing".
    assert_eq!(
        metadata.ingress_zone, TEST_WAN_ZONE_ID,
        "the reverse companion's ingress zone is the forward flow's egress zone"
    );
}

/// The same LAN -> WAN flow, but with the gateway neighbor UNRESOLVED, so the
/// poll takes the missing-neighbor branch and installs a
/// `MissingNeighborSeed` forward session instead.
fn run_missing_neighbor_seed_flow() -> SessionTable {
    let mut snapshot = ingress_identity_snapshot();
    // Drop the reachable 172.16.80.1 entry: the default route's next hop no
    // longer resolves, which is the ordinary cold-start case (first packet of
    // a flow racing ARP/NDP on a busy LAN).
    snapshot.neighbors.clear();
    let forwarding = build_forwarding_state(&snapshot);

    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 62, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        TCP_FLAG_SYN,
    );
    let mut meta = txn_meta_v4(
        INGRESS_PARENT_IFINDEX as u32,
        TCP_FLAG_SYN,
        frame.len() as u16,
    );
    meta.ingress_vlan_id = INGRESS_VLAN_ID;

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, INGRESS_PARENT_IFINDEX, 0);
    binding.interface = Arc::<str>::from("ge-0-0-0");
    let ha_state = txn_ha_state();
    let mut sessions = SessionTable::new();
    txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    sessions
}

/// #4983 PRODUCER fail-on-revert (missing-neighbor seed install). A flow whose
/// FIRST packet arrives while the next-hop ARP/NDP is still unresolved installs
/// a seed session so the reply finds the forward NAT match. That seed is a
/// forward session with an ordinary lifetime — the pending-neighbor retry
/// sweep replays the buffered FRAME but never re-installs the SESSION (it
/// takes no `&mut SessionTable`), and the seed is published to the BPF
/// conntrack map at install. So whatever it is stamped with is what the flow
/// carries for its whole life.
///
/// RED on reverting `build_missing_neighbor_session_metadata`'s stamp to 0
/// while the two other FRAME-DRIVEN install sites stay stamped. ("Frame-driven",
/// not "policy-admitted": the transit install is policy-admitted, but the
/// LocalDelivery install also runs for a `JunosHostLocalPolicy::NoMatch`
/// host-bound flow that the zone's host-inbound set admits with no junos-host
/// policy matching at all — #6928 review.)
#[test]
fn poll_descriptor_missing_neighbor_seed_stamps_ingress_binding_4983() {
    let sessions = run_missing_neighbor_seed_flow();
    let mut seeds = Vec::new();
    sessions.iter_with_origin(|_key, _decision, metadata, origin| {
        if origin == SessionOrigin::MissingNeighborSeed {
            seeds.push(metadata.clone());
        }
    });
    assert_eq!(
        seeds.len(),
        1,
        "an unresolved next hop must install exactly one missing-neighbor seed \
         (if it installs none, this test proves nothing)"
    );
    let metadata = &seeds[0];
    assert!(
        !metadata.is_reverse,
        "the missing-neighbor seed is a FORWARD session"
    );
    assert_eq!(
        metadata.ingress_ifindex, INGRESS_PARENT_IFINDEX as u32,
        "the missing-neighbor seed must record the ingress binding of the frame \
         that created it (RED on revert: every flow whose first packet raced an \
         unresolved neighbor keeps the zone approximation for its whole life)"
    );
    assert_eq!(
        metadata.ingress_vlan_id, INGRESS_VLAN_ID,
        "the missing-neighbor seed must record the ingress 802.1Q VID too"
    );
}

/// The HOST-INBOUND ingress unit under test: `reth2.70`, VLAN 80 on the
/// physical trunk `ge-0-0-3` (parent ifindex 7), in zone `lan`, owning
/// 10.0.70.1. A TCP SYN addressed to that address resolves `LocalDelivery`
/// through `ingress_interface_local_resolution_on_session_miss` and installs a
/// `SessionOrigin::LocalMiss` session.
///
/// Every one of these three numbers is DISTINCT from every other number the
/// stamp could plausibly have been copied from, so the assertions below can
/// tell "stamped from the frame's binding" apart from "stamped from something
/// else that happened to be in scope":
///   - 7 is not 0 and not 1 (no zero/one default can satisfy it);
///   - 7 != 80, so a transposition of the ifindex and VLAN halves is RED;
///   - 7 != 17, so stamping the RESOLVED LOGICAL unit instead of the binding
///     the frame arrived on is RED;
///   - {7, 80} is neither of the transit fixture's {11, 50} (ingress) or
///     {11, 80} (egress sibling), so no single constant satisfies this test
///     and `poll_descriptor_transit_install_stamps_ingress_binding_4983`
///     at once;
///   - 7 is not `TEST_LAN_ZONE_ID` (1) or `TEST_WAN_ZONE_ID` (2), so a zone
///     re-derivation is RED.
const LOCAL_PARENT_IFINDEX: i32 = 7;
const LOCAL_VLAN_ID: u16 = 80;
const LOCAL_LOGICAL_IFINDEX: i32 = 17;

/// `ingress_identity_snapshot()` plus a THIRD LAN interface — `reth2.70`, a
/// VLAN unit on its own physical trunk (parent ifindex 7) — that owns a host
/// address of its own. Adding it to the same zone keeps the #4983 premise
/// intact (zone `lan` now holds THREE interfaces, so the ingress zone
/// identifies no single interface) while giving the host-inbound flow a
/// binding that is distinct from both transit units.
///
/// Note the VLAN id 80 is deliberately the SAME as the fixture's WAN egress
/// unit reth0.80 while the parent differs: the ingress map is keyed by the
/// `{parent ifindex, VLAN}` PAIR, so this proves the stamp records the pair
/// this frame arrived on and not "whichever unit carries VLAN 80".
fn local_miss_identity_snapshot() -> crate::ConfigSnapshot {
    let mut snapshot = ingress_identity_snapshot();
    snapshot.interfaces.push(crate::InterfaceSnapshot {
        name: "reth2.70".to_string(),
        zone: "lan".to_string(),
        linux_name: "ge-0-0-3.80".to_string(),
        ifindex: LOCAL_LOGICAL_IFINDEX,
        parent_ifindex: LOCAL_PARENT_IFINDEX,
        vlan_id: LOCAL_VLAN_ID as i32,
        // RG 2 is producible here BECAUSE this unit is the only one on its
        // parent (ifindex 7): with no sibling unit there is no base-RG conflict
        // to create. See the reth0.50 note above for why a differing RG on a
        // SHARED parent would not be. RG 2 is forwarding-active in the shared
        // `txn_ha_state()`, so the local node owns this ingress.
        redundancy_group: 2,
        hardware_addr: "02:bf:72:00:70:07".to_string(),
        addresses: vec![InterfaceAddressSnapshot {
            family: "inet".to_string(),
            address: "10.0.70.1/24".to_string(),
            scope: 0,
        }],
        ..Default::default()
    });
    snapshot
}

/// Push ONE TCP SYN addressed to the firewall's OWN 10.0.70.1 through the real
/// poll body, ingressing on `reth2.70` ({parent 7, VLAN 80}). The dst is that
/// unit's own primary address, so the session-miss resolution is
/// `LocalDelivery` and the poll takes the host-inbound install arm
/// (`install_helper_local_session_on_miss` -> `publish_bpf_conntrack_entry`).
/// Returns the session table the poll installed into.
///
/// Asserts the fixture is live before returning — the binding must resolve to
/// the LAN logical unit, the packet must actually take the LocalDelivery arm
/// (`dbg.local`), and exactly one session must be installed. Without those a
/// fixture that quietly stopped admitting the flow, or that started taking the
/// transit arm, would make the metadata assertion vacuous instead of RED.
fn run_local_miss_identity_flow() -> SessionTable {
    let forwarding = build_forwarding_state(&local_miss_identity_snapshot());
    assert_eq!(
        crate::afxdp::forwarding::resolve_ingress_logical_ifindex(
            &forwarding,
            LOCAL_PARENT_IFINDEX,
            LOCAL_VLAN_ID
        ),
        Some(LOCAL_LOGICAL_IFINDEX),
        "fixture must map parent 7 / VLAN 80 -> the reth2.70 logical unit"
    );
    assert_eq!(
        forwarding
            .ifindex_to_zone_id
            .get(&LOCAL_LOGICAL_IFINDEX)
            .copied(),
        Some(TEST_LAN_ZONE_ID),
        "reth2.70 is in zone lan"
    );
    assert_ne!(
        LOCAL_PARENT_IFINDEX, LOCAL_LOGICAL_IFINDEX,
        "the binding the frame arrives on must differ from the resolved \
         logical unit, or 'stamped the binding' and 'stamped the logical \
         unit' produce the same number and the assertion cannot separate them"
    );

    // Host-bound: dst is reth2.70's OWN address, so the miss-path resolution is
    // LocalDelivery. Port 179 matches the other host-inbound pins; the fixture
    // zone carries `host-inbound-traffic system-services any-service`, so
    // admission is not the thing under test here.
    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 70, 102),
        Ipv4Addr::new(10, 0, 70, 1),
        12345,
        179,
        TCP_FLAG_SYN,
    );
    // As in the transit flow: the shim strips the 802.1Q tag and conveys the
    // VID out of band in `meta.ingress_vlan_id`, so the frame stays untagged.
    let mut meta = txn_meta_v4(
        LOCAL_PARENT_IFINDEX as u32,
        TCP_FLAG_SYN,
        frame.len() as u16,
    );
    meta.ingress_vlan_id = LOCAL_VLAN_ID;

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, LOCAL_PARENT_IFINDEX, 0);
    binding.interface = Arc::<str>::from("ge-0-0-3");
    let ha_state = txn_ha_state();
    let mut sessions = SessionTable::new();
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert_eq!(
        dbg.local, 1,
        "the host-bound SYN must take the LocalDelivery arm; if it took a \
         transit arm instead this test would be re-pinning the already-bound \
         forward install"
    );
    assert_eq!(
        sessions.len(),
        1,
        "the admitted host-bound SYN must install exactly one host-local \
         session (no reverse companion on this path); without it the metadata \
         assertions below are vacuous"
    );
    sessions
}

/// #4983 PRODUCER fail-on-revert (HOST-INBOUND LocalMiss install). The
/// host-local session the poll installs must carry the {ifindex, VLAN} of the
/// binding the SYN actually arrived on — parent 7, VLAN 80.
///
/// This is the fourth and last session-metadata construction site that reaches
/// the conntrack map, and it was the only one no test drove: reverting its
/// stamp to 0 left the whole Rust suite green while the transit and
/// neighbor-seed reverts both went RED. A host-local session is exactly the
/// population an operator reaches for when a management/BGP/syslog flow to the
/// firewall itself misbehaves, and on a multi-interface zone the zone fallback
/// answers with every sibling.
///
/// RED on reverting `poll_descriptor/mod.rs`'s `local_metadata` to
/// `ingress_ifindex: 0` / `ingress_vlan_id: 0`.
#[test]
fn poll_descriptor_local_miss_install_stamps_ingress_binding_4983() {
    let sessions = run_local_miss_identity_flow();
    let mut host_local = Vec::new();
    sessions.iter_with_origin(|_key, _decision, metadata, origin| {
        if origin == SessionOrigin::LocalMiss {
            host_local.push(metadata.clone());
        }
    });
    assert_eq!(
        host_local.len(),
        1,
        "the host-bound SYN must install exactly one LocalMiss session (if it \
         installs none, this test proves nothing)"
    );
    let metadata = &host_local[0];
    assert!(
        !metadata.is_reverse,
        "the host-local install is a FORWARD session"
    );
    assert_eq!(
        metadata.ingress_ifindex, LOCAL_PARENT_IFINDEX as u32,
        "the host-local session must record the ifindex of the binding its \
         first packet arrived on (RED on revert: every firewall-bound session \
         stamps 0 and `show/clear security flow session interface <name>` \
         falls back to the zone, matching every sibling interface of a \
         multi-interface zone)"
    );
    assert_eq!(
        metadata.ingress_vlan_id, LOCAL_VLAN_ID,
        "the host-local session must record the ingress 802.1Q VID (RED on \
         revert: stamping 0 loses the unit half of the identity, so two units \
         of one trunk NIC alias onto the parent)"
    );
    // The ingress ZONE is unchanged by this PR. Pinned here so a future change
    // that "fixed" the ifindex by rewriting the zone stamp is not mistaken for
    // this one.
    assert_eq!(
        metadata.ingress_zone, TEST_LAN_ZONE_ID,
        "the host-local session's ingress zone still resolves from the LOGICAL \
         unit (#3021)"
    );
}

/// `ingress_identity_snapshot()` with every interface moved OUT of a redundancy
/// group — the STANDALONE (non-chassis-cluster) topology, which is the majority
/// deployment and the one where `owner_rg_for_resolution` returns 0. Driven
/// with an EMPTY `ha_state`, the other half of "this box is not clustered";
/// see `run_ingress_identity_flow_on` for why both are required.
fn standalone_ingress_identity_snapshot() -> crate::ConfigSnapshot {
    let mut snapshot = ingress_identity_snapshot();
    for iface in snapshot.interfaces.iter_mut() {
        iface.redundancy_group = 0;
    }
    snapshot
}

/// #4983 SCOPE guard for the transit stamp: the identity must be recorded
/// UNCONDITIONALLY, not only for sessions that happen to be owned by a
/// redundancy group.
///
/// `poll_descriptor_transit_install_stamps_ingress_binding_4983` cannot see
/// this on its own. Its fixture is a chassis-cluster topology, so the installed
/// session's `owner_rg_id` is non-zero, and a stamp rewritten as
/// `if owner_rg_id > 0 { meta.ingress_ifindex } else { 0 }` leaves it — and
/// every other test in this module — GREEN. That mutation is not hypothetical
/// book-keeping: it is exactly the shape a future HA-scoping change would take,
/// and it would silently drop the identity on every STANDALONE firewall while
/// CI stayed green.
///
/// This arm differs from the sibling in exactly one property (redundancy group
/// 0 instead of 1/2), and asserts that property as a precondition — without the
/// `owner_rg_id == 0` assertion the fixture could quietly acquire an RG and
/// become a duplicate of the sibling rather than a second data point.
///
/// RED on gating either half of the transit stamp on `owner_rg_id`.
#[test]
fn poll_descriptor_transit_install_stamps_ingress_binding_without_an_rg_4983() {
    let sessions =
        run_ingress_identity_flow_on(&standalone_ingress_identity_snapshot(), &BTreeMap::new());
    let (forward, _reverse) = split_forward_reverse(&sessions);
    assert_eq!(
        forward.len(),
        1,
        "exactly one forward session for the driven standalone flow"
    );
    let metadata = &forward[0];
    assert_eq!(
        metadata.owner_rg_id, 0,
        "PRECONDITION: this arm exists to cover the RG-less case, so the \
         installed session must actually carry owner_rg_id 0; if the fixture \
         acquires an RG this test silently becomes a copy of the sibling"
    );
    assert_eq!(
        metadata.ingress_ifindex, INGRESS_PARENT_IFINDEX as u32,
        "a standalone firewall's transit session must record its ingress \
         binding too (RED on gating the stamp behind owner_rg_id > 0, which \
         the chassis-cluster sibling cannot detect)"
    );
    assert_eq!(
        metadata.ingress_vlan_id, INGRESS_VLAN_ID,
        "the ingress 802.1Q VID is likewise unconditional"
    );
}
