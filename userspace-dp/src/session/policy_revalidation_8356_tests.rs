// #8356: the ZONE-POLICY revalidation STAMP's lifecycle, at the session-table
// layer. The verdict half — which flows are revoked, and the reverse-companion
// trap — lives in `afxdp/tests_policy_revocation_8356.rs`, driven through the
// real poll body.
//
// Sibling of `filter_revalidation_7212_tests.rs`. The stamps are deliberately
// SEPARATE: sharing one would let a filter ACCEPT re-stamp suppress a pending
// policy re-derivation and vice versa, so the last cell here pins their
// independence directly.
#![allow(unused_imports)]

use super::*;
use std::net::{IpAddr, Ipv4Addr};

const IF_A: i32 = 24;

fn key(dst_port: u16) -> SessionKey {
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102));
    let dst = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: src,
        dst_ip: dst,
        src_port: 12345,
        dst_port,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

fn metadata() -> SessionMetadata {
    SessionMetadata {
        ingress_zone: crate::test_zone_ids::TEST_LAN_ZONE_ID,
        egress_zone: crate::test_zone_ids::TEST_WAN_ZONE_ID,
        ingress_ifindex: IF_A as u32,
        ingress_vlan_id: 0,
        owner_rg_id: 1,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
    }
}

fn decision() -> SessionDecision {
    SessionDecision {
        resolution: crate::afxdp::ForwardingResolution {
            disposition: crate::afxdp::ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: crate::nat::NatDecision::default(),
    }
}

fn table_with_one_session(live_gen: u64) -> (SessionTable, SessionKey) {
    let mut table = SessionTable::new();
    table.set_policy_revalidation_gen(live_gen);
    let k = key(443);
    assert!(table.install_with_protocol_with_origin(
        k.clone(),
        decision(),
        metadata(),
        SessionOrigin::ForwardFlow,
        122_000_000_000,
        PROTO_TCP,
        0,
    ));
    (table, k)
}

/// A freshly installed session is STALE for policy: `install` stamps `0`, which
/// is never a live generation. So the first packet it forwards re-derives.
///
/// This is also the peer-synced failover fence — `upsert_synced` takes the same
/// `0` — obtained from the import default rather than from cross-node plumbing.
#[test]
fn a_new_session_starts_unvalidated_for_policy_8356() {
    let (table, k) = table_with_one_session(41);
    assert_eq!(
        table.policy_revalidation_target(&k),
        PolicyRevalidationTarget::Stale(k.clone()),
        "install must stamp UNVALIDATED (0), so the first packet re-derives \
         zone policy against THIS node's state. A live stamp at install would \
         mean a peer-synced import never re-asks its own policy — the residual \
         #7323 accepted and #8356 closes"
    );
}

/// The steady state: re-stamped once, then FRESH for the rest of the
/// generation. This is what makes the feature once-per-session-per-commit
/// rather than per-packet.
#[test]
fn a_re_stamped_session_is_fresh_until_the_generation_moves_8356() {
    let (mut table, k) = table_with_one_session(41);
    table.mark_policy_revalidated(&k);
    assert_eq!(
        table.policy_revalidation_target(&k),
        PolicyRevalidationTarget::Fresh,
        "after a PERMIT re-derivation the entry must read fresh, or every \
         later packet of this generation re-walks the policy terms"
    );

    // The operator commits something — anything. `config_generation` is a
    // deliberate SUPERSET trigger: it advances on every commit, not only on
    // policy edits.
    table.set_policy_revalidation_gen(42);
    assert_eq!(
        table.policy_revalidation_target(&k),
        PolicyRevalidationTarget::Stale(k.clone()),
        "a generation bump must make the verdict stale again, or a commit that \
         narrows zone policy never reaches the sessions it denies"
    );
}

/// The stamp is keyed on the GENERATION ALONE, unlike the filter's, which is
/// keyed `(generation, logical ingress ifindex)`.
///
/// This cell used to justify that by saying the verdict's zones "both come from
/// the ENTRY — never from the interface a given packet arrived on". #9384 made
/// the from-zone come from the arrival interface and nothing re-checked the
/// sentence. By then it was false in the way that mattered: a packet from
/// ANOTHER zone reached the re-derivation, revoked the entry on a deny, and
/// re-stamped it fresh on a permit (#9519).
///
/// Generation-only is still right, for a reason that now holds by
/// construction. Only an OWNER reaches the re-derivation
/// (`afxdp/poll_descriptor/session_hit_authority.rs`), and an owner arrived IN
/// the entry's admitting zone (or over the fabric, which keeps the entry's
/// zone). Every packet that can read or write this stamp therefore judges from
/// the same from-zone within a generation, and an ifindex in the key would only
/// re-walk terms for a LAG member or an ECMP path in that zone. What varies with
/// the arrival interface is the authority check, not the stamp.
#[test]
fn the_policy_stamp_does_not_vary_with_the_arrival_interface_8356() {
    let (mut table, k) = table_with_one_session(41);
    table.mark_policy_revalidated(&k);
    // The FILTER stamp would read stale for a different ingress here. The
    // policy stamp must not.
    assert_eq!(
        table.policy_revalidation_target(&k),
        PolicyRevalidationTarget::Fresh,
        "the policy stamp must be generation-only"
    );
    assert!(
        table.filter_revalidation_stale(&k, IF_A + 1),
        "CONTROL: the FILTER stamp on the same entry IS interface-keyed and \
         reads stale for a different ingress. If this ever stops being true the \
         cell above is asserting a distinction that no longer exists"
    );
}

/// The two verdicts are INDEPENDENT. Re-stamping one must not silence the
/// other's re-derivation — which is the whole reason they are separate fields
/// rather than one shared stamp.
#[test]
fn the_policy_and_filter_stamps_do_not_suppress_each_other_8356() {
    let (mut table, k) = table_with_one_session(41);
    table.set_filter_revalidation_gen(41);

    table.mark_filter_revalidated(&k, IF_A);
    assert_eq!(
        table.policy_revalidation_target(&k),
        PolicyRevalidationTarget::Stale(k.clone()),
        "a FILTER accept re-stamp must NOT mark the policy verdict judged — a \
         shared stamp would let an accepted filter suppress the policy \
         re-derivation for the rest of the generation (#8356)"
    );

    table.mark_policy_revalidated(&k);
    assert!(
        !table.filter_revalidation_stale(&k, IF_A),
        "and the filter stamp keeps its own state"
    );

    let (mut table2, k2) = table_with_one_session(41);
    table2.set_filter_revalidation_gen(41);
    table2.mark_policy_revalidated(&k2);
    assert!(
        table2.filter_revalidation_stale(&k2, IF_A),
        "symmetrically, a POLICY re-stamp must not mark the FILTER verdict \
         judged"
    );
}

/// A key naming no entry is `NoLocalEntry`, not `Stale` — there is nothing to
/// stamp and nothing to tear down, and a teardown handed a tuple that names no
/// entry would delete nothing while the caller believed it had revoked.
#[test]
fn a_tuple_with_no_entry_is_not_reported_stale_8356() {
    let (table, _k) = table_with_one_session(41);
    assert_eq!(
        table.policy_revalidation_target(&key(8443)),
        PolicyRevalidationTarget::NoLocalEntry,
        "an absent entry must be NoLocalEntry — reporting it Stale would send \
         the caller into a revocation for a session it does not hold"
    );
}
