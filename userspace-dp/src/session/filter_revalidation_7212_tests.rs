// #7212: the per-entry static input-filter revalidation stamp
// (`SessionEntry::filter_revalidated_gen` + the `SessionTable` accessors).
//
// The stamp is what makes the revocation LAZY and per-tuple instead of a
// family-wide purge: a session whose verdict was already computed under the
// live config generation is not re-derived at all, and a session whose verdict
// predates it is re-derived exactly once. These cells pin the lifecycle; the
// verdict itself and the revocation are pinned in
// `afxdp/poll_descriptor/filter_revalidation_7212_tests.rs`.
//
// Loaded as a sibling submodule via `#[path]` from session/mod.rs.

use super::*;
use crate::test_zone_ids::*;
use std::net::Ipv4Addr;

fn key(src_port: u16) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 50)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        src_port,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

/// #7212: `ingress_ifindex` is `IF_A` for a FORWARD entry and `0` for a reverse
/// companion, matching production (#4983: the reverse half's ingress is
/// unobserved at install). Those are the two values a hypothetical
/// stamp-at-install would use, so the cells below assert staleness against
/// exactly them — a fixture that stamped one value and probed another would
/// report "stale" for the wrong reason and stay green against an install that
/// DOES stamp.
fn metadata(is_reverse: bool) -> SessionMetadata {
    SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        ingress_ifindex: if is_reverse { 0 } else { IF_A as u32 },
        ingress_vlan_id: 0,
        owner_rg_id: 1,
        fabric_ingress: false,
        is_reverse,
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
    SessionDecision { resolution: ForwardingResolution {
        disposition: crate::afxdp::ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 12,
        tx_ifindex: 12,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
        neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
        src_mac: None,
        tx_vlan_id: 0,
    }, nat: NatDecision::default(), install_table_domain: 0, install_table_check: 0 }
}

fn install(table: &mut SessionTable, k: &SessionKey, is_reverse: bool) {
    assert!(table.install_with_protocol_with_origin(
        k.clone(),
        decision(),
        metadata(is_reverse),
        SessionOrigin::ForwardFlow,
        1_000,
        PROTO_TCP,
        0,
    ));
}

/// The ingress interfaces the cells below stamp against. Two of them, because
/// the stamp names the interface as well as the generation and a single-value
/// fixture cannot show that.
const IF_A: i32 = 24;
const IF_B: i32 = 25;

/// An INSTALL leaves the entry unvalidated, so its next packet derives a
/// verdict; `mark_filter_revalidated` is the only thing that clears that.
///
/// The install used to stamp the live generation, on the reasoning that the
/// forward session's first packet had just been adjudicated by the session-MISS
/// path. That is true of the forward entry and FALSE of the reverse companion
/// this same constructor builds, whose ingress is explicitly unobserved at
/// install (#4983) — a live stamp there claims a filter judged a direction no
/// filter has seen. Uniformly unvalidated costs one side-effect-free term walk
/// per direction, on an interface that has an input filter at all.
#[test]
fn install_leaves_the_entry_unvalidated_7212() {
    let mut table = SessionTable::new();
    table.set_filter_revalidation_gen(41);
    let k = key(49152);
    install(&mut table, &k, false);

    // `IF_A` is the metadata's own `ingress_ifindex`, so this is the exact
    // (generation, ingress) pair an install that stamped LIVE would write. A
    // probe on any OTHER interface would be stale either way and would let such
    // an install through.
    assert!(
        table.filter_revalidation_stale(&k, IF_A),
        "a fresh FORWARD install carries no verdict, so its next packet must \
         derive one"
    );
    table.mark_filter_revalidated(&k, IF_A);
    assert!(!table.filter_revalidation_stale(&k, IF_A));

    // The REVERSE companion is the half that matters most: its ingress is
    // unobserved at install (`ingress_ifindex == 0`), so a live stamp there
    // would claim a filter judged a direction no filter has seen. Probe on `0`,
    // the value such a stamp would carry.
    let mut rev = key(49153);
    std::mem::swap(&mut rev.src_ip, &mut rev.dst_ip);
    std::mem::swap(&mut rev.src_port, &mut rev.dst_port);
    install(&mut table, &rev, true);
    assert!(
        table.filter_revalidation_stale(&rev, 0),
        "a fresh REVERSE install carries no verdict either — its ingress was \
         not observed, so nothing has judged it"
    );
}

/// A generation bump makes a revalidated session stale again. Without this the
/// stamp could be a one-shot "seen" bit and nothing would notice.
#[test]
fn a_generation_bump_makes_a_revalidated_session_stale_7212() {
    let mut table = SessionTable::new();
    table.set_filter_revalidation_gen(41);
    let k = key(49152);
    install(&mut table, &k, false);
    table.mark_filter_revalidated(&k, IF_A);
    assert!(!table.filter_revalidation_stale(&k, IF_A));

    table.set_filter_revalidation_gen(42);
    assert!(
        table.filter_revalidation_stale(&k, IF_A),
        "a config generation bump must make the stamped verdict stale"
    );
}

/// An INGRESS change makes it stale too, at a FIXED generation.
///
/// The verdict is a function of the interface as well as the snapshot: the
/// filter that judged the session on A says nothing about B's filter. A
/// generation-only stamp reports the session already judged when a
/// same-direction packet arrives on B — asymmetric routing, a redundancy-group
/// member change — and B's deny is skipped. The generation is deliberately held
/// FIXED here so the only thing that can move the answer is the interface.
#[test]
fn an_ingress_change_makes_a_revalidated_session_stale_7212() {
    let mut table = SessionTable::new();
    table.set_filter_revalidation_gen(41);
    let k = key(49152);
    install(&mut table, &k, false);
    table.mark_filter_revalidated(&k, IF_A);

    assert!(!table.filter_revalidation_stale(&k, IF_A));
    assert!(
        table.filter_revalidation_stale(&k, IF_B),
        "the same generation on a DIFFERENT ingress must be stale — that \
         interface's filter has not judged this session"
    );
}

/// `mark_filter_revalidated` clears the staleness, and clears it only for the
/// key it names. The second half is what keeps the revalidation per-tuple: a
/// re-stamp that touched more than its own entry would silently suppress the
/// revalidation of every other session on the interface.
#[test]
fn mark_filter_revalidated_clears_only_its_own_entry_7212() {
    let mut table = SessionTable::new();
    table.set_filter_revalidation_gen(2);
    let a = key(49152);
    let b = key(49153);
    install(&mut table, &a, false);
    install(&mut table, &b, false);

    table.mark_filter_revalidated(&a, IF_A);
    assert!(!table.filter_revalidation_stale(&a, IF_A));
    assert!(
        table.filter_revalidation_stale(&b, IF_A),
        "re-stamping one session must not re-stamp its neighbours"
    );
}

/// Forward and reverse are separate entries with separate stamps, which is what
/// gives each DIRECTION its own revalidation against the interface ITS packets
/// arrive on. A shared stamp would let the forward direction's re-derivation
/// suppress the reverse direction's — the reply would keep forwarding under a
/// filter that now denies it on the reply-side interface.
#[test]
fn forward_and_reverse_carry_independent_stamps_7212() {
    let mut table = SessionTable::new();
    table.set_filter_revalidation_gen(6);
    let fwd = key(49152);
    let mut rev = key(49152);
    std::mem::swap(&mut rev.src_ip, &mut rev.dst_ip);
    std::mem::swap(&mut rev.src_port, &mut rev.dst_port);
    install(&mut table, &fwd, false);
    install(&mut table, &rev, true);

    table.mark_filter_revalidated(&fwd, IF_A);
    assert!(!table.filter_revalidation_stale(&fwd, IF_A));
    assert!(
        table.filter_revalidation_stale(&rev, IF_B),
        "the reverse direction must revalidate on its own ingress interface"
    );
}

/// A peer-SYNCED import carries stamp `0`, which is never a live generation, so
/// the first packet the promoted session forwards revalidates against THIS
/// node's filter state. That is the #7212 failover fence: without it a standby
/// that imported a session before the commit would cold-serve, after a
/// promotion, a flow the primary had already revoked.
#[test]
fn peer_synced_import_is_always_stale_7212() {
    let mut table = SessionTable::new();
    table.set_filter_revalidation_gen(9);
    let k = key(49152);
    assert!(table.upsert_synced(
        k.clone(),
        decision(),
        metadata(false),
        1_000,
        PROTO_TCP,
        0,
        true,
    ));
    assert!(
        table.filter_revalidation_stale(&k, IF_A),
        "an imported session carries no locally-derived verdict, so it must \
         revalidate before this node forwards on it"
    );
    // Not vacuous against "everything is stale": marking it clears it, so the
    // predicate is reading the stamp rather than returning a constant.
    table.mark_filter_revalidated(&k, IF_A);
    assert!(!table.filter_revalidation_stale(&k, IF_A));
}

/// A key with no entry answers "not stale". The caller would otherwise be sent
/// into a re-derivation whose re-stamp has nowhere to land, and would re-derive
/// (and possibly re-emit a reject reply for) the same phantom on every packet.
#[test]
fn an_absent_key_is_not_stale_7212() {
    let mut table = SessionTable::new();
    table.set_filter_revalidation_gen(3);
    assert!(!table.filter_revalidation_stale(&key(49152), IF_A));
    // ...and re-stamping it is a no-op rather than a panic.
    table.mark_filter_revalidated(&key(49152), IF_A);
}

/// The generation `mark_filter_revalidated` writes is the one the worker
/// published, not a value the table invents. `set_filter_revalidation_gen` is
/// called once per poll pass with the SAME `ValidationState` the pass
/// classifies packets against; if the table drifted from it, a session could be
/// stamped with a generation its verdict was never derived under.
#[test]
fn the_published_generation_is_what_gets_stamped_7212() {
    let mut table = SessionTable::new();
    assert_eq!(table.filter_revalidation_gen(), 0);
    table.set_filter_revalidation_gen(77);
    assert_eq!(table.filter_revalidation_gen(), 77);
    let k = key(49152);
    install(&mut table, &k, false);
    table.mark_filter_revalidated(&k, IF_A);

    // Rewinding to the value the entry should carry proves it was stamped with
    // 77 specifically, not merely "some non-stale value".
    table.set_filter_revalidation_gen(78);
    assert!(table.filter_revalidation_stale(&k, IF_A));
    table.set_filter_revalidation_gen(77);
    assert!(!table.filter_revalidation_stale(&k, IF_A));
}

/// #8114 item 2 — THE CLASSIFICATION. The probe must give THREE answers, and
/// the two that used to collapse onto `None` need opposite handling.
///
/// `Fresh` and `NoLocalEntry` were indistinguishable to the caller before
/// #8114, because both were `Option::None`. That is the whole defect: the
/// caller's only production call site is an `if let Some(..)` with no `else`,
/// so a tuple that names no entry was treated exactly like one whose verdict
/// was already derived — and the packet forwarded under a filter that may deny
/// it.
///
/// Asserted as an EXACT match on each of the three, not `is_some()`/`is_none()`
/// over them: a boolean view is what allowed the collapse in the first place,
/// and re-asserting one here would leave the same hole open under a new name.
///
/// Fail-on-revert: make `filter_revalidation_target` return `Fresh` for an
/// absent key (master's `None`) and the `NoLocalEntry` arm reds.
#[test]
fn filter_revalidation_target_separates_no_entry_from_fresh_8114() {
    let mut table = SessionTable::new();
    table.set_filter_revalidation_gen(41);
    let k = key(49152);

    // (a) NO ENTRY. Nothing installed under this tuple at all.
    assert_eq!(
        table.filter_revalidation_target(&k, IF_A),
        FilterRevalidationTarget::NoLocalEntry,
        "a tuple that names no entry is NOT 'already judged' — reading it as \
         Fresh is the #8114 fail-open"
    );

    // (b) STALE. Installed, never revalidated, so a verdict is owed — and the
    // target carries the CANONICAL key the caller must tear down.
    install(&mut table, &k, false);
    assert_eq!(
        table.filter_revalidation_target(&k, IF_A),
        FilterRevalidationTarget::Stale(k.clone()),
        "a fresh install carries no verdict, so its next packet must derive one"
    );

    // (c) FRESH. Same entry, verdict derived under this (generation, ingress).
    table.mark_filter_revalidated(&k, IF_A);
    assert_eq!(
        table.filter_revalidation_target(&k, IF_A),
        FilterRevalidationTarget::Fresh,
        "an entry judged under the live pair must cost nothing further"
    );

    // (d) ...and freshness is per (generation, ingress): the SAME entry probed
    // on another interface is stale, not fresh. Without this, (c) would also
    // pass for a target that ignored the interface half of the stamp.
    assert_eq!(
        table.filter_revalidation_target(&k, IF_B),
        FilterRevalidationTarget::Stale(k.clone()),
        "no filter on IF_B has judged this entry"
    );
}
