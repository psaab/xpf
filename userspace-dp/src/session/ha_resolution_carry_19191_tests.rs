//! #19191: an HA import keeps the replaced row's resolution, forwarding stamp
//! and install epoch when it differs from the row ONLY by this node's own,
//! current HA judgment (`ha_resolution_carry_applies`), and in no other case.
//!
//! The row these cells build is the split-RG non-owner shape: the HA import
//! stored the raw local candidate (`upsert_synced_with_origin`), then the slow
//! path persisted the HA-derived redirect under the table's current
//! generation (`revalidate_forwarding_resolution`, the #12265 Owner-persist
//! write). The re-import states the handler's judgment
//! (`LocalHaRederivation`) the way `handle_upsert_synced` does.
use super::reimport_carry_19173_tests::{SEC, base, forwarding_input_changes};
use super::tests::key_v4;
use super::*;
use crate::afxdp::ForwardingDisposition;

const GENERATION: (u64, u32) = (7, 9);

/// The raw local candidate the import carries (the base row's resolution).
fn candidate(disposition: ForwardingDisposition) -> ForwardingResolution {
    let mut resolution = base(0).decision.resolution;
    resolution.disposition = disposition;
    resolution
}

/// The HA-derived redirect the slow path persisted: the fabric parent, the
/// peer's fabric MAC, the zone-encoded source MAC, no VLAN.
fn redirect() -> ForwardingResolution {
    ForwardingResolution {
        disposition: ForwardingDisposition::FabricRedirect,
        local_ifindex: 0,
        egress_ifindex: 4,
        tx_ifindex: 4,
        tunnel_endpoint_id: 0,
        next_hop: None,
        neighbor_mac: Some([0x10, 0x66, 0x6a, 0x3f, 0x67, 0x60]),
        src_mac: Some([0x02, 0xbf, 0x72, 0x16, 0x00, 0x01]),
        tx_vlan_id: 0,
        source_ifindex: 0,
        route_mtu: 0,
        transport_route_mtu: 0,
    }
}

/// The judgment `handle_upsert_synced` states for an import whose raw local
/// candidate is `from`: this node's HA state derives the redirect.
fn judgment(from: ForwardingResolution) -> LocalHaRederivation {
    LocalHaRederivation { from, to: redirect() }
}

/// Install the base import with `raw` as its resolution, then persist
/// `persisted` the way the slow path's Owner-persist does, under the table's
/// current generation.
fn persisted_row(table: &mut SessionTable, raw: ForwardingResolution, persisted: ForwardingResolution) {
    table.set_forwarding_revalidation_gen(GENERATION.0, GENERATION.1);
    let mut first = base(10 * SEC);
    first.decision.resolution = raw;
    assert!(table.upsert_synced_with_origin(first, false), "premise: the import installs");
    assert!(
        table.revalidate_forwarding_resolution(&key_v4(), persisted, None),
        "premise: the slow path persists"
    );
}

/// What one re-import left in the row.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    kept_epoch: bool,
    resolution: ForwardingResolution,
    stamp: ForwardingGenerationStamp,
}

fn reimport(
    table: &mut SessionTable,
    next: SessionInstall,
    next_leak: u64,
    judgment: Option<LocalHaRederivation>,
) -> Outcome {
    let key = next.key.clone();
    let before = table.entry_by_key_quiet(&key).expect("row").install_epoch;
    assert!(table.upsert_synced_import(next, false, next_leak, judgment), "the re-import installs");
    let row = table.entry_by_key_quiet(&key).expect("row");
    Outcome {
        kept_epoch: row.install_epoch == before,
        resolution: row.decision.resolution,
        stamp: row.forwarding_generation,
    }
}

/// The carry: five liveness re-imports of the raw candidate (a
/// `ForwardCandidate`, and a `MissingNeighbor` when the non-owner has not
/// resolved the WAN neighbor) each keep the persisted redirect, its validated
/// stamp, the install epoch and the slab slot, and mint nothing. MR2 (never
/// carry) reds the epoch; MR3 (keep the import's resolution while carrying
/// the epoch) reds the resolution and the stamp.
#[test]
fn ha_derived_difference_keeps_the_rows_resolution_stamp_and_epoch_19191() {
    for disposition in [ForwardingDisposition::ForwardCandidate, ForwardingDisposition::MissingNeighbor] {
        let mut table = SessionTable::new();
        let key = key_v4();
        persisted_row(&mut table, candidate(disposition), redirect());
        let persisted = table.entry_by_key_quiet(&key).expect("row");
        let (epoch, stamp) = (persisted.install_epoch, persisted.forwarding_generation);
        assert!(stamp.valid, "premise: the persist stamps a validated generation");
        let handle = *table.key_to_handle.get(&key).expect("handle");
        let counter = table.current_epoch();
        for n in 1..=5u64 {
            let mut next = base(10 * SEC + n * SEC);
            next.origin = SessionOrigin::SyncLiveness;
            next.decision.resolution = candidate(disposition);
            next.fwd_packets = 10 + n;
            assert_eq!(
                reimport(&mut table, next, 0, Some(judgment(candidate(disposition)))),
                Outcome { kept_epoch: true, resolution: redirect(), stamp },
                "{disposition:?} re-import {n}"
            );
            assert_eq!(
                table.entry_by_key_quiet(&key).expect("row").install_epoch,
                epoch,
                "{disposition:?} re-import {n}"
            );
            assert_eq!(*table.key_to_handle.get(&key).expect("handle"), handle, "slot {n}");
            assert_eq!(table.current_epoch(), counter, "{disposition:?} re-import {n} minted");
        }
    }
}

/// Every other shape mints a new epoch AND installs the import's own
/// decision unvalidated, exactly as without the carry. Each case names the
/// conjunct of `ha_resolution_carry_applies` (or the compare it hands to)
/// that refuses it:
/// - no judgment stated (the handler's active path, a reverse row, any other
///   caller): MR1 (carry any resolution difference) keeps the redirect;
/// - a judgment about another resolution than the import's;
/// - HA class: an import that is no pre-HA candidate, a judgment deriving no
///   redirect, a judgment deriving a local forward;
/// - a judged redirect that differs from the row's (another fabric egress,
///   another peer MAC): MR4 with a disposition-only compare keeps it;
/// - the row's stamp: never validated (an imported redirect), validated under
///   an older generation, or a table that never published one. These are the
///   shapes the five #19173 cells the option (A) prototype redded pin.
#[test]
fn every_other_resolution_difference_mints_and_installs_the_import_19191() {
    type Setup = fn(&mut SessionTable);
    type Edit = fn(&mut SessionInstall);
    type Judge = fn() -> Option<LocalHaRederivation>;
    let usual: Setup = |table| persisted_row(table, candidate(ForwardingDisposition::ForwardCandidate), redirect());
    let no_edit: Edit = |_| {};
    let stated: Judge = || Some(judgment(candidate(ForwardingDisposition::ForwardCandidate)));
    let cases: Vec<(&str, Setup, Edit, Judge)> = vec![
        ("no judgment stated", usual, no_edit, || None),
        ("a judgment about another resolution", usual, no_edit, || {
            let mut from = candidate(ForwardingDisposition::ForwardCandidate);
            from.egress_ifindex += 1;
            Some(judgment(from))
        }),
        (
            "the import is no pre-HA candidate",
            usual,
            |next| next.decision.resolution.disposition = ForwardingDisposition::LocalDelivery,
            || Some(judgment(candidate(ForwardingDisposition::LocalDelivery))),
        ),
        (
            "the judgment derives no redirect (HAInactive)",
            |table| {
                persisted_row(
                    table,
                    candidate(ForwardingDisposition::ForwardCandidate),
                    candidate(ForwardingDisposition::HAInactive),
                )
            },
            no_edit,
            || {
                Some(LocalHaRederivation {
                    from: candidate(ForwardingDisposition::ForwardCandidate),
                    to: candidate(ForwardingDisposition::HAInactive),
                })
            },
        ),
        (
            "the judgment derives a local forward",
            |table| {
                let mut other = candidate(ForwardingDisposition::ForwardCandidate);
                other.egress_ifindex = 14;
                persisted_row(table, candidate(ForwardingDisposition::ForwardCandidate), other)
            },
            no_edit,
            || {
                let mut other = candidate(ForwardingDisposition::ForwardCandidate);
                other.egress_ifindex = 14;
                Some(LocalHaRederivation {
                    from: candidate(ForwardingDisposition::ForwardCandidate),
                    to: other,
                })
            },
        ),
        ("the judged redirect names another fabric egress", usual, no_edit, || {
            let mut j = judgment(candidate(ForwardingDisposition::ForwardCandidate));
            j.to.egress_ifindex = 5;
            j.to.tx_ifindex = 5;
            Some(j)
        }),
        ("the judged redirect names another peer MAC", usual, no_edit, || {
            let mut j = judgment(candidate(ForwardingDisposition::ForwardCandidate));
            j.to.neighbor_mac = Some([0x10, 0x66, 0x6a, 0x3f, 0x67, 0x61]);
            Some(j)
        }),
        (
            "the row's stamp was never validated (an imported redirect)",
            |table| {
                table.set_forwarding_revalidation_gen(GENERATION.0, GENERATION.1);
                let mut first = base(10 * SEC);
                first.decision.resolution = redirect();
                assert!(table.upsert_synced_with_origin(first, false));
            },
            no_edit,
            stated,
        ),
        (
            "the row's stamp is from an older generation",
            |table| {
                persisted_row(table, candidate(ForwardingDisposition::ForwardCandidate), redirect());
                table.set_forwarding_revalidation_gen(GENERATION.0 + 1, GENERATION.1);
            },
            no_edit,
            stated,
        ),
        (
            "the table never published a generation",
            |table| {
                let mut first = base(10 * SEC);
                first.decision.resolution = candidate(ForwardingDisposition::ForwardCandidate);
                assert!(table.upsert_synced_with_origin(first, false));
                assert!(table.revalidate_forwarding_resolution(&key_v4(), redirect(), None));
            },
            no_edit,
            stated,
        ),
    ];
    let mut wrong = Vec::new();
    for (name, setup, edit, judge) in &cases {
        let mut table = SessionTable::new();
        setup(&mut table);
        let mut next = base(11 * SEC);
        next.origin = SessionOrigin::SyncLiveness;
        edit(&mut next);
        let imported = next.decision.resolution;
        let outcome = reimport(&mut table, next, 0, judge());
        let expected = Outcome {
            kept_epoch: false,
            resolution: imported,
            stamp: ForwardingGenerationStamp::default(),
        };
        if outcome != expected {
            wrong.push(format!("{name}: {outcome:?}"));
        }
    }
    assert!(wrong.is_empty(), "#19191: these must mint and install the import: {wrong:#?}");
    assert_eq!(cases.len(), 10, "anti-vacuity");
}

/// The carry never widens the identity rule: with the judgment stated, a
/// validated redirect in the row and a candidate import (so the resolution
/// conjuncts all hold), every non-resolution row of #19173's change table
/// (NAT, installing table, every metadata field, SNAT provenance, origin,
/// identity, TCP close class), a leak-stamp change and the adoption mark
/// still mint and install the import's own decision. MR4 (drop the NAT and
/// installing-table equality) reds the `decision.nat` and
/// `decision.install_table` rows.
#[test]
fn any_non_resolution_change_mints_under_the_carry_19191() {
    let fc = candidate(ForwardingDisposition::ForwardCandidate);
    let mut wrong = Vec::new();
    let mut checked = 0usize;
    let mut run = |name: &str, edit: &dyn Fn(&mut SessionInstall), mark: &dyn Fn(&mut SessionTable), next_leak: u64| {
        let mut table = SessionTable::new();
        persisted_row(&mut table, fc, redirect());
        mark(&mut table);
        let mut next = base(11 * SEC);
        next.origin = SessionOrigin::SyncLiveness;
        edit(&mut next);
        assert_eq!(next.decision.resolution, fc, "{name}: premise: the import is the candidate");
        let outcome = reimport(&mut table, next, next_leak, Some(judgment(fc)));
        checked += 1;
        if outcome != (Outcome { kept_epoch: false, resolution: fc, stamp: ForwardingGenerationStamp::default() }) {
            wrong.push(format!("{name}: {outcome:?}"));
        }
    };
    let rows: Vec<_> = forwarding_input_changes()
        .into_iter()
        .filter(|(name, _)| !name.starts_with("decision.resolution"))
        .collect();
    assert!(rows.iter().any(|(name, _)| *name == "decision.nat"), "premise: the NAT row");
    assert!(rows.iter().any(|(name, _)| *name == "decision.install_table"), "premise: the table row");
    for (name, change) in &rows {
        run(name, &|next| change(next), &|_| {}, 0);
    }
    run("leak incarnation gained", &|_| {}, &|_| {}, 6);
    run(
        "fabric_established (the #16217 adoption mark)",
        &|_| {},
        &|table| table.entry_by_key_mut(&key_v4()).expect("row").fabric_established = true,
        0,
    );
    assert!(wrong.is_empty(), "#19191: the carry kept these changed imports: {wrong:#?}");
    assert_eq!((rows.len(), checked), (25, 27), "anti-vacuity");
}
