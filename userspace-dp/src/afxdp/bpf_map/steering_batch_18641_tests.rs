// #18641: the batched multi-entry publish (`SteeringRowOwners::publish_entries`)
// must leave the registry exactly where sequential `publish_entry` calls would,
// write every row inside its shard lock, and never read a partial batch as done.

use super::steering_owners::*;
use crate::session::SessionKey;
use smallvec::SmallVec;
use std::cell::RefCell;
use std::io;

fn key(src_port: u16) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: 17,
        src_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 62, 102)),
        dst_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 16, 80, 210)),
        src_port,
        dst_port: 9,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

/// A distinct row per (entry, slot): bytes 0..2 carry the entry, byte 2 the slot.
fn row(entry: u16, slot: u8) -> SteeringRow {
    let mut r = [0u8; 40];
    r[0..2].copy_from_slice(&entry.to_le_bytes());
    r[2] = slot;
    r
}

type Entry = (SessionKey, SmallVec<[(SteeringRow, (SteeringRow, u8)); 4]>);

/// `n` entries with `per` rows each, action REDIRECT (1).
fn entries(n: u16, per: u8) -> Vec<Entry> {
    (0..n)
        .map(|e| {
            let rows = (0..per).map(|s| (row(e, s), (row(e, s), 1u8))).collect();
            (key(30000 + e), rows)
        })
        .collect()
}

/// Physical writes seen, as (row, action, shard-locked-at-write).
struct Seen {
    writes: RefCell<Vec<(SteeringRow, u8)>>,
}

fn publish_batched(
    owners: &SteeringRowOwners,
    holder: SteeringHolder,
    entries: &[Entry],
    batch: impl FnMut(&[(SteeringRow, u8)]) -> (usize, Option<io::Error>),
    single_fails_on: Option<SteeringRow>,
    seen: &Seen,
) -> Vec<Option<io::Error>> {
    let mut batch = batch;
    owners.publish_entries(
        holder,
        entries,
        |&(_, a)| a,
        |&(r, _), a| (r, a),
        |payloads| {
            let (applied, err) = batch(payloads);
            for p in &payloads[..applied.min(payloads.len())] {
                assert!(owners.shard_is_locked(&p.0), "a batched write ran outside its row's shard lock");
                seen.writes.borrow_mut().push(*p);
            }
            (applied, err)
        },
        |&(r, a)| {
            assert!(owners.shard_is_locked(&r), "a single write ran outside its row's shard lock");
            if Some(r) == single_fails_on {
                return Err(io::Error::from_raw_os_error(libc::E2BIG));
            }
            seen.writes.borrow_mut().push((r, a));
            Ok(())
        },
        |_| {},
        |_, _| {},
    )
}

fn seen() -> Seen {
    Seen { writes: RefCell::new(Vec::new()) }
}

/// Every row of every entry claimed by `holder`, with its recorded action.
fn assert_all_claimed(owners: &SteeringRowOwners, entries: &[Entry], holder: SteeringHolder) {
    for (owner, rows) in entries {
        assert_eq!(owners.held_rows_for(owner, holder).len(), rows.len(), "owner {owner:?} holds every row it published");
        for (r, (_, a)) in rows {
            assert_eq!(owners.owner_count(r), 1, "row claimed once");
            assert_eq!(owners.recorded_action(r), Some(*a));
        }
    }
}

#[test]
fn batched_publish_claims_what_sequential_publish_claims_18641() {
    let batched = SteeringRowOwners::default();
    let sequential = SteeringRowOwners::default();
    let set = entries(300, 3);
    let s = seen();
    let out = publish_batched(&batched, SteeringHolder::Coordinator, &set, |p| (p.len(), None), None, &s);
    assert!(out.iter().all(Option::is_none));
    for (owner, rows) in &set {
        let plain: Vec<(SteeringRow, u8)> = rows.iter().map(|(r, (_, a))| (*r, *a)).collect();
        sequential
            .publish_entry(owner, SteeringHolder::Coordinator, &plain, |a| *a, |_, a| a, |_| Ok(()), |_| {}, |_, _| {})
            .unwrap();
    }
    assert_all_claimed(&batched, &set, SteeringHolder::Coordinator);
    for (owner, rows) in &set {
        assert_eq!(
            batched.held_rows_for(owner, SteeringHolder::Coordinator).len(),
            sequential.held_rows_for(owner, SteeringHolder::Coordinator).len()
        );
        for (r, _) in rows {
            assert_eq!(batched.owner_count(r), sequential.owner_count(r));
            assert_eq!(batched.recorded_action(r), sequential.recorded_action(r));
        }
    }
    assert_eq!(s.writes.borrow().len(), 900, "each row written exactly once");
}

/// BPF_MAP_UPDATE_BATCH applies a prefix and stops. The remainder must be
/// retried, never counted as done.
#[test]
fn partial_batch_is_finished_one_row_at_a_time_18641() {
    let owners = SteeringRowOwners::default();
    let set = entries(200, 2);
    let s = seen();
    // Every batch call lands at most 3 rows and then reports an error.
    let out = publish_batched(
        &owners,
        SteeringHolder::Coordinator,
        &set,
        |p| (p.len().min(3), (p.len() > 3).then(|| io::Error::from_raw_os_error(libc::EAGAIN))),
        None,
        &s,
    );
    assert!(out.iter().all(Option::is_none), "every row landed, batched or single");
    assert_all_claimed(&owners, &set, SteeringHolder::Coordinator);
    let mut rows: Vec<SteeringRow> = s.writes.borrow().iter().map(|(r, _)| *r).collect();
    rows.sort_unstable();
    rows.dedup();
    assert_eq!(rows.len(), 400, "every row written");
}

/// A batch that reports success but applies nothing must not stall: the rows go
/// one at a time.
#[test]
fn batch_that_applies_nothing_falls_back_to_single_writes_18641() {
    let owners = SteeringRowOwners::default();
    let set = entries(50, 2);
    let s = seen();
    let out = publish_batched(&owners, SteeringHolder::Coordinator, &set, |_| (0, None), None, &s);
    assert!(out.iter().all(Option::is_none));
    assert_all_claimed(&owners, &set, SteeringHolder::Coordinator);
}

/// A row whose write fails fails its own entry and no other, and leaves that
/// row unclaimed.
#[test]
fn a_failed_row_fails_only_its_entry_18641() {
    let owners = SteeringRowOwners::default();
    let set = entries(20, 2);
    let bad = row(7, 1);
    let s = seen();
    // The batch refuses the bad row (applies the rows before it, then errors).
    let out = publish_batched(
        &owners,
        SteeringHolder::Coordinator,
        &set,
        |p| match p.iter().position(|(r, _)| *r == bad) {
            Some(i) => (i, Some(io::Error::from_raw_os_error(libc::E2BIG))),
            None => (p.len(), None),
        },
        Some(bad),
        &s,
    );
    for (i, o) in out.iter().enumerate() {
        assert_eq!(o.is_some(), i == 7, "entry {i}");
    }
    assert_eq!(owners.owner_count(&bad), 0, "a failed write records no claim");
    for (i, (owner, rows)) in set.iter().enumerate() {
        if i == 7 {
            continue;
        }
        assert_eq!(owners.held_rows_for(owner, SteeringHolder::Coordinator).len(), rows.len());
    }
}

/// Two owners aliasing one physical row with different actions: REDIRECT
/// wins the physical write, as with sequential publishes (#14650).
#[test]
fn aliased_row_coalesces_to_redirect_18641() {
    let owners = SteeringRowOwners::default();
    let shared = row(999, 0);
    let set: Vec<Entry> = vec![
        (key(1), SmallVec::from_vec(vec![(shared, (shared, 1u8))])),
        (key(2), SmallVec::from_vec(vec![(shared, (shared, 2u8))])),
    ];
    let s = seen();
    let out = publish_batched(&owners, SteeringHolder::Coordinator, &set, |p| (p.len(), None), None, &s);
    assert!(out.iter().all(Option::is_none));
    assert_eq!(owners.owner_count(&shared), 2);
    assert_eq!(owners.recorded_action(&shared), Some(1));
    assert!(
        s.writes.borrow().iter().all(|(r, a)| *r != shared || *a == 1),
        "the shared row was never physically written PASS: {:?}",
        s.writes.borrow()
    );
}

/// A row the holder held for an owner and the new publish does not name is
/// released, as `publish_entry` does.
#[test]
fn rows_the_new_publish_drops_are_released_18641() {
    let owners = SteeringRowOwners::default();
    let owner = key(5);
    let old = row(5, 9);
    owners
        .publish_entry(&owner, SteeringHolder::Coordinator, &[(old, 1u8)], |a| *a, |_, a| a, |_| Ok(()), |_| {}, |_, _| {})
        .unwrap();
    let set: Vec<Entry> = vec![(owner.clone(), SmallVec::from_vec(vec![(row(5, 0), (row(5, 0), 1u8))]))];
    let mut deleted = Vec::new();
    let out = owners.publish_entries(
        SteeringHolder::Coordinator,
        &set,
        |&(_, a)| a,
        |&(r, _), a| (r, a),
        |p| (p.len(), None),
        |_| Ok(()),
        |r| deleted.push(*r),
        |_, _| {},
    );
    assert!(out.iter().all(Option::is_none));
    assert_eq!(deleted, vec![old], "the row the new publish dropped is released");
    assert_eq!(owners.held_rows_for(&owner, SteeringHolder::Coordinator).len(), 1);
}
