//! #9560: the steering map's DELETE arm honours every owner of a shared row.
//!
//! `UserspaceSessionMapKey` is a bare 5-tuple, so sessions the authoritative
//! `SessionKey` keeps apart (routing domain, GRE discriminator) and a forward
//! entry's reverse companion publish the same 40-byte row. #9517 closed the
//! OVERWRITE arm; until #9560 any one owner's teardown deleted the row out from
//! under the others.
//!
//! These cells drive the real publish/delete primitives against
//! `RECORDER_ONLY_MAP_FD`, a test-only descriptor on which every write lands in
//! the `SESSION_MAP_WRITES` recorder and "succeeds". That is what lets an entry
//! publish reach every derived row: with the #9517 cells' `NOT_A_MAP_FD` the
//! first failed syscall stops it at row one. Each cell builds its own
//! `SteeringRowOwners`, because sharing one across calls is the thing under test.
use super::routing_domain_publish_9517_tests::host_bound_key;
use super::*;
use crate::afxdp::bpf_map::{
    RECORDER_ONLY_MAP_FD, SessionMapWriteRecord, SteeringRowOwners, clear_session_map_writes,
    session_map_row, session_map_writes,
};
use crate::session::TunnelDiscriminator;

fn steering(owners: &SteeringRowOwners) -> SteeringMap<'_> {
    SteeringMap {
        fd: RECORDER_ONLY_MAP_FD,
        owners,
    }
}

fn in_domain(routing_domain: u32) -> SessionKey {
    SessionKey {
        routing_domain,
        ..host_bound_key()
    }
}

fn gre_key(discriminator: TunnelDiscriminator) -> SessionKey {
    SessionKey {
        protocol: crate::ip_proto::PROTO_GRE,
        src_port: 0,
        dst_port: 0,
        discriminator,
        ..host_bound_key()
    }
}

/// The DELETEs issued against the 40-byte row `row_of` maps to, whichever full
/// `SessionKey` issued them.
fn deletes_of(writes: &[SessionMapWriteRecord], row_of: &SessionKey) -> usize {
    let row = session_map_row(row_of);
    writes
        .iter()
        .filter(|w| w.value.is_none() && session_map_row(&w.key) == row)
        .count()
}

/// C1.
#[test]
fn a_domain_alias_keeps_the_shared_row_until_its_last_owner_goes_9560() {
    let owners = SteeringRowOwners::default();
    let nat = NatDecision::default();
    let (domain_a, domain_b) = (in_domain(1), in_domain(2));
    let reverse = reverse_session_key(&domain_b, nat);
    assert_eq!(
        session_map_row(&domain_a),
        session_map_row(&domain_b),
        "control: two sessions differing only in routing_domain must alias to one \
         40-byte steering row, or this cell cannot observe a shared-row delete"
    );
    let _ = publish_live_session_entry(steering(&owners), &domain_a, nat, false);
    let _ = publish_live_session_entry(steering(&owners), &domain_b, nat, false);

    clear_session_map_writes();
    delete_live_session_entry(steering(&owners), &domain_a, nat, false);
    let first_teardown = session_map_writes();
    assert_eq!(
        deletes_of(&first_teardown, &domain_b) + deletes_of(&first_teardown, &reverse),
        0,
        "tearing down the domain-1 session deleted a steering row the domain-2 session \
         still owns. With an lo0 input filter the survivor's next packet misses the \
         steering map, reaches the kernel and skips the filter (#9560). \
         Writes: {first_teardown:?}"
    );

    clear_session_map_writes();
    delete_live_session_entry(steering(&owners), &domain_b, nat, false);
    let last_teardown = session_map_writes();
    assert!(
        deletes_of(&last_teardown, &domain_b) >= 1 && deletes_of(&last_teardown, &reverse) >= 1,
        "once the LAST owner is gone its forward and reverse rows must be deleted, or \
         every aliased pair leaks a REDIRECT row. Writes: {last_teardown:?}"
    );
}

/// C2. No routing domains are involved: two GRE tunnels between one endpoint pair
/// alias on a single-instance node.
#[test]
fn a_tunnel_discriminator_alias_keeps_the_shared_row_until_its_last_owner_goes_9560() {
    let nat = NatDecision::default();
    for (label, first, second) in [
        (
            "Keyed(1) against Keyed(2)",
            gre_key(TunnelDiscriminator::Keyed(1)),
            gre_key(TunnelDiscriminator::Keyed(2)),
        ),
        (
            "Unkeyed against Keyed(1)",
            gre_key(TunnelDiscriminator::Unkeyed),
            gre_key(TunnelDiscriminator::Keyed(1)),
        ),
    ] {
        let owners = SteeringRowOwners::default();
        let reverse = reverse_session_key(&second, nat);
        assert_eq!(
            session_map_row(&first),
            session_map_row(&second),
            "control ({label}): the steering key carries no discriminator, so these \
             two tunnels must share a row"
        );
        let _ = publish_live_session_entry(steering(&owners), &first, nat, false);
        let _ = publish_live_session_entry(steering(&owners), &second, nat, false);

        clear_session_map_writes();
        delete_live_session_entry(steering(&owners), &first, nat, false);
        let writes = session_map_writes();
        assert_eq!(
            deletes_of(&writes, &second) + deletes_of(&writes, &reverse),
            0,
            "({label}) one tunnel's teardown deleted the row the other tunnel still \
             owns (#9560). Writes: {writes:?}"
        );

        clear_session_map_writes();
        delete_live_session_entry(steering(&owners), &second, nat, false);
        let writes = session_map_writes();
        assert!(
            deletes_of(&writes, &second) >= 1 && deletes_of(&writes, &reverse) >= 1,
            "({label}) the last tunnel's teardown must delete the shared rows. \
             Writes: {writes:?}"
        );
    }
}

/// C3. The row's owner must be the ENTRY key: the reverse-canonical key is the
/// same `SessionKey` for both domains, so registering the row key would make the
/// two owners one.
#[test]
fn the_zeroed_reverse_canonical_row_outlives_one_of_its_two_domains_9560() {
    let owners = SteeringRowOwners::default();
    let nat = NatDecision::default();
    let (domain_a, domain_b) = (in_domain(1), in_domain(2));
    let canonical = reverse_canonical_key(&domain_a, nat);
    assert_eq!(
        canonical,
        reverse_canonical_key(&domain_b, nat),
        "#7160: the reverse-canonical key zeroes routing_domain, so both domains' \
         forward entries derive the IDENTICAL SessionKey for this row"
    );
    let _ = publish_live_session_entry(steering(&owners), &domain_a, nat, false);
    let _ = publish_live_session_entry(steering(&owners), &domain_b, nat, false);
    assert_eq!(
        owners.owner_count(&session_map_row(&canonical)),
        2,
        "both forward entries must own the shared reverse row. One owner means the \
         identical row key was registered instead of each entry's own key"
    );

    clear_session_map_writes();
    delete_live_session_entry(steering(&owners), &domain_a, nat, false);
    let writes = session_map_writes();
    assert_eq!(
        deletes_of(&writes, &canonical),
        0,
        "the domain-1 teardown deleted the reverse row the domain-2 forward entry \
         still owns, so domain 2's replies miss the steering map (#9560). \
         Writes: {writes:?}"
    );

    clear_session_map_writes();
    delete_live_session_entry(steering(&owners), &domain_b, nat, false);
    let writes = session_map_writes();
    assert!(
        deletes_of(&writes, &canonical) >= 1,
        "the last domain's teardown must delete the reverse row. Writes: {writes:?}"
    );
}

/// C4. A forward entry and its own reverse entry share the reverse row by design.
#[test]
fn a_reverse_half_torn_down_first_keeps_the_row_its_forward_half_still_owns_9560() {
    let owners = SteeringRowOwners::default();
    let nat = NatDecision::default();
    let forward = host_bound_key();
    let reverse = reverse_session_key(&forward, nat);
    let _ = publish_live_session_entry(steering(&owners), &forward, nat, false);
    let _ = publish_live_session_entry(steering(&owners), &reverse, nat, true);

    clear_session_map_writes();
    delete_live_session_entry(steering(&owners), &reverse, nat, true);
    let writes = session_map_writes();
    assert_eq!(
        deletes_of(&writes, &reverse),
        0,
        "the forward entry also publishes its reverse wire row. Tearing down only the \
         reverse half must leave that row while the forward session lives. \
         Writes: {writes:?}"
    );

    clear_session_map_writes();
    delete_live_session_entry(steering(&owners), &forward, nat, false);
    let writes = session_map_writes();
    assert!(
        deletes_of(&writes, &forward) >= 1 && deletes_of(&writes, &reverse) >= 1,
        "the forward teardown, now the last owner of both rows, must delete both. \
         Writes: {writes:?}"
    );
}

/// C5. No-leak control.
#[test]
fn an_unaliased_session_still_deletes_every_row_it_published_9560() {
    let owners = SteeringRowOwners::default();
    let nat = NatDecision::default();
    let forward = host_bound_key();
    clear_session_map_writes();
    let _ = publish_live_session_entry(steering(&owners), &forward, nat, false);
    let published: Vec<SessionKey> = session_map_writes()
        .into_iter()
        .filter(|w| w.value.is_some())
        .map(|w| w.key)
        .collect();
    assert!(
        published.len() >= 2,
        "control: a forward publish writes its own row and its reverse wire row. Fewer \
         means the entry publish stopped early and the loop below checks nothing. \
         Published: {published:?}"
    );

    clear_session_map_writes();
    delete_live_session_entry(steering(&owners), &forward, nat, false);
    let writes = session_map_writes();
    for key in &published {
        assert!(
            deletes_of(&writes, key) >= 1,
            "this session alone published the row for {key:?} and its teardown did not \
             delete it: a REDIRECT row leak. Writes: {writes:?}"
        );
        assert_eq!(
            owners.owner_count(&session_map_row(key)),
            0,
            "the torn-down session is still registered as an owner of {key:?}. That \
             stale owner would block the next legitimate delete of the row"
        );
    }
}

/// C6. `handle_delete_synced` with no local entry deletes the bare tuple.
#[test]
fn a_synced_delete_for_an_absent_session_honours_the_rows_other_owners_9560() {
    let nat = NatDecision::default();
    let (absent, sibling) = (in_domain(1), in_domain(2));
    let delete_synced = |owners: &SteeringRowOwners| {
        let mut sessions = SessionTable::new();
        let mut deleted_keys = Vec::new();
        clear_session_map_writes();
        super::commands::handle_delete_synced(
            &mut sessions,
            steering(owners),
            &ForwardingState::default(),
            &std::collections::BTreeMap::new(),
            absent.clone(),
            2_000_000,
            0,
            &mut deleted_keys,
            0,
        );
        session_map_writes()
    };

    let unowned = delete_synced(&SteeringRowOwners::default());
    assert_eq!(
        deletes_of(&unowned, &absent),
        1,
        "control: with no registered owner the no-entry arm must still delete the \
         tuple's row, as before #9560, or this cell never reached that arm. \
         Writes: {unowned:?}"
    );

    let owners = SteeringRowOwners::default();
    let _ = publish_live_session_entry(steering(&owners), &sibling, nat, false);
    let shared = delete_synced(&owners);
    assert_eq!(
        deletes_of(&shared, &absent),
        0,
        "a peer's delete for a session this node does not hold removed the row a \
         live session in another routing domain owns. The no-entry arm must go \
         through the owner registry too (#9560). Writes: {shared:?}"
    );
}

/// C7.
#[test]
fn a_row_the_registry_never_saw_is_still_deleted_9560() {
    let owners = SteeringRowOwners::default();
    let key = host_bound_key();
    clear_session_map_writes();
    delete_live_session_key(steering(&owners), &key, &key);
    let writes = session_map_writes();
    assert_eq!(
        deletes_of(&writes, &key),
        1,
        "a row no registered owner claims (a worker-local session that died with its \
         worker, or a write from before this registry existed) must be deleted as it \
         was before #9560. Skipping it leaks the row. Writes: {writes:?}"
    );
}

/// C8, registry lifetime.
#[test]
fn a_new_bpf_maps_starts_an_empty_owner_registry_9560() {
    let key = host_bound_key();
    let row = session_map_row(&key);
    let previous = crate::afxdp::coordinator::BpfMaps::default();
    previous.session_map_owners.add(&row, &in_domain(2));
    let next = crate::afxdp::coordinator::BpfMaps::default();
    assert!(
        !std::sync::Arc::ptr_eq(&previous.session_map_owners, &next.session_map_owners),
        "a new BpfMaps must not share the previous one's registry"
    );
    assert_eq!(
        next.session_map_owners.owner_count(&row),
        0,
        "a new BpfMaps (bringup, or stop) must start an empty registry. The sessions \
         that owned rows before it are gone, so their owners are stale"
    );
    clear_session_map_writes();
    delete_live_session_key(
        SteeringMap {
            fd: RECORDER_ONLY_MAP_FD,
            owners: &next.session_map_owners,
        },
        &key,
        &key,
    );
    let writes = session_map_writes();
    assert_eq!(
        deletes_of(&writes, &key),
        1,
        "a row owned only in the previous bringup's registry is Unregistered in the \
         new one and must be deleted, never blocked by a stale owner. \
         Writes: {writes:?}"
    );
}

/// C9. Ownership decided under the shard lock but acted on after releasing it lets
/// a sibling publish land between the decision and the delete.
#[test]
fn every_steering_write_and_delete_runs_under_the_row_owner_lock_9560() {
    let owners = SteeringRowOwners::default();
    let nat = NatDecision::default();
    let key = host_bound_key();
    clear_session_map_writes();
    let _ = publish_live_session_entry(steering(&owners), &key, nat, false);
    delete_live_session_entry(steering(&owners), &key, nat, false);
    let writes = session_map_writes();
    assert!(
        writes.iter().any(|w| w.value.is_some()) && writes.iter().any(|w| w.value.is_none()),
        "control: the cell must record at least one write and one delete. \
         Writes: {writes:?}"
    );
    assert!(
        writes.iter().all(|w| w.owner_lock_held),
        "a steering-map write or delete ran outside its row's owner-shard lock. A \
         teardown that decides under the lock and deletes after releasing it can \
         delete a row a sibling published in between (#9560). Writes: {writes:?}"
    );
}
