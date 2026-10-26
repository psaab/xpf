use super::*;

/// Acquire an independent inbound reference on the exact lease recorded by a
/// shared session. The translated tuple check prevents a stale source key from
/// being replayed onto a different lease, and the allocator/incarnation pair
/// prevents cross-pool release and same-key re-mint ABA.
pub(crate) fn acquire_recorded_persistent_inbound_hold(
    rules: &[SourceNatRule],
    hold: crate::nat::PersistentLeaseHold,
    expected_translated: TranslatedTuple,
    now_ns: u64,
) -> bool {
    if hold.incarnation == 0 {
        return false;
    }
    for rule in rules {
        if rule.pool_mode && rule.pool_allocator.debug_shared_identity() == hold.allocator_id {
            return rule.pool_allocator.acquire_persistent_inbound_for_hold(
                hold,
                expected_translated,
                now_ns,
            );
        }
    }
    false
}

/// Release only the recorded lease incarnation, and only through its exact
/// allocator. A missing allocator or stale incarnation is deliberately a no-op.
pub(crate) fn release_recorded_persistent_inbound_hold(
    rules: &[SourceNatRule],
    hold: crate::nat::PersistentLeaseHold,
    now_ns: u64,
) -> bool {
    if hold.incarnation == 0 {
        return false;
    }
    for rule in rules {
        if rule.pool_mode && rule.pool_allocator.debug_shared_identity() == hold.allocator_id {
            return rule
                .pool_allocator
                .release_persistent_inbound_for_hold(hold, now_ns);
        }
    }
    false
}
