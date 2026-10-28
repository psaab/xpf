//! #17083: `refresh_for_ha_transition` resolves against the current
//! config/FIB pair, so the refreshed row must carry the live
//! forwarding-generation stamp. Before the fix it hand-copied
//! `update_session`'s in-place rewrite and missed that stamp, leaving
//! the entry stale so the next hit re-resolved it.

use crate::session::tests::{decision, key_v4, metadata};
use crate::session::{SessionOrigin, SessionTable};

#[test]
fn ha_transition_refresh_stamps_forwarding_generation_17083() {
    let mut table = SessionTable::new();
    let key = key_v4();
    table.set_forwarding_revalidation_gen(1, 1);
    assert!(table.install_with_protocol_with_origin(
        key.clone(),
        decision(),
        metadata(),
        SessionOrigin::SyncImport,
        1_000_000_000,
        key.protocol,
        0,
    ));

    // The HA scan re-resolves against the bumped config/FIB pair and
    // writes that decision through the transition refresh.
    table.set_forwarding_revalidation_gen(2, 1);
    assert!(table.refresh_for_ha_transition(&key, decision(), metadata(), 2_000_000_000));

    let (_, _, _, stamped) = table
        .entry_with_origin_and_forwarding_generation(&key)
        .expect("refreshed row present");
    assert!(
        !table.forwarding_resolution_is_stale(stamped),
        "HA transition refresh must stamp the live forwarding generation, got {stamped:?}"
    );
}
