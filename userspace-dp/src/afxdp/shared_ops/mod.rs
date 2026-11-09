use super::*;
use crate::session::ForwardingGenerationStamp;
use std::sync::atomic::AtomicU64;
/// Keep the #18662 `entry.key` directory paired with the forward-wire map.
/// Call only while holding that map's mutex, always before dropping it.
pub(super) fn update_stage_counts_entry_key_index(
    index: &Arc<Mutex<SharedEntryKeyIndex>>,
    map_key: &SessionKey,
    previous: Option<&SyncedSessionEntry>,
    next: Option<&SyncedSessionEntry>,
) {
    let mut index = lock_shared_recover(index);
    if let Some(previous) = previous
        && let Some(map_keys) = index.get_mut(&previous.key)
    {
        // Keep removed keys in their slots so a cursor resumed after another
        // publisher's update cannot skip a later alias.
        if let Some(slot) = map_keys.iter_mut().find(|slot| slot.map_key == *map_key) {
            slot.live = false;
        }
    }
    if let Some(next) = next {
        let map_keys = index.entry(next.key.clone()).or_default();
        if let Some(slot) = map_keys.iter_mut().find(|slot| slot.map_key == *map_key) {
            // Re-publishing/restamping the same map key revives its stable slot.
            slot.live = true;
        } else {
            map_keys.push(SharedEntryKeySlot {
                map_key: map_key.clone(),
                live: true,
            });
        }
    }
}

/// Drop a reserved bucket only after its canonical session is gone.
pub(super) fn prune_empty_stage_counts_entry_key_index(
    index: &Arc<Mutex<SharedEntryKeyIndex>>,
    entry_key: &SessionKey,
) {
    let mut index = lock_shared_recover(index);
    if index
        .get(entry_key)
        .is_some_and(|map_keys| map_keys.iter().all(|slot| !slot.live))
    {
        index.remove(entry_key);
    }
}

use std::sync::{MutexGuard, TryLockError};

/// #4800: calls to [`publish_shared_session`] — one per session published
/// into the cross-worker shared maps, i.e. one per new transit flow (plus
/// its reverse companion) and one per promote / HA import / tunnel install.
///
/// This is the DENOMINATOR for the publish leg of the new-flow-install
/// serialization question. On its own a publish rate says nothing; paired
/// with `SHARED_SESSION_PUBLISH_LOCK_CONTENDED` it says whether the publish
/// mutexes are where new flows queue up.
mod counters;
mod lookup;
mod owner_rg;
mod restamp;
mod reverse_synth;
mod store;
#[cfg(test)]
pub(crate) mod stage_counts_18655_tests;
#[cfg(test)]
mod restore_closer_19026_tests;
#[cfg(test)]
pub(crate) mod wire_lock_order_18658_tests;
pub(super) use counters::*;
pub(super) use lookup::*;
pub(super) use owner_rg::*;
pub(super) use restamp::*;
pub(super) use reverse_synth::*;
pub(super) use store::*;
#[cfg(test)]
pub(in crate::afxdp) use store::{nat_ambiguity_lock_stats, reset_nat_ambiguity_lock_stats};
