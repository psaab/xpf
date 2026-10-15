//! Per-batch replay of reverse packets waiting on PMech session ownership.

use std::collections::VecDeque;

use crate::afxdp::types::PendingPMechReversePacket;
use crate::session::{PMechSessionDirectory, PMechTokenProbe};

/// Move newly-live reverse packets to the replay queue, retain still-pending
/// packets, and recycle packets whose owner token has expired or changed.
///
/// The queue and recycle borrows are disjoint from the RX ring borrow held by
/// the caller; keeping this stage's state boundary explicit preserves that
/// split-borrow discipline.
#[inline(never)]
pub(super) fn drain_pending_pmech_replays(
    directory: &PMechSessionDirectory,
    pending_reverse: &mut VecDeque<PendingPMechReversePacket>,
    pending_replay: &mut VecDeque<PendingPMechReversePacket>,
    scratch_recycle: &mut Vec<u64>,
) {
    let scan_len = pending_reverse.len();
    for _ in 0..scan_len {
        let Some(held) = pending_reverse.pop_front() else {
            break;
        };
        match directory.probe_token(held.token) {
            PMechTokenProbe::Pending { owner_generation }
                if owner_generation == held.owner_generation =>
            {
                pending_reverse.push_back(held);
            }
            PMechTokenProbe::Live {
                owner_generation, ..
            } if owner_generation == held.owner_generation => {
                let _ = directory.remove_waiter(
                    held.token,
                    held.owner_generation,
                    held.waiter.arrival_worker_id,
                    held.waiter.defer_id,
                );
                pending_replay.push_back(held);
            }
            _ => {
                let _ = directory.remove_waiter(
                    held.token,
                    held.owner_generation,
                    held.waiter.arrival_worker_id,
                    held.waiter.defer_id,
                );
                scratch_recycle.push(held.desc.addr);
            }
        }
    }
}
