//! Per-batch replay of reverse packets waiting on PMech session ownership.

use std::collections::VecDeque;

use crate::afxdp::types::PendingPMechReversePacket;
use crate::session::{PMechSessionDirectory, PMechTokenProbe};

/// Move newly-live reverse packets to the replay queue, retain still-pending
/// packets, and recycle packets whose owner token has expired or changed.
///
/// Descriptor origin is preserved on drop (#13636): an injected WireGuard
/// plaintext descriptor came from this binding's `free_tx_frames` pool, so
/// its addr goes to `tx_recycle`, never `scratch_recycle` (dropping it into
/// the RX list hands a TX address to the RX fill ring and strands the TX
/// frame — the #10597 contract). Native RX descriptors go to
/// `scratch_recycle` and return to the RX fill ring.
#[inline(never)]
pub(super) fn drain_pending_pmech_replays(
    directory: &PMechSessionDirectory,
    pending_reverse: &mut VecDeque<PendingPMechReversePacket>,
    pending_replay: &mut VecDeque<PendingPMechReversePacket>,
    scratch_recycle: &mut Vec<u64>,
    tx_recycle: &mut VecDeque<u64>,
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
                if held.is_injected {
                    tx_recycle.push_back(held.desc.addr);
                } else {
                    scratch_recycle.push(held.desc.addr);
                }
            }
        }
    }
}
