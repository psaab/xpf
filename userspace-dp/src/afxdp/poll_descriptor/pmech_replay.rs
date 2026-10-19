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

/// #15243 (A60-01): whether a reverse packet may be admitted to the hold
/// queue. Only packets whose `meta` still describes the frame referenced
/// by their descriptor may be held:
///
/// - a native packet (`is_injected == false`) with
///   `owned_frame.is_some()` was decapsulated at stage 6/6b (GRE/WG):
///   `meta` is the INNER packet's meta while `desc` still references the
///   OUTER UMEM frame. Replaying it would slice the outer frame at inner
///   offsets and re-run decap against inner bytes (`NotGre`/`NotWg`), so
///   the held packet could never be delivered. Refuse it (the caller
///   recycles the descriptor and counts `pmech_decap_hold_refused`).
/// - an injected packet's descriptor already holds its owned frame bytes
///   in a TX-pool frame, so it is always admissible.
#[inline]
pub(super) fn pmech_hold_admissible(is_injected: bool, owned_frame_is_some: bool) -> bool {
    is_injected || !owned_frame_is_some
}

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
