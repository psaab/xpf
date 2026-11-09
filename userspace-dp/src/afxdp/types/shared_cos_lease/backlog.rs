// #2158 (P2): interface-global exact-backlog visibility, extracted from
// shared_cos_lease/mod.rs as a pure code-motion split. The
// `SharedCoSExactBacklog` cluster (PaddedBacklogSlot and, until #19025
// replaced it with per-binding shares, the residual-surplus token bucket)
// is self-contained — it reaches no sibling-submodule item — so this move
// required NO visibility widening.

use std::sync::atomic::{AtomicU64, Ordering};

pub(in crate::afxdp) const EXACT_DEMAND_MASK_WORDS: usize = 4;

/// #9365: which exact guarantee queues on one CoS interface have demand, one
/// bit per index into `CoSInterfaceRuntime::queues`.
///
/// Queue ids are `u8` and the strict commit gate enforces a forwarding-class
/// <-> queue bijection, so a committed interface has at most 256 queues and
/// every one of them has its own bit (the const assertion below ties the width
/// to the id type). Before #9365 this was a `u64`, which cannot name index 64:
/// a serviceable queue there saturated the whole mask, and the consumers
/// counted every exact queue at index >= 64 whenever the mask was non-zero. A
/// 65-queue interface then reserved the rates of IDLE exact classes, and a pure
/// best-effort class, whose only service path is the surplus pass, lost all
/// service.
///
/// Past `BITS` — reachable only from a tolerated config that breaks the
/// bijection — there is one overflow policy, applied by `with_queue` and
/// `counts` alike: a demanding queue saturates the mask, and an untracked index
/// counts as demanding whenever the mask is non-empty. That over-reserves,
/// withholding best-effort surplus, rather than under-reserving and letting
/// best-effort take rate an exact guarantee is owed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) struct ExactDemandQueueMask([u64; EXACT_DEMAND_MASK_WORDS]);

const _: () = assert!(ExactDemandQueueMask::BITS > u8::MAX as usize);

impl ExactDemandQueueMask {
    pub(in crate::afxdp) const BITS: usize = EXACT_DEMAND_MASK_WORDS * u64::BITS as usize;
    pub(in crate::afxdp) const EMPTY: Self = Self([0; EXACT_DEMAND_MASK_WORDS]);
    pub(in crate::afxdp) const ALL: Self = Self([u64::MAX; EXACT_DEMAND_MASK_WORDS]);

    #[inline]
    pub(in crate::afxdp) fn with_queue(self, queue_idx: usize) -> Self {
        if queue_idx >= Self::BITS {
            return Self::ALL;
        }
        let mut words = self.0;
        words[queue_idx / u64::BITS as usize] |= 1u64 << (queue_idx % u64::BITS as usize);
        Self(words)
    }

    /// Clear one queue's bit. Past `BITS` there is no bit to clear: the
    /// overflow policy saturated the mask when that index was set.
    #[inline]
    pub(in crate::afxdp) fn without_queue(self, queue_idx: usize) -> Self {
        if queue_idx >= Self::BITS {
            return self;
        }
        let mut words = self.0;
        words[queue_idx / u64::BITS as usize] &= !(1u64 << (queue_idx % u64::BITS as usize));
        Self(words)
    }

    #[inline]
    pub(in crate::afxdp) fn counts(self, queue_idx: usize) -> bool {
        if queue_idx >= Self::BITS {
            return !self.is_empty();
        }
        self.0[queue_idx / u64::BITS as usize] & (1u64 << (queue_idx % u64::BITS as usize)) != 0
    }

    #[inline]
    pub(in crate::afxdp) fn is_empty(self) -> bool {
        self.0.iter().all(|word| *word == 0)
    }

    #[inline]
    fn from_words(words: [u64; EXACT_DEMAND_MASK_WORDS]) -> Self {
        Self(words)
    }
}

impl std::ops::BitOr for ExactDemandQueueMask {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        let mut words = self.0;
        for (word, other) in words.iter_mut().zip(rhs.0) {
            *word |= other;
        }
        Self(words)
    }
}

#[repr(align(64))]
struct PaddedBacklogSlot {
    queued_bytes: AtomicU64,
    /// #9365: one `AtomicU64` per `ExactDemandQueueMask` word. With the
    /// byte counter and the #19025 flag below the slot holds 48 bytes, inside
    /// the 64-byte alignment. (#18748 dropped the write-only
    /// `serviceable_bytes` counter: its only reader was a test.)
    demand_queue_mask: [AtomicU64; EXACT_DEMAND_MASK_WORDS],
    /// #19025: non-zero while this binding has a backlogged non-exact queue
    /// on the interface. The number of set slots is the `n` that divides the
    /// non-exact residual into per-binding shares.
    nonexact_backlogged: AtomicU64,
}

const _: () = assert!(std::mem::size_of::<PaddedBacklogSlot>() == 64);

/// Interface-global exact-backlog visibility for diagnostics and
/// cross-binding surplus suppression. Each binding owns one slot and publishes:
///   * queued exact bytes, used by diagnostics and `has_peer_backlog`; and
///   * the mask of exact queues that demand their reservation (#18748:
///     backlogged with their own tokens covering the head), used to reserve
///     each exact queue's aggregate guarantee rate once when bounding peer
///     residual surplus; and
///   * whether it has a backlogged non-exact queue (#19025), used to divide
///     that residual into equal per-binding shares.
///
/// The demand mask and the non-exact flag use release/acquire ordering so
/// transitions are visible across bindings without putting a locked
/// operation in the forwarding loop. The queued-byte diagnostic remains
/// relaxed.
///
/// #19025 removed the interface-wide residual token bucket that used to live
/// here. Every binding's non-exact surplus drew from it first-come, so the
/// binding whose worker also served an exact class polled less often and
/// lost the race (a colocated instance at 0.25 Gb/s while its peers took
/// 5.7). Each binding now meters its surplus with its own bucket at
/// `residual / n` (`queue_service::nonexact_surplus_budget_under_exact_demand`).
pub(in crate::afxdp) struct SharedCoSExactBacklog {
    worker_bytes: Box<[PaddedBacklogSlot]>,
}

impl SharedCoSExactBacklog {
    pub(in crate::afxdp) fn new(max_binding_slot: usize) -> Self {
        Self {
            worker_bytes: (0..=max_binding_slot)
                .map(|_| PaddedBacklogSlot {
                    queued_bytes: AtomicU64::new(0),
                    demand_queue_mask: std::array::from_fn(|_| AtomicU64::new(0)),
                    nonexact_backlogged: AtomicU64::new(0),
                })
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        }
    }

    pub(in crate::afxdp) fn matches_config(&self, max_binding_slot: usize) -> bool {
        self.worker_bytes.len() == max_binding_slot.saturating_add(1)
    }

    #[inline]
    pub(in crate::afxdp) fn publish(&self, binding_slot: u32, bytes: u64) {
        self.publish_demand(
            binding_slot,
            bytes,
            if bytes > 0 {
                ExactDemandQueueMask::ALL
            } else {
                ExactDemandQueueMask::EMPTY
            },
        );
    }

    #[inline]
    pub(in crate::afxdp) fn publish_demand(
        &self,
        binding_slot: u32,
        queued_bytes: u64,
        demand_queue_mask: ExactDemandQueueMask,
    ) {
        if let Some(slot) = self.worker_bytes.get(binding_slot as usize) {
            slot.queued_bytes.store(queued_bytes, Ordering::Relaxed);
            // #9365: the words are stored one at a time, so a reader racing
            // this publish can combine words from two publishes. Each word is
            // one a worker really published, so the result can only add or
            // drop a queue for the one scheduling pass before the next publish.
            for (word, value) in slot.demand_queue_mask.iter().zip(demand_queue_mask.0) {
                word.store(value, Ordering::Release);
            }
        }
    }

    /// The demand mask this binding last published (#18748): lets a drain
    /// republish only when its demand actually changed.
    #[inline]
    pub(in crate::afxdp) fn published_demand_queue_mask(
        &self,
        binding_slot: u32,
    ) -> ExactDemandQueueMask {
        self.worker_bytes
            .get(binding_slot as usize)
            .map(|slot| {
                ExactDemandQueueMask::from_words(std::array::from_fn(|word| {
                    slot.demand_queue_mask[word].load(Ordering::Acquire)
                }))
            })
            .unwrap_or(ExactDemandQueueMask::EMPTY)
    }

    #[inline]
    pub(in crate::afxdp) fn has_peer_backlog(&self, binding_slot: u32) -> bool {
        self.worker_bytes
            .iter()
            .enumerate()
            .filter(|(idx, _)| *idx != binding_slot as usize)
            .any(|(_, slot)| slot.queued_bytes.load(Ordering::Relaxed) > 0)
    }

    #[inline]
    pub(in crate::afxdp) fn peer_exact_demand_queue_mask(
        &self,
        binding_slot: u32,
    ) -> ExactDemandQueueMask {
        self.worker_bytes
            .iter()
            .enumerate()
            .filter(|(idx, _)| *idx != binding_slot as usize)
            .fold(ExactDemandQueueMask::EMPTY, |acc, (_, slot)| {
                acc | ExactDemandQueueMask::from_words(std::array::from_fn(|word| {
                    slot.demand_queue_mask[word].load(Ordering::Acquire)
                }))
            })
    }

    /// #19025: record whether this binding has a backlogged non-exact queue
    /// on the interface. Only the owning binding writes its slot, so the
    /// relaxed read of the current value is exact; the store (and its
    /// cache-line traffic) happens only on a change.
    #[inline]
    pub(in crate::afxdp) fn publish_nonexact_backlogged(
        &self,
        binding_slot: u32,
        backlogged: bool,
    ) {
        if let Some(slot) = self.worker_bytes.get(binding_slot as usize) {
            let value = u64::from(backlogged);
            if slot.nonexact_backlogged.load(Ordering::Relaxed) != value {
                slot.nonexact_backlogged.store(value, Ordering::Release);
            }
        }
    }

    /// #19025: how many bindings, this one included, have a backlogged
    /// non-exact queue on the interface: the `n` of the `residual / n`
    /// per-binding share. O(bindings), the same scan the peer demand mask
    /// makes.
    #[inline]
    pub(in crate::afxdp) fn nonexact_backlogged_bindings(&self) -> u64 {
        self.worker_bytes
            .iter()
            .filter(|slot| slot.nonexact_backlogged.load(Ordering::Acquire) != 0)
            .count() as u64
    }
}
