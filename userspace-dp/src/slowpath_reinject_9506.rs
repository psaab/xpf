//! #9506 S5: q0 REINJECT ACK/commit primitive.
//!
//! This module owns the small asynchronous completion table used by the sole
//! delegated q0 writer. It deliberately does not touch the snapshot mutex:
//! epoch publication is copied into `AuthorityState`, while submit/cancel/
//! completion operations take only this module's short mutex.

use crate::afxdp::ipsec_inner_queue::{
    IPSEC_INNER_SLAB_BYTES, IpsecInnerSlabPool, IpsecInnerVerdict, reason as ipsec_reason,
};
use crate::io_uring_write::WriteResult;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Aggregate live descriptor budget: queued + write-started + terminal but
/// not yet drained. A descriptor releases this slot only at completion drain.
pub(crate) const N_LIVE: usize = 16_384;
/// Bounded per-run request-ID tombstones prevent terminal IDs being reused
/// after their completion row is drained.
pub(crate) const TERMINAL_TOMBSTONE_MAX: usize = N_LIVE;
/// Maximum frames in one submit message.
pub(crate) const SUBMIT_MAX_FRAMES: usize = 64;
/// Maximum payload bytes in one submitted frame.
pub(crate) const SUBMIT_MAX_DATA_LEN: usize = 65_535;
/// Maximum complete binary message, including its type byte.
pub(crate) const REINJECT_MAX_MSG: usize = 1_048_576;
/// P-MECH submit tail size: snapshot u64 + config u64 + FIB u32 + zone u16
/// + if_id u32. Keep this shared with strict codec tests (26 bytes).
pub(crate) const SUBMIT_PMECH_TAIL_LEN: usize = 26;

/// Dedicated data-plane message types. Control-socket JSON is intentionally not
/// used for packet admission or completion handoff.
pub(crate) const MSG_SUBMIT_BATCH: u8 = 1;
pub(crate) const MSG_CANCEL: u8 = 2;
pub(crate) const MSG_ANNOUNCE: u8 = 3;
pub(crate) const MSG_ADMIT: u8 = 11;
pub(crate) const MSG_COMPLETE: u8 = 12;

/// ADMIT reason codes (payload wire values). Values 11/12 are the only
/// P-MECH additions; intermediate values remain reserved and decode rejects
/// them rather than applying a permissive default.
pub(crate) const ADMIT_OK: u8 = 0;
pub(crate) const ADMIT_STALE: u8 = 1;
pub(crate) const ADMIT_FULL: u8 = 2;
pub(crate) const ADMIT_BAD_LEASE: u8 = 3;
pub(crate) const ADMIT_SHUTDOWN: u8 = 4;
pub(crate) const ADMIT_BRIDGE: u8 = 5;
pub(crate) const ADMIT_INPUT_HOOK: u8 = 6;
pub(crate) const ADMIT_NON_DRY_RUN: u8 = 7;
pub(crate) const ADMIT_NO_GENERATION: u8 = 11;
pub(crate) const ADMIT_TUNNEL_ROW_MISSING: u8 = 12;

fn admit_reason_valid(reason: u8) -> bool {
    matches!(
        reason,
        ADMIT_OK
            | ADMIT_STALE
            | ADMIT_FULL
            | ADMIT_BAD_LEASE
            | ADMIT_SHUTDOWN
            | ADMIT_BRIDGE
            | ADMIT_INPUT_HOOK
            | ADMIT_NON_DRY_RUN
            | ADMIT_NO_GENERATION
            | ADMIT_TUNNEL_ROW_MISSING
    )
}

/// Submit-capture origin wire values.
pub(crate) const ORIGIN_INET: u8 = 1;
pub(crate) const ORIGIN_BRIDGE: u8 = 2;
pub(crate) const ORIGIN_FORWARD: u8 = 1;
pub(crate) const ORIGIN_INPUT: u8 = 2;
pub(crate) const SUBMIT_FLAG_SHADOW: u8 = 0x01;
pub(crate) const SUBMIT_FLAG_DRY_RUN: u8 = 0x02;
pub(crate) const ORIGIN_MAX_OWNER: usize = 64;
pub(crate) const RUN_ID_MAX: usize = 64;
pub(crate) const ORIGIN_MAX_STN: usize = 16;

/// CANCEL scope flags.
pub(crate) const CANCEL_IDS: u8 = 0x01;
pub(crate) const CANCEL_PERMIT_SCOPE: u8 = 0x02;
pub(crate) const CANCEL_QUEUE_SCOPE: u8 = 0x04;
/// Maximum queue/epoch pairs carried by one authority announcement.
pub(crate) const ANNOUNCE_MAX_QUEUES: usize = 128;

/// Authority state sent over the persistent submit socket.
///
/// The queue list is a sequence rather than a map so its wire shape remains
/// deterministic and mirrors the ConfigSnapshot queue-epoch list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AuthorityAnnouncement {
    pub run_id: String,
    pub generation: u64,
    pub permit_epoch: u64,
    pub permit_open: bool,
    pub queue_epochs: Vec<(u16, u64)>,
}

/// COMPLETE outcome wire values.
pub(crate) const OUTCOME_WRITTEN: u8 = 1;
pub(crate) const OUTCOME_STALE: u8 = 2;
pub(crate) const OUTCOME_CANCELLED: u8 = 3;
pub(crate) const OUTCOME_REFUSED: u8 = 4;
pub(crate) const OUTCOME_UNCERTAIN: u8 = 5;
pub(crate) const OUTCOME_FENCED: u8 = 6;
pub(crate) const OUTCOME_DENIED: u8 = 7;
pub(crate) const OUTCOME_ACCEPTED: u8 = 8;
pub(crate) const OUTCOME_WOULD_REINJECT: u8 = 9;
pub(crate) const OUTCOME_WOULD_PERMIT: u8 = 10;

/// Immutable nfqueue capture provenance carried with every submitted frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CaptureOrigin {
    pub family: u8,
    pub hook: u8,
    pub owned_ifindex: u32,
    pub owner: String,
    pub stn: String,
    pub valid: bool,
}

impl CaptureOrigin {
    pub(crate) fn inet_forward(owned_ifindex: u32, owner: &str, stn: &str) -> Self {
        Self {
            family: ORIGIN_INET,
            hook: ORIGIN_FORWARD,
            owned_ifindex,
            owner: owner.to_string(),
            stn: stn.to_string(),
            valid: owned_ifindex != 0
                && !owner.is_empty()
                && !stn.is_empty()
                && owner.len() <= ORIGIN_MAX_OWNER
                && stn.len() <= ORIGIN_MAX_STN,
        }
    }

    pub(crate) fn wire_valid(&self) -> bool {
        self.valid
            && self.owned_ifindex != 0
            && !self.owner.is_empty()
            && !self.stn.is_empty()
            && (self.family == ORIGIN_INET || self.family == ORIGIN_BRIDGE)
            && (self.hook == ORIGIN_FORWARD || self.hook == ORIGIN_INPUT)
            && self.owner.len() <= ORIGIN_MAX_OWNER
            && self.stn.len() <= ORIGIN_MAX_STN
    }
}

impl Default for CaptureOrigin {
    fn default() -> Self {
        Self::inet_forward(0, "", "")
    }
}

/// Lease transferred from Go capture/adjudication to the q0 writer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ReinjectLease {
    pub permit_epoch: u64,
    pub queue_epoch: u64,
    pub queue_number: u16,
    pub request_id: u64,
}

/// One binary submit frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SubmitFrame {
    pub lease: ReinjectLease,
    pub flow_tag: u64,
    pub flags: u8,
    pub origin: CaptureOrigin,
    pub bytes: Vec<u8>,
    /// P-MECH advisory tail. These values are checked against the immutable
    /// RuntimeView and exact STN tunnel row by the Rust worker.
    pub snapshot_generation: u64,
    pub config_generation: u64,
    pub fib_generation: u32,
    pub zone_id: u16,
    pub if_id: u32,
}

fn d11_frame_digest(frame: &SubmitFrame, run_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"XPF-D11-FRAME/v1");
    hasher.update(11u32.to_be_bytes());
    let mut field = |bytes: &[u8]| {
        hasher.update((bytes.len() as u32).to_be_bytes());
        hasher.update(bytes);
    };
    field(&frame.bytes);
    field(&frame.lease.request_id.to_be_bytes());
    field(&frame.lease.permit_epoch.to_be_bytes());
    field(&frame.lease.queue_epoch.to_be_bytes());
    field(&frame.lease.queue_number.to_be_bytes());
    field(&[frame.origin.family]);
    field(&[frame.origin.hook]);
    field(&frame.origin.owned_ifindex.to_be_bytes());
    field(frame.origin.owner.as_bytes());
    field(frame.origin.stn.as_bytes());
    field(run_id.as_bytes());
    hasher.finalize().into()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReinjectOutcome {
    Written,
    Stale,
    Cancelled,
    Refused,
    Uncertain,
    Fenced,
    Denied,
    Accepted,
    WouldReinject,
    WouldPermit,
}

impl ReinjectOutcome {
    pub(crate) fn wire(self) -> u8 {
        match self {
            Self::Written => OUTCOME_WRITTEN,
            Self::Stale => OUTCOME_STALE,
            Self::Cancelled => OUTCOME_CANCELLED,
            Self::Refused => OUTCOME_REFUSED,
            Self::Uncertain => OUTCOME_UNCERTAIN,
            Self::Fenced => OUTCOME_FENCED,
            Self::Denied => OUTCOME_DENIED,
            Self::Accepted => OUTCOME_ACCEPTED,
            Self::WouldReinject => OUTCOME_WOULD_REINJECT,
            Self::WouldPermit => OUTCOME_WOULD_PERMIT,
        }
    }

    pub(crate) fn from_wire(code: u8) -> Option<Self> {
        Some(match code {
            OUTCOME_WRITTEN => Self::Written,
            OUTCOME_STALE => Self::Stale,
            OUTCOME_CANCELLED => Self::Cancelled,
            OUTCOME_REFUSED => Self::Refused,
            OUTCOME_UNCERTAIN => Self::Uncertain,
            OUTCOME_FENCED => Self::Fenced,
            OUTCOME_DENIED => Self::Denied,
            OUTCOME_ACCEPTED => Self::Accepted,
            OUTCOME_WOULD_REINJECT => Self::WouldReinject,
            OUTCOME_WOULD_PERMIT => Self::WouldPermit,
            _ => return None,
        })
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Written => "written",
            Self::Stale => "stale",
            Self::Cancelled => "cancelled",
            Self::Refused => "refused",
            Self::Uncertain => "uncertain",
            Self::Fenced => "fenced",
            Self::Denied => "denied",
            Self::Accepted => "accepted",
            Self::WouldReinject => "would_reinject",
            Self::WouldPermit => "would_permit",
        }
    }
}

/// Definitive/ambiguous result supplied by the write/adjudication path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TransferVerdict {
    Written { bytes: u32 },
    Refused { reason: String },
    Uncertain { reason: String },
    Fenced,
    Denied,
    Accepted,
    WouldReinject,
    WouldPermit,
}

/// Completion held until the Go poller drains it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReinjectCompletion {
    pub request_id: u64,
    pub permit_epoch: u64,
    pub queue_epoch: u64,
    pub queue_number: u16,
    pub family: u8,
    pub hook: u8,
    pub owned_ifindex: u32,
    pub outcome: ReinjectOutcome,
    pub bytes_written: u32,
    pub flow_tag: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EntryView {
    Unknown,
    Queued,
    WriteStarted,
    Terminal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PreWrite {
    Proceed,
    Fenced,
    Cancelled,
    Unknown,
}

/// Epoch/permit authority. Implementations are deliberately tiny and
/// lock-free from the caller's perspective; the production state is owned by
/// `ReinjectCore`'s private mutex, not by ServerState's snapshot lock.
pub(crate) trait ReinjectAuthority {
    fn allows(&self, permit_epoch: u64, queue_number: u16, queue_epoch: u64) -> bool;
    fn permit_open(&self) -> bool;
}

#[derive(Clone, Debug, Default)]
pub(crate) struct AuthorityState {
    run_id: String,
    generation: u64,
    permit_epoch: u64,
    queue_epochs: BTreeMap<u16, u64>,
    /// Queue/epoch pairs cancelled by an applied queue-scope cancel. These
    /// remain closed across republish/announce of the same epoch.
    tombstones: BTreeSet<(u16, u64)>,
    open: bool,
    closed_epoch: u64,
}

impl AuthorityState {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Publish a snapshot-derived authority. Epoch zero is the old-snapshot
    /// compatibility state: legacy lease-None packets remain available, but
    /// all 9506 leased packets are closed.
    pub(crate) fn publish(&mut self, permit_epoch: u64, queue_epochs: &[(u16, u64)]) -> bool {
        if permit_epoch == 0 {
            self.queue_epochs.clear();
            self.open = false;
            self.closed_epoch = self.closed_epoch.max(self.permit_epoch);
            return true;
        }
        if permit_epoch < self.permit_epoch {
            return false;
        }
        if permit_epoch > self.permit_epoch {
            self.permit_epoch = permit_epoch;
            self.open = permit_epoch > self.closed_epoch;
        }
        self.queue_epochs = queue_epochs
            .iter()
            .copied()
            .filter(|(_, epoch)| *epoch != 0)
            .collect();
        if permit_epoch <= self.closed_epoch {
            self.open = false;
        }
        true
    }
    pub(crate) fn publish_announce(
        &mut self,
        run_id: &str,
        generation: u64,
        permit_epoch: u64,
        permit_open: bool,
        queue_epochs: &[(u16, u64)],
    ) -> bool {
        if run_id.is_empty() || run_id.len() > RUN_ID_MAX || generation == 0 {
            return false;
        }
        if !self.run_id.is_empty() && self.run_id != run_id {
            // A daemon restart starts a fresh authority timeline. Do not let
            // the previous process's epoch fence reject its first announce.
            self.run_id = run_id.to_string();
            self.generation = generation;
            self.permit_epoch = 0;
            self.closed_epoch = 0;
            self.queue_epochs.clear();
            self.tombstones.clear();
            self.open = false;
        }
        if permit_epoch == 0 {
            self.run_id = run_id.to_string();
            self.generation = generation;
            self.queue_epochs.clear();
            self.open = false;
            self.closed_epoch = self.closed_epoch.max(self.permit_epoch);
            return true;
        }
        if permit_epoch < self.permit_epoch {
            return false;
        }
        // Same-epoch generation advance is a legitimate queue rotation: the
        // daemon mints a new handles generation under an unchanged permit
        // epoch, so accept and adopt the announced generation (#10478).
        self.run_id = run_id.to_string();
        self.generation = generation;
        if permit_epoch > self.permit_epoch {
            self.permit_epoch = permit_epoch;
        }
        self.open = permit_open && permit_epoch > self.closed_epoch;
        self.queue_epochs = queue_epochs
            .iter()
            .copied()
            .filter(|(_, epoch)| *epoch != 0)
            .collect();
        true
    }
    pub(crate) fn tombstone_queue_epochs(&mut self, queue_epochs: &[(u16, u64)]) {
        for &(queue_number, queue_epoch) in queue_epochs {
            if queue_number != 0 && queue_epoch != 0 {
                self.tombstones.insert((queue_number, queue_epoch));
            }
        }
    }

    fn queue_scope_applies(&self, permit_epoch: Option<u64>) -> bool {
        match permit_epoch {
            None => true,
            Some(epoch) => epoch != 0 && epoch == self.permit_epoch,
        }
    }

    pub(crate) fn reset_baseline(&mut self) {
        *self = Self::default();
    }
    pub(crate) fn close_permit(&mut self, permit_epoch: u64) {
        if permit_epoch == 0 {
            return;
        }
        self.closed_epoch = self.closed_epoch.max(permit_epoch);
        if permit_epoch == self.permit_epoch {
            self.open = false;
        }
    }
}

impl ReinjectAuthority for AuthorityState {
    fn allows(&self, permit_epoch: u64, queue_number: u16, queue_epoch: u64) -> bool {
        self.open
            && permit_epoch != 0
            && queue_epoch != 0
            && permit_epoch == self.permit_epoch
            && !self.tombstones.contains(&(queue_number, queue_epoch))
            && self.queue_epochs.get(&queue_number).copied() == Some(queue_epoch)
    }

    fn permit_open(&self) -> bool {
        self.open
    }
}
pub(crate) fn decide_pre_write(
    view: EntryView,
    lease: &ReinjectLease,
    authority: &dyn ReinjectAuthority,
) -> PreWrite {
    match view {
        EntryView::Unknown => PreWrite::Unknown,
        EntryView::Queued
            if authority.allows(lease.permit_epoch, lease.queue_number, lease.queue_epoch) =>
        {
            PreWrite::Proceed
        }
        EntryView::Queued => PreWrite::Fenced,
        EntryView::WriteStarted | EntryView::Terminal => PreWrite::Cancelled,
    }
}
/// The authorization linearization point is immediately before the TUN write.
/// Once that point has passed, a definitive full-frame write is always the
/// `written` commit even if authority closes concurrently.
pub(crate) fn decide_resolve(
    _lease: &ReinjectLease,
    verdict: &TransferVerdict,
    _authority: &dyn ReinjectAuthority,
) -> (ReinjectOutcome, u32) {
    match verdict {
        TransferVerdict::Written { bytes } => (ReinjectOutcome::Written, *bytes),
        TransferVerdict::Refused { .. } => (ReinjectOutcome::Refused, 0),
        TransferVerdict::Uncertain { .. } => (ReinjectOutcome::Uncertain, 0),
        TransferVerdict::Fenced => (ReinjectOutcome::Fenced, 0),
        TransferVerdict::Denied => (ReinjectOutcome::Denied, 0),
        TransferVerdict::Accepted => (ReinjectOutcome::Accepted, 0),
        TransferVerdict::WouldReinject => (ReinjectOutcome::WouldReinject, 0),
        TransferVerdict::WouldPermit => (ReinjectOutcome::WouldPermit, 0),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdmissionClass {
    Adjudicated,
    Delegated,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ReinjectStats {
    pub live_descriptors: usize,
    pub oldest_unacked_ms: u64,
    pub completed_written: u64,
    pub completed_stale: u64,
    pub completed_cancelled: u64,
    pub completed_refused: u64,
    pub completed_uncertain: u64,
    pub adjudicated_admitted: u64,
    pub adjudicated_refused: u64,
    pub delegated_admitted: u64,
    pub delegated_refused: u64,
    pub purged_queued: u64,
    pub purged_unacked: u64,
    pub epoch_rejects: u64,
    pub dry_run_admitted: u64,
    pub dry_run_refused: u64,
    pub non_dry_run_refused: u64,
}

pub(crate) const PROVENANCE_MAX: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReinjectProvenanceRow {
    pub request_id: u64,
    pub permit_epoch: u64,
    pub queue_epoch: u64,
    pub queue_number: u16,
    pub family: u8,
    pub hook: u8,
    pub owned_ifindex: u32,
    pub owner: String,
    pub stn: String,
    pub outcome: String,
    pub bytes_written: u32,
    pub frame_digest: [u8; 32],
    pub reason: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReinjectStatusSnapshot {
    pub run_id: String,
    pub generation: u64,
    pub permit_epoch: u64,
    pub permit_open: bool,
    pub stats: ReinjectStats,
    pub provenance: Vec<ReinjectProvenanceRow>,
    // No product-owned witness currently observes downstream delivery after
    // the Rust TUN write; this must never be inferred from completed_written.
    pub delivered_available: bool,
    pub delivered: u64,
}

impl ReinjectStats {
    pub(crate) fn is_empty(&self) -> bool {
        self.live_descriptors == 0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AdmitDecision {
    pub request_id: u64,
    pub permit_epoch: u64,
    pub queue_epoch: u64,
    pub queue_number: u16,
    pub family: u8,
    pub hook: u8,
    pub owned_ifindex: u32,
    pub admitted: bool,
    pub reason: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CancelScope {
    pub ids: Option<Vec<u64>>,
    pub permit_epoch: Option<u64>,
    pub queue_epochs: Vec<(u16, u64)>,
}

impl CancelScope {
    pub(crate) fn none() -> Self {
        Self {
            ids: None,
            permit_epoch: None,
            queue_epochs: Vec::new(),
        }
    }

    pub(crate) fn ids(ids: Vec<u64>) -> Self {
        Self {
            ids: Some(ids),
            ..Self::none()
        }
    }

    pub(crate) fn permit(epoch: u64) -> Self {
        Self {
            permit_epoch: Some(epoch),
            ..Self::none()
        }
    }

    pub(crate) fn queue(queue_number: u16, epoch: u64) -> Self {
        Self {
            queue_epochs: vec![(queue_number, epoch)],
            ..Self::none()
        }
    }

    fn is_empty(&self) -> bool {
        self.ids.as_ref().is_none_or(Vec::is_empty)
            && self.permit_epoch.is_none()
            && self.queue_epochs.is_empty()
    }
}

#[derive(Debug)]
enum EntryState {
    Queued,
    WriteStarted { cancel_requested: bool },
    Terminal(ReinjectCompletion),
}
#[derive(Debug)]
struct Entry {
    lease: ReinjectLease,
    origin: CaptureOrigin,
    flow_tag: u64,
    connection_id: u64,
    frame_digest: [u8; 32],
    since: Instant,
    state: EntryState,
}
#[derive(Debug)]
struct CoreInner {
    authority: AuthorityState,
    entries: BTreeMap<u64, Entry>,
    flow_order: BTreeMap<u64, VecDeque<u64>>,
    ready_count: usize,
    /// Completion ids reserved for an in-progress socket write. Reservation
    /// prevents a second client/drain pass from racing the write; a failed
    /// write releases the exact ids without losing their terminal records.
    reserved: BTreeSet<u64>,
    /// Terminal request IDs retained for this authority run. The set is
    /// bounded and reset only when the frozen run identity changes.
    terminal_tombstones: BTreeSet<u64>,
    /// Once true the run is fail-closed for all new request IDs; clearing is
    /// allowed only on a new authority run.
    terminal_tombstone_overflow: bool,
    announce_events: VecDeque<Vec<u8>>,
    provenance: VecDeque<ReinjectProvenanceRow>,
    stats: ReinjectStats,
    shutdown: bool,
}

/// Shared completion-table state. Every method holds this mutex only for
/// bookkeeping; the q0 writer performs its TUN syscall outside it.
pub(crate) struct ReinjectCore {
    inner: Mutex<CoreInner>,
}

impl ReinjectCore {
    pub(crate) fn new_shared() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(CoreInner {
                authority: AuthorityState::new(),
                entries: BTreeMap::new(),
                terminal_tombstones: BTreeSet::new(),
                flow_order: BTreeMap::new(),
                ready_count: 0,
                reserved: BTreeSet::new(),
                announce_events: VecDeque::new(),
                provenance: VecDeque::new(),
                stats: ReinjectStats::default(),
                terminal_tombstone_overflow: false,
                shutdown: false,
            }),
        })
    }

    pub(crate) fn publish_epochs(&self, permit_epoch: u64, queue_epochs: &[(u16, u64)]) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if !inner.authority.publish(permit_epoch, queue_epochs) {
            inner.stats.epoch_rejects += 1;
        }
    }

    pub(crate) fn announce_epochs(
        &self,
        run_id: &str,
        generation: u64,
        permit_epoch: u64,
        permit_open: bool,
        queue_epochs: &[(u16, u64)],
    ) -> bool {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let prev_run = inner.authority.run_id.clone();
        let accepted = inner.authority.publish_announce(
            run_id,
            generation,
            permit_epoch,
            permit_open,
            queue_epochs,
        );
        if accepted {
            if !prev_run.is_empty() && prev_run.as_str() != run_id {
                // A daemon restart starts a fresh run timeline; old-run
                // provenance and request-ID tombstones must not be relabeled
                // under the new run.
                inner.provenance.clear();
                inner.terminal_tombstones.clear();
                inner.terminal_tombstone_overflow = false;
            }
        } else {
            inner.stats.epoch_rejects += 1;
        }
        accepted
    }

    pub(crate) fn reset_epoch_baseline(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.authority.reset_baseline();
    }

    pub(crate) fn authority_snapshot(&self) -> (String, u64, u64, bool, Vec<(u16, u64)>) {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        (
            inner.authority.run_id.clone(),
            inner.authority.generation,
            inner.authority.permit_epoch,
            inner.authority.open,
            inner
                .authority
                .queue_epochs
                .iter()
                .map(|(n, e)| (*n, *e))
                .collect(),
        )
    }

    /// Transfer the fallback authority into a newly installed target core.
    ///
    /// ANNOUNCE can arrive while the slow-path target is absent, so the
    /// submit listener applies it to the fallback core. Target installation
    /// must copy that state before swapping the target into service; otherwise
    /// the target starts closed and immediately rejects unchanged leases.
    pub(crate) fn copy_authority_from(&self, source: &Self) {
        if std::ptr::eq(self, source) {
            return;
        }
        let (source_authority, source_terminal_tombstones, source_tombstone_overflow) = {
            let source_inner = source.inner.lock().unwrap_or_else(|e| e.into_inner());
            (
                source_inner.authority.clone(),
                source_inner.terminal_tombstones.clone(),
                source_inner.terminal_tombstone_overflow,
            )
        };
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let target_authority = inner.authority.clone();
        let mut merged = if source_authority.permit_epoch >= target_authority.permit_epoch {
            source_authority.clone()
        } else {
            target_authority.clone()
        };
        merged.closed_epoch = merged
            .closed_epoch
            .max(source_authority.closed_epoch)
            .max(target_authority.closed_epoch);
        if merged.permit_epoch <= merged.closed_epoch {
            merged.open = false;
        }
        merged
            .tombstones
            .extend(source_authority.tombstones.iter().copied());
        merged
            .tombstones
            .extend(target_authority.tombstones.iter().copied());
        inner.authority = merged;
        let target_tombstone_overflow = inner.terminal_tombstone_overflow;
        if source_authority.run_id == target_authority.run_id {
            if source_tombstone_overflow
                || target_tombstone_overflow
                || source_terminal_tombstones.len() + inner.terminal_tombstones.len()
                    > TERMINAL_TOMBSTONE_MAX
            {
                inner.terminal_tombstones.clear();
                inner.terminal_tombstone_overflow = true;
            } else {
                inner.terminal_tombstones.extend(source_terminal_tombstones);
            }
        } else if inner.authority.run_id == source_authority.run_id {
            inner.terminal_tombstones = source_terminal_tombstones;
            inner.terminal_tombstone_overflow = source_tombstone_overflow;
        } else {
            inner.terminal_tombstone_overflow = target_tombstone_overflow;
        }
    }
    pub(crate) fn enqueue_announce_ack(&self, payload: Vec<u8>) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.announce_events.push_back(payload);
    }

    pub(crate) fn peek_announce_ack(&self) -> Option<Vec<u8>> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .announce_events
            .front()
            .cloned()
    }

    pub(crate) fn ack_announce_ack(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.announce_events.pop_front();
    }
    /// Validate-only admission. This intentionally never inserts an entry,
    /// touches the worker channel, or reaches any TUN writer.
    pub(crate) fn validate_dry_run(&self, frame: &SubmitFrame) -> AdmitDecision {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let refusal = if frame.flags & !(SUBMIT_FLAG_SHADOW | SUBMIT_FLAG_DRY_RUN) != 0 {
            Some(ADMIT_BAD_LEASE)
        } else if inner.shutdown {
            Some(ADMIT_SHUTDOWN)
        } else if frame.lease.queue_number == 0 {
            Some(ADMIT_BAD_LEASE)
        } else if frame.lease.request_id == 0
            || frame.bytes.is_empty()
            || frame.bytes.len() > SUBMIT_MAX_DATA_LEN
        {
            Some(ADMIT_BAD_LEASE)
        } else if !frame.origin.wire_valid() {
            Some(ADMIT_BAD_LEASE)
        } else if frame.origin.family == ORIGIN_BRIDGE {
            Some(ADMIT_BRIDGE)
        } else if frame.origin.hook == ORIGIN_INPUT && frame.origin.family != ORIGIN_INET {
            Some(ADMIT_INPUT_HOOK)
        } else if !inner.authority.allows(
            frame.lease.permit_epoch,
            frame.lease.queue_number,
            frame.lease.queue_epoch,
        ) {
            Some(ADMIT_STALE)
        } else if frame.snapshot_generation == 0
            || frame.config_generation == 0
            || frame.fib_generation == 0
        {
            Some(ADMIT_NO_GENERATION)
        } else if frame.if_id == 0 || frame.origin.stn.is_empty() {
            Some(ADMIT_TUNNEL_ROW_MISSING)
        } else if inner.authority.run_id.starts_with("attest-")
            && inner.terminal_tombstone_overflow
        {
            Some(ADMIT_FULL)
        } else if (inner.authority.run_id.starts_with("attest-")
            && inner.terminal_tombstones.contains(&frame.lease.request_id))
            || inner.entries.contains_key(&frame.lease.request_id)
        {
            Some(ADMIT_BAD_LEASE)
        } else if inner.entries.len() >= N_LIVE {
            Some(ADMIT_FULL)
        } else {
            None
        };
        Self::decision(frame, refusal.is_none(), refusal.unwrap_or(ADMIT_OK))
    }

    pub(crate) fn note_dry_run(&self, admitted: bool) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if admitted {
            inner.stats.dry_run_admitted += 1;
        } else {
            inner.stats.dry_run_refused += 1;
        }
    }

    pub(crate) fn refuse_non_dry_run(&self, frame: &SubmitFrame) -> AdmitDecision {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.stats.non_dry_run_refused += 1;
        Self::decision(frame, false, ADMIT_NON_DRY_RUN)
    }

    pub(crate) fn refuse_shutdown(&self, frame: &SubmitFrame) -> AdmitDecision {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if frame.flags & SUBMIT_FLAG_DRY_RUN != 0 {
            inner.stats.dry_run_refused += 1;
        } else {
            inner.stats.non_dry_run_refused += 1;
        }
        Self::decision(frame, false, ADMIT_SHUTDOWN)
    }

    pub(crate) fn close_permit(&self, permit_epoch: u64) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.authority.close_permit(permit_epoch);
    }
    pub(crate) fn admit(&self, frame: &SubmitFrame) -> AdmitDecision {
        self.admit_with_class_owner(frame, None, 0)
    }

    pub(crate) fn admit_for_connection(
        &self,
        frame: &SubmitFrame,
        connection_id: u64,
    ) -> AdmitDecision {
        self.admit_with_class_owner(frame, None, connection_id)
    }

    pub(crate) fn admit_with_class(
        &self,
        frame: &SubmitFrame,
        class: Option<AdmissionClass>,
    ) -> AdmitDecision {
        self.admit_with_class_owner(frame, class, 0)
    }

    pub(crate) fn admit_with_class_owner(
        &self,
        frame: &SubmitFrame,
        class: Option<AdmissionClass>,
        connection_id: u64,
    ) -> AdmitDecision {
        let id = frame.lease.request_id;
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if frame.flags & !(SUBMIT_FLAG_SHADOW | SUBMIT_FLAG_DRY_RUN) != 0 {
            if let Some(class) = class {
                Self::record_refusal(&mut inner.stats, class);
            }
            return Self::decision(frame, false, ADMIT_BAD_LEASE);
        }
        if frame.flags & SUBMIT_FLAG_DRY_RUN != 0 {
            inner.stats.non_dry_run_refused += 1;
            if let Some(class) = class {
                Self::record_refusal(&mut inner.stats, class);
            }
            return Self::decision(frame, false, ADMIT_NON_DRY_RUN);
        }
        let refusal = if inner.shutdown {
            Some(ADMIT_SHUTDOWN)
        } else if frame.lease.queue_number == 0 {
            Some(ADMIT_BAD_LEASE)
        } else if id == 0 || frame.bytes.is_empty() || frame.bytes.len() > SUBMIT_MAX_DATA_LEN {
            Some(ADMIT_BAD_LEASE)
        } else if !frame.origin.wire_valid() {
            Some(ADMIT_BAD_LEASE)
        } else if frame.origin.family == ORIGIN_BRIDGE {
            Some(ADMIT_BRIDGE)
        } else if frame.origin.hook == ORIGIN_INPUT {
            Some(ADMIT_INPUT_HOOK)
        } else if !inner.authority.allows(
            frame.lease.permit_epoch,
            frame.lease.queue_number,
            frame.lease.queue_epoch,
        ) {
            Some(ADMIT_STALE)
        } else if inner.authority.run_id.starts_with("attest-")
            && inner.terminal_tombstone_overflow
        {
            Some(ADMIT_FULL)
        } else if (inner.authority.run_id.starts_with("attest-")
            && inner.terminal_tombstones.contains(&id))
            || inner.entries.contains_key(&id)
        {
            Some(ADMIT_BAD_LEASE)
        } else if inner.entries.len() >= N_LIVE {
            Some(ADMIT_FULL)
        } else {
            None
        };
        if let Some(reason) = refusal {
            if let Some(class) = class {
                Self::record_refusal(&mut inner.stats, class);
            }
            return Self::decision(frame, false, reason);
        }
        let now = Instant::now();
        let frame_digest = d11_frame_digest(frame, &inner.authority.run_id);
        inner.entries.insert(
            id,
            Entry {
                lease: frame.lease,
                origin: frame.origin.clone(),
                flow_tag: frame.flow_tag,
                connection_id,
                frame_digest,
                since: now,
                state: EntryState::Queued,
            },
        );
        inner
            .flow_order
            .entry(frame.flow_tag)
            .or_default()
            .push_back(id);
        if let Some(class) = class {
            Self::record_admission(&mut inner.stats, class);
        }
        Self::decision(frame, true, ADMIT_OK)
    }

    fn decision(frame: &SubmitFrame, admitted: bool, reason: u8) -> AdmitDecision {
        AdmitDecision {
            request_id: frame.lease.request_id,
            permit_epoch: frame.lease.permit_epoch,
            queue_epoch: frame.lease.queue_epoch,
            queue_number: frame.lease.queue_number,
            family: frame.origin.family,
            hook: frame.origin.hook,
            owned_ifindex: frame.origin.owned_ifindex,
            admitted,
            reason,
        }
    }

    pub(crate) fn submit_batch(&self, frames: &[SubmitFrame]) -> Vec<AdmitDecision> {
        frames.iter().map(|frame| self.admit(frame)).collect()
    }

    pub(crate) fn view(&self, lease: &ReinjectLease) -> EntryView {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        match inner.entries.get(&lease.request_id).map(|e| &e.state) {
            None => EntryView::Unknown,
            Some(EntryState::Queued) => EntryView::Queued,
            Some(EntryState::WriteStarted { .. }) => EntryView::WriteStarted,
            Some(EntryState::Terminal(_)) => EntryView::Terminal,
        }
    }

    /// Dequeue-side epoch/connection check. A stale queued lease becomes
    /// terminal without touching the TUN; this is the only authority check
    /// needed before write.
    pub(crate) fn pre_write_check(&self, lease: &ReinjectLease) -> PreWrite {
        self.pre_write_check_for(0, lease)
    }

    pub(crate) fn pre_write_check_for(
        &self,
        connection_id: u64,
        lease: &ReinjectLease,
    ) -> PreWrite {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let view = match inner.entries.get(&lease.request_id) {
            Some(entry) if entry.connection_id == connection_id && entry.lease == *lease => {
                match entry.state {
                    EntryState::Queued => EntryView::Queued,
                    EntryState::WriteStarted { .. } => EntryView::WriteStarted,
                    EntryState::Terminal(_) => EntryView::Terminal,
                }
            }
            _ => EntryView::Unknown,
        };
        match decide_pre_write(view, lease, &inner.authority) {
            PreWrite::Proceed => {
                if let Some(entry) = inner.entries.get_mut(&lease.request_id) {
                    entry.state = EntryState::WriteStarted {
                        cancel_requested: false,
                    };
                }
                PreWrite::Proceed
            }
            PreWrite::Fenced => {
                Self::terminalize(&mut inner, lease.request_id, ReinjectOutcome::Fenced, 0);
                PreWrite::Fenced
            }
            other => other,
        }
    }
    /// Resolve a write after the syscall. No authority check is repeated here:
    /// a full-frame success after WRITE_STARTED is the definitive commit.
    pub(crate) fn resolve_write(&self, lease: &ReinjectLease, verdict: TransferVerdict) -> bool {
        self.resolve_write_for(0, lease, verdict)
    }

    pub(crate) fn resolve_write_for(
        &self,
        connection_id: u64,
        lease: &ReinjectLease,
        verdict: TransferVerdict,
    ) -> bool {
        let (outcome, bytes) = decide_resolve(
            lease,
            &verdict,
            &AuthorityState::new(), // post-write authority is intentionally ignored
        );
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(entry) = inner.entries.get(&lease.request_id) else {
            return false;
        };
        if entry.connection_id != connection_id
            || entry.lease != *lease
            || !matches!(entry.state, EntryState::WriteStarted { .. })
        {
            return false;
        }
        Self::terminalize(&mut inner, lease.request_id, outcome, bytes)
    }

    /// Join a Rust D11 worker verdict to the Go-facing completion table.
    /// V1 is deny-only: a deny becomes `Denied`, while a successful
    /// adjudication becomes `WouldPermit` (never a q0 write or NF_ACCEPT).
    pub(crate) fn resolve_ipsec_inner_verdict(&self, verdict: IpsecInnerVerdict) -> bool {
        let (request_id, outcome, reason) = match verdict {
            IpsecInnerVerdict::Deny {
                request_id, reason, ..
            } if reason == ipsec_reason::VERDICT_UNCERTAIN => {
                (request_id, ReinjectOutcome::Uncertain, reason)
            }
            IpsecInnerVerdict::Deny {
                request_id, reason, ..
            } => (request_id, ReinjectOutcome::Denied, reason),
            IpsecInnerVerdict::WouldPermit { request_id } => {
                (request_id, ReinjectOutcome::WouldPermit, 0)
            }
        };
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(entry) = inner.entries.get(&request_id) else {
            return false;
        };
        if !matches!(entry.state, EntryState::Queued) {
            return false;
        }
        Self::terminalize_with_reason(&mut inner, request_id, outcome, 0, reason)
    }

    /// Mark a queued descriptor as a definitive no-write refusal.
    pub(crate) fn refuse_queued(&self, lease: &ReinjectLease, _reason: String) -> bool {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(entry) = inner.entries.get(&lease.request_id) else {
            return false;
        };
        if !matches!(entry.state, EntryState::Queued) || entry.lease != *lease {
            return false;
        }
        Self::terminalize(&mut inner, lease.request_id, ReinjectOutcome::Refused, 0)
    }

    pub(crate) fn cancel(&self, scope: &CancelScope) -> Vec<u64> {
        if scope.is_empty() {
            return Vec::new();
        }
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.authority.queue_scope_applies(scope.permit_epoch) {
            inner.authority.tombstone_queue_epochs(&scope.queue_epochs);
        }
        if let Some(permit) = scope.permit_epoch {
            if scope.queue_epochs.is_empty() {
                inner.authority.close_permit(permit);
            }
        }
        let ids: Vec<u64> = inner
            .entries
            .iter()
            .filter_map(|(id, entry)| {
                if !scope_matches(scope, *id, &entry.lease) {
                    return None;
                }
                Some(*id)
            })
            .collect();
        let mut cancelled = Vec::new();
        for id in ids {
            let state = inner.entries.get(&id).map(|e| &e.state);
            match state {
                Some(EntryState::Queued) => {
                    if Self::terminalize(&mut inner, id, ReinjectOutcome::Cancelled, 0) {
                        cancelled.push(id);
                    }
                }
                Some(EntryState::WriteStarted { .. }) => {
                    if let Some(entry) = inner.entries.get_mut(&id) {
                        entry.state = EntryState::WriteStarted {
                            cancel_requested: true,
                        };
                    }
                }
                _ => {}
            }
        }
        cancelled
    }

    /// Reserve terminal heads for a socket write without removing them.
    pub(crate) fn peek_ready(&self, max: usize) -> Vec<ReinjectCompletion> {
        if max == 0 {
            return Vec::new();
        }
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut output = Vec::new();
        let mut offsets: BTreeMap<u64, usize> = BTreeMap::new();
        let mut batch_ids = BTreeSet::new();
        while output.len() < max {
            let id = inner.flow_order.iter().find_map(|(flow, queue)| {
                let offset = *offsets.get(flow).unwrap_or(&0);
                let id = *queue.get(offset)?;
                if inner.reserved.contains(&id) && !batch_ids.contains(&id) {
                    return None;
                }
                match inner.entries.get(&id).map(|e| &e.state) {
                    Some(EntryState::Terminal(_)) => Some((*flow, id, offset)),
                    _ => None,
                }
            });
            let Some((flow, id, offset)) = id else { break };
            offsets.insert(flow, offset + 1);
            inner.reserved.insert(id);
            batch_ids.insert(id);
            if let Some(EntryState::Terminal(completion)) =
                inner.entries.get(&id).map(|entry| &entry.state)
            {
                output.push(completion.clone());
            }
        }
        output
    }

    /// Commit a previously reserved batch after a complete framed write.
    /// Unknown/unreserved ids are ignored; terminal records are never lost.
    pub(crate) fn ack_ready(&self, ids: &[u64]) -> Vec<ReinjectCompletion> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut output = Vec::new();
        for id in ids {
            if !inner.reserved.remove(id) {
                continue;
            }
            let Some(entry) = inner.entries.get(id) else {
                continue;
            };
            let flow = entry.flow_tag;
            let is_head = inner
                .flow_order
                .get(&flow)
                .and_then(|queue| queue.front())
                .is_some_and(|head| head == id);
            if !is_head {
                // Preserve the reservation if a caller supplies an invalid
                // order; the record can be retried without loss.
                inner.reserved.insert(*id);
                continue;
            }
            let queue = inner.flow_order.get_mut(&flow).expect("flow exists");
            let popped = queue.pop_front();
            debug_assert_eq!(popped, Some(*id));
            if queue.is_empty() {
                inner.flow_order.remove(&flow);
            }
            if let Some(entry) = inner.entries.remove(id) {
                Self::remember_terminal_tombstone(&mut inner, *id);
                if let EntryState::Terminal(completion) = entry.state {
                    inner.ready_count = inner.ready_count.saturating_sub(1);
                    output.push(completion);
                }
            }
        }
        output
    }

    /// Return a failed socket-write batch to the ready table verbatim.
    pub(crate) fn release_ready(&self, ids: &[u64]) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        for id in ids {
            inner.reserved.remove(id);
        }
    }

    /// Convenience API for in-process callers/tests. Socket callers must use
    /// peek/ack so a disconnect cannot lose a terminal record.
    pub(crate) fn drain_ready(&self, max: usize) -> Vec<ReinjectCompletion> {
        let batch = self.peek_ready(max);
        let ids: Vec<u64> = batch
            .iter()
            .map(|completion| completion.request_id)
            .collect();
        let _ = self.ack_ready(&ids);
        batch
    }

    /// Drop all records owned by a disconnected submit connection. Queued
    /// work is counted as dropped; write-started and terminal-but-unacked work
    /// is discarded without exposing a completion to a later connection.
    pub(crate) fn purge_connection(&self, connection_id: u64) -> (u64, u64) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let ids: Vec<u64> = inner
            .entries
            .iter()
            .filter_map(|(id, entry)| (entry.connection_id == connection_id).then_some(*id))
            .collect();
        Self::purge_ids(&mut inner, &ids)
    }

    /// Hygiene for records whose owning side disappeared without a clean
    /// socket close. The caller controls the conservative TTL.
    pub(crate) fn sweep_orphans(&self, ttl: Duration) -> (u64, u64) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let ids: Vec<u64> = inner
            .entries
            .iter()
            .filter_map(|(id, entry)| {
                (now.saturating_duration_since(entry.since) >= ttl).then_some(*id)
            })
            .collect();
        Self::purge_ids(&mut inner, &ids)
    }

    fn purge_ids(inner: &mut CoreInner, ids: &[u64]) -> (u64, u64) {
        let mut queued = 0;
        let mut unacked = 0;
        for id in ids {
            let Some(entry) = inner.entries.remove(id) else {
                continue;
            };
            Self::remember_terminal_tombstone(inner, *id);
            match entry.state {
                EntryState::Queued => {
                    queued += 1;
                    inner.stats.purged_queued += 1;
                }
                EntryState::WriteStarted { .. } | EntryState::Terminal(_) => {
                    unacked += 1;
                    inner.stats.purged_unacked += 1;
                    if matches!(entry.state, EntryState::Terminal(_)) {
                        inner.ready_count = inner.ready_count.saturating_sub(1);
                    }
                }
            }
            inner.reserved.remove(id);
            if let Some(flow) = inner.flow_order.get_mut(&entry.flow_tag) {
                flow.retain(|queued_id| queued_id != id);
                if flow.is_empty() {
                    inner.flow_order.remove(&entry.flow_tag);
                }
            }
        }
        (queued, unacked)
    }

    pub(crate) fn live_count(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entries
            .len()
    }

    pub(crate) fn ready_len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .ready_count
    }

    pub(crate) fn shutdown(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.shutdown = true;
        let ids: Vec<u64> = inner
            .entries
            .iter()
            .filter_map(|(id, entry)| matches!(entry.state, EntryState::Queued).then_some(*id))
            .collect();
        for id in ids {
            Self::terminalize(&mut inner, id, ReinjectOutcome::Cancelled, 0);
        }
    }

    pub(crate) fn is_shutdown(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .shutdown
    }

    pub(crate) fn stats_snapshot(&self) -> ReinjectStats {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let oldest = inner
            .entries
            .values()
            .map(|entry| entry.since)
            .min()
            .map(|since| since.elapsed().as_millis() as u64)
            .unwrap_or(0);
        let mut stats = inner.stats.clone();
        stats.live_descriptors = inner.entries.len();
        stats.oldest_unacked_ms = oldest;
        stats
    }
    pub(crate) fn status_snapshot(&self) -> Option<ReinjectStatusSnapshot> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.authority.run_id.is_empty() || inner.authority.generation == 0 {
            return None;
        }
        let oldest = inner
            .entries
            .values()
            .map(|entry| entry.since)
            .min()
            .map(|since| since.elapsed().as_millis() as u64)
            .unwrap_or(0);
        let mut stats = inner.stats.clone();
        stats.live_descriptors = inner.entries.len();
        stats.oldest_unacked_ms = oldest;
        Some(ReinjectStatusSnapshot {
            run_id: inner.authority.run_id.clone(),
            generation: inner.authority.generation,
            permit_epoch: inner.authority.permit_epoch,
            permit_open: inner.authority.open,
            stats,
            provenance: inner.provenance.iter().cloned().collect(),
            delivered_available: false,
            delivered: 0,
        })
    }

    pub(crate) fn record_class_admitted(&self, class: AdmissionClass) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        Self::record_admission(&mut inner.stats, class);
    }

    pub(crate) fn record_class_refused(&self, class: AdmissionClass) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        Self::record_refusal(&mut inner.stats, class);
    }

    fn remember_terminal_tombstone(inner: &mut CoreInner, id: u64) {
        if !inner.authority.run_id.starts_with("attest-")
            || id == 0
            || inner.terminal_tombstone_overflow
        {
            return;
        }
        if inner.terminal_tombstones.contains(&id) {
            return;
        }
        if inner.terminal_tombstones.len() >= TERMINAL_TOMBSTONE_MAX {
            inner.terminal_tombstone_overflow = true;
            return;
        }
        inner.terminal_tombstones.insert(id);
    }

    fn terminalize(
        inner: &mut CoreInner,
        id: u64,
        outcome: ReinjectOutcome,
        bytes_written: u32,
    ) -> bool {
        Self::terminalize_with_reason(inner, id, outcome, bytes_written, 0)
    }

    fn terminalize_with_reason(
        inner: &mut CoreInner,
        id: u64,
        outcome: ReinjectOutcome,
        bytes_written: u32,
        reason: u8,
    ) -> bool {
        let (flow_tag, already_terminal, provenance) = {
            let Some(entry) = inner.entries.get_mut(&id) else {
                return false;
            };
            let already = matches!(entry.state, EntryState::Terminal(_));
            let provenance = if !already {
                entry.state = EntryState::Terminal(ReinjectCompletion {
                    request_id: id,
                    permit_epoch: entry.lease.permit_epoch,
                    queue_epoch: entry.lease.queue_epoch,
                    queue_number: entry.lease.queue_number,
                    family: entry.origin.family,
                    hook: entry.origin.hook,
                    owned_ifindex: entry.origin.owned_ifindex,
                    outcome,
                    bytes_written,
                    flow_tag: entry.flow_tag,
                });
                Some(ReinjectProvenanceRow {
                    request_id: id,
                    permit_epoch: entry.lease.permit_epoch,
                    queue_epoch: entry.lease.queue_epoch,
                    queue_number: entry.lease.queue_number,
                    family: entry.origin.family,
                    hook: entry.origin.hook,
                    owned_ifindex: entry.origin.owned_ifindex,
                    owner: entry.origin.owner.clone(),
                    stn: entry.origin.stn.clone(),
                    outcome: outcome.as_str().to_string(),
                    bytes_written,
                    frame_digest: entry.frame_digest,
                    reason,
                })
            } else {
                None
            };
            (entry.flow_tag, already, provenance)
        };
        if already_terminal {
            Self::remember_terminal_tombstone(inner, id);
            return false;
        }
        Self::remember_terminal_tombstone(inner, id);
        if let Some(row) = provenance {
            inner.provenance.push_back(row);
            while inner.provenance.len() > PROVENANCE_MAX {
                inner.provenance.pop_front();
            }
        }
        let _ = flow_tag;
        inner.ready_count += 1;
        match outcome {
            ReinjectOutcome::Written => inner.stats.completed_written += 1,
            ReinjectOutcome::Stale => inner.stats.completed_stale += 1,
            ReinjectOutcome::Cancelled => inner.stats.completed_cancelled += 1,
            ReinjectOutcome::Refused
            | ReinjectOutcome::Fenced
            | ReinjectOutcome::Denied
            | ReinjectOutcome::Accepted
            | ReinjectOutcome::WouldReinject
            | ReinjectOutcome::WouldPermit => inner.stats.completed_refused += 1,
            ReinjectOutcome::Uncertain => inner.stats.completed_uncertain += 1,
        }
        true
    }

    fn record_admission(stats: &mut ReinjectStats, class: AdmissionClass) {
        match class {
            AdmissionClass::Adjudicated => stats.adjudicated_admitted += 1,
            AdmissionClass::Delegated => stats.delegated_admitted += 1,
        }
    }

    fn record_refusal(stats: &mut ReinjectStats, class: AdmissionClass) {
        match class {
            AdmissionClass::Adjudicated => stats.adjudicated_refused += 1,
            AdmissionClass::Delegated => stats.delegated_refused += 1,
        }
    }
}

fn scope_matches(scope: &CancelScope, id: u64, lease: &ReinjectLease) -> bool {
    if let Some(ids) = &scope.ids {
        if !ids.contains(&id) {
            return false;
        }
    }
    if let Some(permit) = scope.permit_epoch {
        if permit != lease.permit_epoch {
            return false;
        }
    }
    if !scope.queue_epochs.is_empty()
        && !scope
            .queue_epochs
            .contains(&(lease.queue_number, lease.queue_epoch))
    {
        return false;
    }
    true
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CodecError {
    Truncated,
    TrailingBytes,
    TooManyFrames,
    FrameTooLarge,
    SlabExhausted,
    TooLarge,
    BadFlags,
    BadValue,
    Io(String),
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}
pub(crate) fn encode_submit_batch(frames: &[SubmitFrame]) -> Vec<u8> {
    assert!(frames.len() <= SUBMIT_MAX_FRAMES);
    let mut out = Vec::with_capacity(2 + frames.len() * 142);
    push_u16(&mut out, frames.len() as u16);
    for frame in frames {
        assert!(frame.bytes.len() <= SUBMIT_MAX_DATA_LEN);
        assert!(frame.origin.owner.len() <= ORIGIN_MAX_OWNER);
        assert!(frame.origin.stn.len() <= ORIGIN_MAX_STN);
        push_u64(&mut out, frame.lease.request_id);
        push_u64(&mut out, frame.lease.permit_epoch);
        push_u64(&mut out, frame.lease.queue_epoch);
        push_u16(&mut out, frame.lease.queue_number);
        push_u64(&mut out, frame.flow_tag);
        out.push(frame.flags);
        out.push(frame.origin.family);
        out.push(frame.origin.hook);
        push_u32(&mut out, frame.origin.owned_ifindex);
        out.push(frame.origin.owner.len() as u8);
        out.extend_from_slice(frame.origin.owner.as_bytes());
        out.push(frame.origin.stn.len() as u8);
        out.extend_from_slice(frame.origin.stn.as_bytes());
        push_u32(&mut out, frame.bytes.len() as u32);
        out.extend_from_slice(&frame.bytes);
        // P-MECH advisory tail is deliberately after the packet bytes so old
        // framing cannot accidentally reinterpret a generation as payload.
        push_u64(&mut out, frame.snapshot_generation);
        push_u64(&mut out, frame.config_generation);
        push_u32(&mut out, frame.fib_generation);
        push_u16(&mut out, frame.zone_id);
        push_u32(&mut out, frame.if_id);
    }
    out
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        let end = self.pos.checked_add(n).ok_or(CodecError::Truncated)?;
        let out = self.bytes.get(self.pos..end).ok_or(CodecError::Truncated)?;
        self.pos = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(*self.take(1)?.first().unwrap())
    }

    fn u16(&mut self) -> Result<u16, CodecError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, CodecError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, CodecError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn done(&self) -> bool {
        self.pos == self.bytes.len()
    }
}

pub(crate) fn decode_submit_batch(payload: &[u8]) -> Result<Vec<SubmitFrame>, CodecError> {
    let mut c = Cursor::new(payload);
    let n = c.u16()? as usize;
    if n > SUBMIT_MAX_FRAMES {
        return Err(CodecError::TooManyFrames);
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let request_id = c.u64()?;
        let permit_epoch = c.u64()?;
        let queue_epoch = c.u64()?;
        let queue_number = c.u16()?;
        let flow_tag = c.u64()?;
        let flags = c.u8()?;
        if flags & !(SUBMIT_FLAG_SHADOW | SUBMIT_FLAG_DRY_RUN) != 0 {
            return Err(CodecError::BadFlags);
        }
        let family = c.u8()?;
        let hook = c.u8()?;
        let owned_ifindex = c.u32()?;
        let owner_len = c.u8()? as usize;
        let owner_bytes = c.take(owner_len)?;
        let stn_len = c.u8()? as usize;
        let stn_bytes = c.take(stn_len)?;
        let owner_valid_utf8 = std::str::from_utf8(owner_bytes).is_ok();
        let stn_valid_utf8 = std::str::from_utf8(stn_bytes).is_ok();
        let valid = owned_ifindex != 0
            && owner_len != 0
            && stn_len != 0
            && owner_len <= ORIGIN_MAX_OWNER
            && stn_len <= ORIGIN_MAX_STN
            && owner_valid_utf8
            && stn_valid_utf8
            && (family == ORIGIN_INET || family == ORIGIN_BRIDGE)
            && (hook == ORIGIN_FORWARD || hook == ORIGIN_INPUT);
        let data_len = c.u32()? as usize;
        if data_len > SUBMIT_MAX_DATA_LEN {
            return Err(CodecError::FrameTooLarge);
        }
        let bytes = c.take(data_len)?.to_vec();
        let snapshot_generation = c.u64()?;
        let config_generation = c.u64()?;
        let fib_generation = c.u32()?;
        let zone_id = c.u16()?;
        let if_id = c.u32()?;
        out.push(SubmitFrame {
            lease: ReinjectLease {
                permit_epoch,
                queue_epoch,
                queue_number,
                request_id,
            },
            flow_tag,
            flags,
            origin: CaptureOrigin {
                family,
                hook,
                owned_ifindex,
                owner: String::from_utf8_lossy(owner_bytes).into_owned(),
                stn: String::from_utf8_lossy(stn_bytes).into_owned(),
                valid,
            },
            bytes,
            snapshot_generation,
            config_generation,
            fib_generation,
            zone_id,
            if_id,
        });
    }
    if !c.done() {
        return Err(CodecError::TrailingBytes);
    }
    Ok(out)
}

/// A submit row whose packet bytes are already owned by a D11 slab.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PooledSubmitFrame {
    pub lease: ReinjectLease,
    pub flow_tag: u64,
    pub flags: u8,
    pub origin: CaptureOrigin,
    pub slab_id: u32,
    pub bytes_len: u32,
    pub snapshot_generation: u64,
    pub config_generation: u64,
    pub fib_generation: u32,
    pub zone_id: u16,
    pub if_id: u32,
}

/// Decode a P-MECH batch directly into preallocated D11 slabs. This is the
/// worker handoff path; unlike `decode_submit_batch`, it never materializes a
/// `Vec<u8>` and then copies it into a slab.
pub(crate) fn decode_submit_batch_into_pool(
    payload: &[u8],
    pool: &IpsecInnerSlabPool,
) -> Result<Vec<PooledSubmitFrame>, CodecError> {
    let mut c = Cursor::new(payload);
    let n = c.u16()? as usize;
    if n > SUBMIT_MAX_FRAMES {
        return Err(CodecError::TooManyFrames);
    }
    let mut out = Vec::with_capacity(n);
    let result = (|| {
        for _ in 0..n {
            let request_id = c.u64()?;
            let permit_epoch = c.u64()?;
            let queue_epoch = c.u64()?;
            let queue_number = c.u16()?;
            let flow_tag = c.u64()?;
            let flags = c.u8()?;
            if flags & !(SUBMIT_FLAG_SHADOW | SUBMIT_FLAG_DRY_RUN) != 0 {
                return Err(CodecError::BadFlags);
            }
            let family = c.u8()?;
            let hook = c.u8()?;
            let owned_ifindex = c.u32()?;
            let owner_len = c.u8()? as usize;
            let owner_bytes = c.take(owner_len)?;
            let stn_len = c.u8()? as usize;
            let stn_bytes = c.take(stn_len)?;
            let data_len = c.u32()? as usize;
            if data_len > SUBMIT_MAX_DATA_LEN || data_len > IPSEC_INNER_SLAB_BYTES {
                return Err(CodecError::FrameTooLarge);
            }
            let bytes = c.take(data_len)?;
            let snapshot_generation = c.u64()?;
            let config_generation = c.u64()?;
            let fib_generation = c.u32()?;
            let zone_id = c.u16()?;
            let if_id = c.u32()?;
            let owner_valid_utf8 = std::str::from_utf8(owner_bytes).is_ok();
            let stn_valid_utf8 = std::str::from_utf8(stn_bytes).is_ok();
            let valid = owned_ifindex != 0
                && owner_len != 0
                && stn_len != 0
                && owner_len <= ORIGIN_MAX_OWNER
                && stn_len <= ORIGIN_MAX_STN
                && owner_valid_utf8
                && stn_valid_utf8
                && (family == ORIGIN_INET || family == ORIGIN_BRIDGE)
                && (hook == ORIGIN_FORWARD || hook == ORIGIN_INPUT);
            let Some(slab_id) = pool.acquire() else {
                return Err(CodecError::SlabExhausted);
            };
            let Some(mut slab) = pool.try_buffer(slab_id) else {
                pool.force_release(slab_id);
                return Err(CodecError::SlabExhausted);
            };
            slab.clear();
            slab.extend_from_slice(bytes);
            out.push(PooledSubmitFrame {
                lease: ReinjectLease {
                    permit_epoch,
                    queue_epoch,
                    queue_number,
                    request_id,
                },
                flow_tag,
                flags,
                origin: CaptureOrigin {
                    family,
                    hook,
                    owned_ifindex,
                    owner: String::from_utf8_lossy(owner_bytes).into_owned(),
                    stn: String::from_utf8_lossy(stn_bytes).into_owned(),
                    valid,
                },
                slab_id,
                bytes_len: data_len as u32,
                snapshot_generation,
                config_generation,
                fib_generation,
                zone_id,
                if_id,
            });
        }
        if !c.done() {
            return Err(CodecError::TrailingBytes);
        }
        Ok(())
    })();
    if let Err(err) = result {
        for frame in out.drain(..) {
            pool.force_release(frame.slab_id);
        }
        return Err(err);
    }
    Ok(out)
}

pub(crate) fn encode_cancel(scope: &CancelScope) -> Vec<u8> {
    let mut flags = 0;
    if scope.ids.as_ref().is_some_and(|ids| !ids.is_empty()) {
        flags |= CANCEL_IDS;
    }
    if scope.permit_epoch.is_some() {
        flags |= CANCEL_PERMIT_SCOPE;
    }
    if !scope.queue_epochs.is_empty() {
        flags |= CANCEL_QUEUE_SCOPE;
    }
    let mut out = vec![flags];
    if flags & CANCEL_IDS != 0 {
        let ids = scope.ids.as_ref().unwrap();
        assert!(ids.len() <= u16::MAX as usize);
        push_u16(&mut out, ids.len() as u16);
        for id in ids {
            push_u64(&mut out, *id);
        }
    }
    if flags & CANCEL_PERMIT_SCOPE != 0 {
        push_u64(&mut out, scope.permit_epoch.unwrap());
    }
    if flags & CANCEL_QUEUE_SCOPE != 0 {
        assert!(scope.queue_epochs.len() <= u16::MAX as usize);
        push_u16(&mut out, scope.queue_epochs.len() as u16);
        for (queue_number, queue_epoch) in &scope.queue_epochs {
            push_u16(&mut out, *queue_number);
            push_u64(&mut out, *queue_epoch);
        }
    }
    out
}

pub(crate) fn decode_cancel(payload: &[u8]) -> Result<CancelScope, CodecError> {
    let mut c = Cursor::new(payload);
    let flags = c.u8()?;
    if flags & !(CANCEL_IDS | CANCEL_PERMIT_SCOPE | CANCEL_QUEUE_SCOPE) != 0 {
        return Err(CodecError::BadFlags);
    }
    let ids = if flags & CANCEL_IDS != 0 {
        let n = c.u16()? as usize;
        let mut ids = Vec::with_capacity(n);
        for _ in 0..n {
            ids.push(c.u64()?);
        }
        Some(ids)
    } else {
        None
    };
    let permit_epoch = if flags & CANCEL_PERMIT_SCOPE != 0 {
        Some(c.u64()?)
    } else {
        None
    };
    let queue_epochs = if flags & CANCEL_QUEUE_SCOPE != 0 {
        let n = c.u16()? as usize;
        let mut pairs = Vec::with_capacity(n);
        for _ in 0..n {
            pairs.push((c.u16()?, c.u64()?));
        }
        pairs
    } else {
        Vec::new()
    };
    if !c.done() {
        return Err(CodecError::TrailingBytes);
    }
    Ok(CancelScope {
        ids,
        permit_epoch,
        queue_epochs,
    })
}

pub(crate) fn encode_announce(announcement: &AuthorityAnnouncement) -> Vec<u8> {
    assert!(!announcement.run_id.is_empty());
    assert!(announcement.run_id.len() <= RUN_ID_MAX);
    assert!(announcement.generation != 0);
    assert!(announcement.queue_epochs.len() <= ANNOUNCE_MAX_QUEUES);
    let mut out = Vec::with_capacity(
        1 + announcement.run_id.len() + 19 + announcement.queue_epochs.len() * 10,
    );
    out.push(announcement.run_id.len() as u8);
    out.extend_from_slice(announcement.run_id.as_bytes());
    push_u64(&mut out, announcement.generation);
    push_u64(&mut out, announcement.permit_epoch);
    out.push(u8::from(announcement.permit_open));
    push_u16(&mut out, announcement.queue_epochs.len() as u16);
    for &(queue_number, queue_epoch) in &announcement.queue_epochs {
        assert!(queue_number != 0);
        assert!(queue_epoch != 0);
        push_u16(&mut out, queue_number);
        push_u64(&mut out, queue_epoch);
    }
    out
}

pub(crate) fn decode_announce(payload: &[u8]) -> Result<AuthorityAnnouncement, CodecError> {
    let mut c = Cursor::new(payload);
    let run_id_len = c.u8()? as usize;
    if run_id_len == 0 || run_id_len > RUN_ID_MAX {
        return Err(CodecError::BadValue);
    }
    let run_id =
        String::from_utf8(c.take(run_id_len)?.to_vec()).map_err(|_| CodecError::BadValue)?;
    let generation = c.u64()?;
    if generation == 0 {
        return Err(CodecError::BadValue);
    }
    let permit_epoch = c.u64()?;
    let permit_open = match c.u8()? {
        0 => false,
        1 => true,
        _ => return Err(CodecError::BadValue),
    };
    let n = c.u16()? as usize;
    if n > ANNOUNCE_MAX_QUEUES {
        return Err(CodecError::TooManyFrames);
    }
    let mut queue_epochs = Vec::with_capacity(n);
    let mut seen = BTreeSet::new();
    for _ in 0..n {
        let queue_number = c.u16()?;
        let queue_epoch = c.u64()?;
        if queue_number == 0 || queue_epoch == 0 || !seen.insert(queue_number) {
            return Err(CodecError::BadValue);
        }
        queue_epochs.push((queue_number, queue_epoch));
    }
    if !c.done() {
        return Err(CodecError::TrailingBytes);
    }
    Ok(AuthorityAnnouncement {
        run_id,
        generation,
        permit_epoch,
        permit_open,
        queue_epochs,
    })
}
pub(crate) fn encode_admit(decisions: &[AdmitDecision]) -> Vec<u8> {
    assert!(decisions.len() <= SUBMIT_MAX_FRAMES);
    let mut out = Vec::with_capacity(2 + decisions.len() * 32);
    push_u16(&mut out, decisions.len() as u16);
    for decision in decisions {
        push_u64(&mut out, decision.request_id);
        push_u64(&mut out, decision.permit_epoch);
        push_u64(&mut out, decision.queue_epoch);
        push_u16(&mut out, decision.queue_number);
        out.push(decision.family);
        out.push(decision.hook);
        push_u32(&mut out, decision.owned_ifindex);
        out.push(u8::from(decision.admitted));
        out.push(decision.reason);
    }
    out
}

pub(crate) fn decode_admit(payload: &[u8]) -> Result<Vec<AdmitDecision>, CodecError> {
    let mut c = Cursor::new(payload);
    let n = c.u16()? as usize;
    if n > SUBMIT_MAX_FRAMES {
        return Err(CodecError::TooManyFrames);
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let request_id = c.u64()?;
        let permit_epoch = c.u64()?;
        let queue_epoch = c.u64()?;
        let queue_number = c.u16()?;
        let family = c.u8()?;
        let hook = c.u8()?;
        let owned_ifindex = c.u32()?;
        let admitted = match c.u8()? {
            0 => false,
            1 => true,
            _ => return Err(CodecError::BadValue),
        };
        let reason = c.u8()?;
        if !admit_reason_valid(reason) {
            return Err(CodecError::BadValue);
        }
        out.push(AdmitDecision {
            request_id,
            permit_epoch,
            queue_epoch,
            queue_number,
            family,
            hook,
            owned_ifindex,
            admitted,
            reason,
        });
    }
    if !c.done() {
        return Err(CodecError::TrailingBytes);
    }
    Ok(out)
}

pub(crate) fn encode_complete(completions: &[ReinjectCompletion]) -> Vec<u8> {
    assert!(completions.len() <= SUBMIT_MAX_FRAMES);
    let mut out = Vec::with_capacity(2 + completions.len() * 35);
    push_u16(&mut out, completions.len() as u16);
    for completion in completions {
        push_u64(&mut out, completion.request_id);
        push_u64(&mut out, completion.permit_epoch);
        push_u64(&mut out, completion.queue_epoch);
        push_u16(&mut out, completion.queue_number);
        out.push(completion.family);
        out.push(completion.hook);
        push_u32(&mut out, completion.owned_ifindex);
        out.push(completion.outcome.wire());
        push_u32(&mut out, completion.bytes_written);
    }
    out
}

pub(crate) fn decode_complete(payload: &[u8]) -> Result<Vec<ReinjectCompletion>, CodecError> {
    let mut c = Cursor::new(payload);
    let n = c.u16()? as usize;
    if n > SUBMIT_MAX_FRAMES {
        return Err(CodecError::TooManyFrames);
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let request_id = c.u64()?;
        let permit_epoch = c.u64()?;
        let queue_epoch = c.u64()?;
        let queue_number = c.u16()?;
        let family = c.u8()?;
        let hook = c.u8()?;
        let owned_ifindex = c.u32()?;
        let outcome = ReinjectOutcome::from_wire(c.u8()?).ok_or(CodecError::BadValue)?;
        let bytes_written = c.u32()?;
        out.push(ReinjectCompletion {
            request_id,
            permit_epoch,
            queue_epoch,
            queue_number,
            family,
            hook,
            owned_ifindex,
            outcome,
            bytes_written,
            flow_tag: 0,
        });
    }
    if !c.done() {
        return Err(CodecError::TrailingBytes);
    }
    Ok(out)
}

pub(crate) fn encode_message(message_type: u8, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() + 1 <= REINJECT_MAX_MSG);
    let mut out = Vec::with_capacity(4 + payload.len() + 1);
    push_u32(&mut out, (payload.len() + 1) as u32);
    out.push(message_type);
    out.extend_from_slice(payload);
    out
}

pub(crate) fn read_message<R: Read>(reader: &mut R) -> Result<(u8, Vec<u8>), CodecError> {
    let mut len_bytes = [0u8; 4];
    reader
        .read_exact(&mut len_bytes)
        .map_err(|e| map_read_error(e, true))?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len == 0 {
        return Err(CodecError::Truncated);
    }
    if len > REINJECT_MAX_MSG {
        return Err(CodecError::TooLarge);
    }
    let mut body = vec![0u8; len];
    reader
        .read_exact(&mut body)
        .map_err(|e| map_read_error(e, false))?;
    let message_type = body[0];
    Ok((message_type, body[1..].to_vec()))
}

fn map_read_error(err: io::Error, header: bool) -> CodecError {
    if err.kind() == io::ErrorKind::UnexpectedEof
        || (header && err.kind() == io::ErrorKind::BrokenPipe)
    {
        CodecError::Truncated
    } else {
        CodecError::Io(err.to_string())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct LeasedWriteOutcome {
    pub verdict: TransferVerdict,
    pub ok: bool,
    pub ring_terminal: bool,
    pub demotion_cause: Option<String>,
}

/// Map the existing io_uring Done/NothingWritten/Transferred/Deferred
/// taxonomy to the ACK contract. Only NothingWritten invokes the sync fallback;
/// Transferred and Deferred are ambiguous and are never retried.
pub(crate) fn classify_leased_write<F>(result: WriteResult, sync_fallback: F) -> LeasedWriteOutcome
where
    F: FnOnce(Vec<u8>) -> TransferVerdict,
{
    match result {
        WriteResult::Done(bytes) => LeasedWriteOutcome {
            verdict: TransferVerdict::Written {
                bytes: bytes.len() as u32,
            },
            ok: true,
            ring_terminal: false,
            demotion_cause: None,
        },
        WriteResult::NothingWritten(bytes, message) => {
            let verdict = sync_fallback(bytes);
            LeasedWriteOutcome {
                ok: matches!(verdict, TransferVerdict::Written { .. }),
                verdict,
                ring_terminal: false,
                demotion_cause: None,
            }
        }
        WriteResult::Transferred(_bytes, message) => LeasedWriteOutcome {
            verdict: TransferVerdict::Uncertain { reason: message },
            ok: false,
            ring_terminal: false,
            demotion_cause: None,
        },
        WriteResult::Deferred {
            id,
            message,
            fatal_ring,
        } => {
            let reason = format!("{message} (in-flight id {id}, buffer retained)");
            let demotion_cause = fatal_ring
                .then(|| format!("slow-path io_uring ring failure, demoting to sync: {reason}"));
            LeasedWriteOutcome {
                verdict: TransferVerdict::Uncertain { reason },
                ok: false,
                ring_terminal: fatal_ring,
                demotion_cause,
            }
        }
    }
}

#[cfg(test)]
#[path = "slowpath_reinject_9506_tests.rs"]
mod tests;
