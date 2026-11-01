//! RFC 2637 PPTP control-channel parsing (#7699 stage 2, #11601 per-call teardown).
//!
//! # What this is for
//!
//! A PPTP GRE data packet carries only ONE of a call's two Call IDs — the one
//! belonging to the peer it is sent to — so the pair that identifies a call can
//! only be learned from the control channel on TCP/1723. An Outgoing-Call-Reply
//! announces both IDs, while a Call-Disconnect-Notify names the PAC-allocated
//! ID to forget; [`crate::session::pptp`] owns the direction-neutral association.
//!
//! # What this is NOT
//!
//! **Not a TCP reassembler.** There is no reassembly machinery in this tree and
//! stage 2 is not the place to invent one, so this parses only a control
//! message wholly contained in the segment it is given and reports
//! [`ControlParse::Truncated`] otherwise. That is a designed degradation, not a
//! defaulted one: a truncated message means *no association learned*, which
//! routes into the unassociated path stage 1 already built — the packet
//! forwards and is counted. PPTP control messages are small (32-byte
//! Outgoing-Call-Reply and 148-byte Call-Disconnect-Notify), and a stack that
//! splits one across segments is pathological, but it must land somewhere
//! defined rather than nowhere.
//!
//! Also not: call-ID rewriting for NAT, a general ALG framework, or IPv6.
//!
//! # The inbox: how a segment gets here from the data path (#7699)
//!
//! Parsing does not run on the AF_XDP hot path. The control channel carries a
//! handful of small messages per call and the data channel does not, and
//! co-locating them buys nothing anyway because RSS hashes the flow tuple — the
//! two channels are not reliably on the same worker. Once the session/policy
//! path admits a TCP/1723 segment, the data path COPIES it into this inbox and
//! moves on; the worker's periodic work drains it, parses, learns calls, applies
//! per-call disconnects and broadcasts both changes. A denied pre-policy
//! segment never enters the inbox.
//!
//! The association is not needed for the control packet itself — it is needed
//! for the GRE data packets that follow.

use std::net::IpAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// A TCP/1723 segment copied off the hot path, waiting to be parsed (#7699).
///
/// The data path copies and moves on; it never parses. The ports ride along
/// because the association is bound to the control CHANNEL that taught it
/// ([`crate::session::pptp::ControlChannelId`]) — an association must not
/// outlive its control connection, and without the ports there is no channel
/// to bind it to. `captured_ns` preserves arrival order when a worker drains
/// after a close has already been observed.
#[derive(Clone, Debug)]
pub(crate) struct PendingControlSegment {
    /// Enable-epoch at capture (stamped by the inbox at push). Entries
    /// whose epoch is not the inbox's current epoch at drain are dropped.
    pub(crate) epoch: u64,
    pub(crate) src: IpAddr,
    pub(crate) dst: IpAddr,
    pub(crate) src_port: u16,
    pub(crate) dst_port: u16,
    pub(crate) captured_ns: u64,
    pub(crate) payload: Vec<u8>,
}

/// How many un-parsed control segments the inbox will hold.
///
/// Small on purpose. PPTP control traffic is a handful of small messages per
/// call, so a backlog past this means something is wrong rather than busy, and
/// the cost of dropping is bounded and already designed: an unlearned
/// association routes its call's data packets to the unassociated path —
/// forwarded and counted — which is the same degradation a control segment
/// arriving after its data takes.
pub(crate) const PENDING_CONTROL_CAPACITY: usize = 64;

/// #16609: hard cap on retained install retries. Without its own cap
/// this Vec grew by up to 64/s for a control channel's lifetime
/// (~230k/hour) on a permanent collision. 256 retains generous
/// headroom for genuine queue-refusal bursts while bounding
/// per-tick retry work and memory. Drop-NEWEST on overflow.
pub(crate) const MAX_PENDING_CALL_INSTALLS: usize = 256;

/// #16609: age bound on a retained install retry, equal to the
/// association idle timeout: past this age the colliding owner is
/// definitionally gone (idle-expired or forgotten).
pub(crate) const CALL_INSTALL_RETRY_TTL_NS: u64 =
    crate::session::pptp::ASSOCIATION_IDLE_TIMEOUT_NS;

/// How often the inbox is drained.
///
/// Matches `SESSION_GC_INTERVAL_NS`. The drain rides the periodic work the
/// worker already does rather than adding a thread or a channel, which is the
/// whole reason this shape was chosen — so an association can land up to one
/// interval after its control exchange, and the first ~1s of that call's GRE
/// data forwards unassociated.
pub(crate) const CONTROL_DRAIN_INTERVAL_NS: u64 = 1_000_000_000;

/// #16240: lock-free last-drain mirror. Each `take_*` first loads the
/// matching atomic; inside the interval it returns without touching the
/// inbox mutex (4 acquisitions/worker/tick -> one atomic load each). The
/// in-lock timestamp stays authoritative: the mirror is only ever written
/// while holding the lock, at the same instant the guarded timestamp is
/// set (take_*) or hypothetically cleared (mark_*_sent), so a stale
/// mirror can only cause a spurious lock acquisition, never a skipped
/// due drain. If a future change clears/resets a guarded timestamp
/// under the lock, it MUST store the same value to the mirror there.
fn gate_closed(mirror: &AtomicU64, now_ns: u64) -> bool {
    let last = mirror.load(Ordering::Relaxed);
    last != 0 && now_ns.saturating_sub(last) < CONTROL_DRAIN_INTERVAL_NS
}

/// The hand-off from the data path to the periodic control-channel work.
///
/// Shared across the workers of a dataplane, like `dynamic_neighbors`, and
/// written through `&self` for the same reason: the hot-path stage that fills
/// it has no mutable state of its own to put it in. Sharing is also what makes
/// ONE drain enough — whichever worker drains installs the association in its
/// own table and broadcasts it to the rest, so a per-worker inbox would only
/// buy N duplicate parses of the same segment.
pub(crate) struct PptpControlInbox {
    inner: Mutex<InboxInner>,
    last_drain_atomic: AtomicU64,
    last_forget_retry_atomic: AtomicU64,
    last_call_forget_retry_atomic: AtomicU64,
    last_call_install_retry_atomic: AtomicU64,
    /// Test-only proof that the lock-free pre-check short-circuits (#16240).
    #[cfg(test)]
    lock_acquisitions: AtomicU64,
}

impl Default for PptpControlInbox {
    fn default() -> Self {
        Self {
            inner: Mutex::default(),
            last_drain_atomic: AtomicU64::new(0),
            last_forget_retry_atomic: AtomicU64::new(0),
            last_call_forget_retry_atomic: AtomicU64::new(0),
            last_call_install_retry_atomic: AtomicU64::new(0),
            #[cfg(test)]
            lock_acquisitions: AtomicU64::new(0),
        }
    }
}

impl PptpControlInbox {
    #[cfg(test)]
    fn lock_acquisition_count(&self) -> u64 {
        self.lock_acquisitions.load(Ordering::Relaxed)
    }

    fn lock_inner(&self) -> std::sync::MutexGuard<'_, InboxInner> {
        #[cfg(test)]
        self.lock_acquisitions.fetch_add(1, Ordering::Relaxed);
        match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

#[derive(Default)]
struct InboxInner {
    pending: Vec<(u32, PendingControlSegment)>,
    /// When [`PptpControlInbox::take_pending`] last handed the buffer out.
    last_drain_ns: u64,
    /// Segments dropped because the buffer was full.
    ///
    /// Their calls learn no association and take the unassociated path. Counted
    /// separately from the table's `unassociated` because the causes differ:
    /// this one means the drain could not keep up, the other means the data
    /// simply arrived first.
    dropped: u64,
    /// Control closes refused by full worker queues, retried by periodic drain.
    pending_forgets: Vec<PendingChannelForget>,
    last_forget_retry_ns: u64,
    /// Per-call CDN commands refused by full worker queues.
    pending_call_forgets: Vec<PendingCallForget>,
    last_call_forget_retry_ns: u64,
    /// PPTP installs refused by full worker queues or a transient
    /// local collision (#16609: capped at MAX_PENDING_CALL_INSTALLS).
    pending_call_installs: Vec<PendingCallInstall>,
    last_call_install_retry_ns: u64,
}

/// A control close still waiting for a bounded worker queue or local table.
#[derive(Clone, Debug)]
pub(crate) struct PendingChannelForget {
    pub(crate) control: crate::session::pptp::ControlChannelId,
    pub(crate) closed_ns: u64,
    pub(crate) unsent_queue_ids: Vec<usize>,
}

/// A CDN still waiting for a bounded worker queue or local table.
#[derive(Clone, Debug)]
pub(crate) struct PendingCallForget {
    pub(crate) disconnect: crate::session::pptp::PptpCallDisconnect,
    pub(crate) unsent_queue_ids: Vec<usize>,
}

/// A PPTP install still waiting for a bounded worker queue or local table.
#[derive(Clone, Debug)]
pub(crate) struct PendingCallInstall {
    pub(crate) call: crate::session::pptp::PptpCall,
    pub(crate) control: crate::session::pptp::ControlChannelId,
    pub(crate) learned_ns: u64,
    pub(crate) epoch: u64,
    pub(crate) unsent_queue_ids: Vec<usize>,
}

impl PptpControlInbox {
    /// Copy a control segment in from the data path. Never blocks on work,
    /// never parses.
    ///
    /// Returns whether it was accepted. A `false` is a DROP, counted, and its
    /// consequence is the unassociated path — not a stall and not a retry,
    /// because the data path must not wait on control-channel work.
    ///
    /// **Drop-NEWEST on full**, the policy `docs/engineering-style.md`
    /// prescribes, and the rationale holds here for its own reason as well as
    /// the general one: an older buffered segment is closer to being parsed,
    /// and evicting it to make room would lose an association that was about to
    /// be learned in favour of one that may not even be a control message.
    pub(crate) fn push(&self, seg: PendingControlSegment) -> bool {
        self.push_in_domain(0, seg)
    }

    pub(crate) fn push_in_domain(&self, routing_domain: u32, seg: PendingControlSegment) -> bool {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if inner.pending.len() >= PENDING_CONTROL_CAPACITY {
            inner.dropped = inner.dropped.saturating_add(1);
            return false;
        }
        // Epoch is publisher-stamped at capture (the view under which
        // the segment was buffered); the inbox never infers it.
        inner.pending.push((routing_domain, seg));
        true
    }

    /// Hand the buffered segments out for parsing, at most once per
    /// [`CONTROL_DRAIN_INTERVAL_NS`].
    ///
    /// **The interval gate is inside this function, deliberately.** The caller
    /// is the worker poll loop, which runs at packet rate — a drain that gated
    /// at the call site would be one edit away from running per-poll, which is
    /// exactly the defect that shipped in #8399 when the association expiry
    /// landed on the wrong side of `expire_stale_entries_ha`'s gate. Keeping
    /// the gate here makes "how often" a property of the function rather than
    /// of every caller.
    ///
    /// Returns an empty vec when gated, so a caller cannot distinguish "nothing
    /// to do" from "not yet" — which is correct: both mean do nothing.
    pub(crate) fn take_pending(&self, now_ns: u64) -> Vec<PendingControlSegment> {
        self.take_pending_in_domain(now_ns, 0)
            .into_iter()
            .map(|(_, segment)| segment)
            .collect()
    }

    pub(crate) fn take_pending_in_domain(&self, now_ns: u64, current_epoch: u64) -> Vec<(u32, PendingControlSegment)> {
        if gate_closed(&self.last_drain_atomic, now_ns) {
            return Vec::new();
        }
        let mut inner = self.lock_inner();
        if inner.last_drain_ns != 0
            && now_ns.saturating_sub(inner.last_drain_ns) < CONTROL_DRAIN_INTERVAL_NS
        {
            return Vec::new();
        }
        inner.last_drain_ns = now_ns;
        self.last_drain_atomic.store(now_ns, Ordering::Relaxed);
        // When the draining view is enabled, only entries stamped with
        // that view's exact epoch are eligible: strictly older entries
        // predate a disable/re-enable, and newer entries were captured
        // under a view this worker has not adopted yet (a stale enabled
        // view must not install them after a later publish).
        let all = std::mem::take(&mut inner.pending);
        all.into_iter().filter(|(_, seg)| seg.epoch == current_epoch).collect()
    }

    pub(crate) fn dropped_count(&self) -> u64 {
        match self.inner.lock() {
            Ok(g) => g.dropped,
            Err(poisoned) => poisoned.into_inner().dropped,
        }
    }

    pub(crate) fn pending_len(&self) -> usize {
        match self.inner.lock() {
            Ok(g) => g.pending.len(),
            Err(poisoned) => poisoned.into_inner().pending.len(),
        }
    }

    /// Observe the enabled bit at drain/poll time. On a
    /// disabled->enabled transition the epoch ADVANCES: every buffered
    /// segment/install stamped with an older epoch becomes ineligible
    /// at the next drain. Nothing is cleared here — poll-time state is
    /// never mutated destructively, so steady-enabled traffic is
    /// untouched by construction, a skipped disabled generation still
    /// advances the epoch when the enabled generation is observed, and
    /// a lagging worker cannot purge current-epoch entries (it only
    /// ever advances the epoch forward, and entries stamped after the
    /// advance carry the new epoch).
    /// #15950: drop every buffered segment (ALG disabled). Returns count.
    pub(crate) fn purge_pending(&self) -> usize {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let n = inner.pending.len();
        inner.pending.clear();
        inner.pending_call_installs.clear();
        n
    }

    /// Drop buffered segments from a control channel that has closed.
    ///
    /// A Reply may be admitted into the interval-gated inbox just before FIN
    /// or RST; purge it now so a later drain cannot resurrect the call.
    pub(crate) fn forget_channel(&self, control: crate::session::pptp::ControlChannelId) -> usize {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let before = inner.pending.len();
        inner.pending.retain(|(routing_domain, segment)| {
            crate::session::pptp::ControlChannelId::new_in_domain(
                *routing_domain,
                segment.src,
                segment.src_port,
                segment.dst,
                segment.dst_port,
            ) != control
        });
        before - inner.pending.len()
    }

    /// Remember queues that refused a close so the periodic worker drain can
    /// retry it without losing the per-recipient acknowledgement state.
    pub(crate) fn record_channel_forget(
        &self,
        control: crate::session::pptp::ControlChannelId,
        closed_ns: u64,
        unsent_queue_ids: Vec<usize>,
    ) {
        if unsent_queue_ids.is_empty() {
            return;
        }
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(existing) = inner
            .pending_forgets
            .iter_mut()
            .find(|pending| pending.control == control && pending.closed_ns == closed_ns)
        {
            for queue_id in unsent_queue_ids {
                if !existing.unsent_queue_ids.contains(&queue_id) {
                    existing.unsent_queue_ids.push(queue_id);
                }
            }
        } else {
            inner.pending_forgets.push(PendingChannelForget {
                control,
                closed_ns,
                unsent_queue_ids,
            });
        }
    }

    /// Remember queues that refused a CDN for later bounded retry.
    pub(crate) fn record_call_forget(
        &self,
        disconnect: crate::session::pptp::PptpCallDisconnect,
        unsent_queue_ids: Vec<usize>,
    ) {
        if unsent_queue_ids.is_empty() {
            return;
        }
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(existing) = inner
            .pending_call_forgets
            .iter_mut()
            .find(|pending| pending.disconnect == disconnect)
        {
            for queue_id in unsent_queue_ids {
                if !existing.unsent_queue_ids.contains(&queue_id) {
                    existing.unsent_queue_ids.push(queue_id);
                }
            }
        } else {
            inner.pending_call_forgets.push(PendingCallForget {
                disconnect,
                unsent_queue_ids,
            });
        }
    }

    /// Track the recipients still missing the latest install for this call.
    ///
    /// A later reply supersedes an older retry: the new broadcast attempted
    /// every peer, so its refused-recipient list is the authoritative set.
    pub(crate) fn record_call_install(
        &self,
        call: crate::session::pptp::PptpCall,
        control: crate::session::pptp::ControlChannelId,
        learned_ns: u64,
        unsent_queue_ids: Vec<usize>,
    ) {
        self.record_call_install_at(call, control, learned_ns, 0, unsent_queue_ids);
    }
    pub(crate) fn record_call_install_at(
        &self,
        call: crate::session::pptp::PptpCall,
        control: crate::session::pptp::ControlChannelId,
        learned_ns: u64,
        epoch: u64,
        unsent_queue_ids: Vec<usize>,
    ) {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(index) = inner
            .pending_call_installs
            .iter()
            .position(|pending| pending.call == call && pending.control == control)
        {
            if inner.pending_call_installs[index].learned_ns > learned_ns {
                return;
            }
            if unsent_queue_ids.is_empty() {
                inner.pending_call_installs.remove(index);
            } else {
                let pending = &mut inner.pending_call_installs[index];
                pending.learned_ns = learned_ns;
                pending.epoch = epoch;
                pending.unsent_queue_ids = unsent_queue_ids;
            }
        } else if !unsent_queue_ids.is_empty() {
            // #16609: enforce the cap BEFORE committing a new entry.
            // Drop-NEWEST: retained older retries are closer to the
            // teardown/expiry that can free them.
            if inner.pending_call_installs.len() >= MAX_PENDING_CALL_INSTALLS {
                return;
            }
            inner.pending_call_installs.push(PendingCallInstall {
                call,
                control,
                learned_ns,
                epoch,
                unsent_queue_ids,
            });
        }
    }

    /// #16609: drop the retained install retry for exactly this
    /// `(call, control, learned_ns)` generation, e.g. when its local
    /// install refusal proved permanent.
    pub(crate) fn drop_call_install(
        &self,
        call: crate::session::pptp::PptpCall,
        control: crate::session::pptp::ControlChannelId,
        learned_ns: u64,
    ) {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        inner.pending_call_installs.retain(|pending| {
            pending.call != call
                || pending.control != control
                || pending.learned_ns != learned_ns
        });
    }

    /// #16609 test seam: how many install retries are retained.
    #[cfg(test)]
    pub(crate) fn pending_call_installs_len(&self) -> usize {
        match self.inner.lock() {
            Ok(g) => g.pending_call_installs.len(),
            Err(poisoned) => poisoned.into_inner().pending_call_installs.len(),
        }
    }

    /// #16609: is a CDN or channel forget that would retire an alias
    /// of `retry.call` (or its whole channel) still awaiting delivery?
    pub(crate) fn has_pending_forget_touching(
        &self,
        retry: &PendingCallInstall,
    ) -> bool {
        let inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        inner.pending_call_forgets.iter().any(|pending| {
            pending.disconnect.control == retry.control
                && retry
                    .call
                    .has_alias(pending.disconnect.allocator, pending.disconnect.call_id)
        }) || inner
            .pending_forgets
            .iter()
            .any(|pending| pending.control == retry.control)
    }

    /// #16609: is a CDN naming exactly `(allocator, call_id)` on this
    /// channel (or a channel forget for it) still awaiting delivery?
    pub(crate) fn has_pending_forget_for_alias(
        &self,
        control: crate::session::pptp::ControlChannelId,
        allocator: std::net::IpAddr,
        call_id: u16,
    ) -> bool {
        let inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        inner.pending_call_forgets.iter().any(|pending| {
            pending.disconnect.control == control
                && pending.disconnect.allocator == allocator
                && pending.disconnect.call_id == call_id
        }) || inner
            .pending_forgets
            .iter()
            .any(|pending| pending.control == control)
    }

    /// Forget install retries superseded by a complete broadcast.
    pub(crate) fn complete_call_install_broadcast(
        &self,
        call: crate::session::pptp::PptpCall,
        control: crate::session::pptp::ControlChannelId,
        learned_ns: u64,
    ) {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        inner.pending_call_installs.retain(|pending| {
            pending.call != call || pending.control != control || pending.learned_ns > learned_ns
        });
    }

    /// A call disconnect cancels retries for that call learned no later than
    /// the notice, so a delayed install cannot resurrect torn-down state.
    pub(crate) fn forget_call_installs_for_disconnect(
        &self,
        disconnect: crate::session::pptp::PptpCallDisconnect,
    ) {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        inner.pending_call_installs.retain(|pending| {
            pending.control != disconnect.control
                || pending.learned_ns > disconnect.disconnected_ns
                || !pending
                    .call
                    .has_alias(disconnect.allocator, disconnect.call_id)
        });
    }

    /// A control-channel close cancels retries learned no later than the close.
    pub(crate) fn forget_call_installs_for_channel(
        &self,
        control: crate::session::pptp::ControlChannelId,
        closed_ns: u64,
    ) {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        inner
            .pending_call_installs
            .retain(|pending| pending.control != control || pending.learned_ns > closed_ns);
    }

    /// Take a snapshot of due close retries. Queue locks are acquired only
    /// after this inbox lock has been released.
    pub(crate) fn take_channel_forget_retries(&self, now_ns: u64) -> Vec<PendingChannelForget> {
        if gate_closed(&self.last_forget_retry_atomic, now_ns) {
            return Vec::new();
        }
        let mut inner = self.lock_inner();
        if inner.last_forget_retry_ns != 0
            && now_ns.saturating_sub(inner.last_forget_retry_ns) < CONTROL_DRAIN_INTERVAL_NS
        {
            return Vec::new();
        }
        inner.last_forget_retry_ns = now_ns;
        self.last_forget_retry_atomic.store(now_ns, Ordering::Relaxed);
        inner.pending_forgets.clone()
    }

    /// Take due CDN retries without holding the inbox lock while workers are
    /// queued.
    pub(crate) fn take_call_forget_retries(&self, now_ns: u64) -> Vec<PendingCallForget> {
        if gate_closed(&self.last_call_forget_retry_atomic, now_ns) {
            return Vec::new();
        }
        let mut inner = self.lock_inner();
        if inner.last_call_forget_retry_ns != 0
            && now_ns.saturating_sub(inner.last_call_forget_retry_ns) < CONTROL_DRAIN_INTERVAL_NS
        {
            return Vec::new();
        }
        inner.last_call_forget_retry_ns = now_ns;
        self.last_call_forget_retry_atomic.store(now_ns, Ordering::Relaxed);
        inner.pending_call_forgets.clone()
    }

    /// Take due install retries without holding the inbox lock while workers
    /// are queued.
    pub(crate) fn take_call_install_retries(&self, now_ns: u64) -> Vec<PendingCallInstall> { self.take_call_install_retries_at(now_ns, 0) }
    pub(crate) fn take_call_install_retries_at(&self, now_ns: u64, current_epoch: u64) -> Vec<PendingCallInstall> {
        if gate_closed(&self.last_call_install_retry_atomic, now_ns) {
            return Vec::new();
        }
        let mut inner = self.lock_inner();
        if inner.last_call_install_retry_ns != 0
            && now_ns.saturating_sub(inner.last_call_install_retry_ns) < CONTROL_DRAIN_INTERVAL_NS
        {
            return Vec::new();
        }
        inner.last_call_install_retry_ns = now_ns;
        self.last_call_install_retry_atomic.store(now_ns, Ordering::Relaxed);
        // #16609: prune retries past their age bound while the lock
        // is held, so an expired retry is neither cloned out nor
        // re-attempted (and its refusal never re-counted).
        inner.pending_call_installs.retain(|pending| {
            now_ns.saturating_sub(pending.learned_ns) <= CALL_INSTALL_RETRY_TTL_NS
        });
        inner
            .pending_call_installs
            .iter()
            .filter(|pending| pending.epoch == current_epoch)
            .cloned()
            .collect()
    }

    /// Acknowledge a close delivered to its queue or applied to its local table.
    pub(crate) fn mark_channel_forget_sent(
        &self,
        control: crate::session::pptp::ControlChannelId,
        closed_ns: u64,
        queue_id: usize,
    ) {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        inner.pending_forgets.retain_mut(|pending| {
            if pending.control == control && pending.closed_ns == closed_ns {
                pending.unsent_queue_ids.retain(|id| *id != queue_id);
            }
            !pending.unsent_queue_ids.is_empty()
        });
    }

    /// Acknowledge a CDN delivered to its queue or applied to its local table.
    pub(crate) fn mark_call_forget_sent(
        &self,
        disconnect: crate::session::pptp::PptpCallDisconnect,
        queue_id: usize,
    ) {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        inner.pending_call_forgets.retain_mut(|pending| {
            if pending.disconnect == disconnect {
                pending.unsent_queue_ids.retain(|id| *id != queue_id);
            }
            !pending.unsent_queue_ids.is_empty()
        });
    }

    /// Acknowledge an install delivered to its queue or applied to its local table.
    pub(crate) fn mark_call_install_sent(
        &self,
        call: crate::session::pptp::PptpCall,
        control: crate::session::pptp::ControlChannelId,
        learned_ns: u64,
        queue_id: usize,
    ) {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        inner.pending_call_installs.retain_mut(|pending| {
            if pending.call == call
                && pending.control == control
                && pending.learned_ns == learned_ns
            {
                pending.unsent_queue_ids.retain(|id| *id != queue_id);
            }
            !pending.unsent_queue_ids.is_empty()
        });
    }
}

/// The TCP port RFC 2637 assigns the PPTP control connection.
pub(crate) const PPTP_CONTROL_PORT: u16 = 1723;

/// RFC 2637 §2.1 control-message header, before any message-specific body.
///
/// `Length(2) | PPTP Message Type(2) | Magic Cookie(4) | Control Message
/// Type(2) | Reserved0(2)`.
const CONTROL_HEADER_LEN: usize = 12;
/// RFC 2637 §2.1: distinguishes a control message and lets a receiver confirm
/// it is still synchronised with the stream. Required, because it is the only
/// cheap check that these bytes are PPTP at all.
const MAGIC_COOKIE: u32 = 0x1A2B_3C4D;
/// RFC 2637 §2.1 PPTP Message Type 1 — Control Message.
const MSG_TYPE_CONTROL: u16 = 1;
/// RFC 2637 §2.8 Control Message Type 8 — Outgoing-Call-Reply.
///
/// The reply is the ONLY message carrying both halves of the pair: its `Call
/// ID` is the sender's own, and `Peer's Call ID` echoes the requester's. An
/// Outgoing-Call-Request alone names one side and cannot pair a call.
const CTRL_OUTGOING_CALL_REPLY: u16 = 8;
/// RFC 2637 §2.10 Control Message Type 10 — Incoming-Call-Reply (PAC-initiated
/// calls; mirror of §2.8 with the same Call ID / Peer's Call ID / Result
/// offsets, total length 24).
const CTRL_INCOMING_CALL_REPLY: u16 = 10;
/// RFC 2637 §2.12 Control Message Type 12 — Call-Clear-Request (Call ID only).
const CTRL_CALL_CLEAR_REQUEST: u16 = 12;
/// RFC 2637 §2.3/§2.4 Control Message Types 3/4 — Stop-Control-Connection.
const CTRL_STOP_CONTROL_REQUEST: u16 = 3;
const CTRL_STOP_CONTROL_REPLY: u16 = 4;
/// RFC 2637 §2.13 Control Message Type 13 — Call-Disconnect-Notify.
const CTRL_CALL_DISCONNECT_NOTIFY: u16 = 13;
/// Total length of a Call-Disconnect-Notify, including its 12-byte header and
/// 128-byte Call Statistics field (RFC 2637 §2.13).
const CALL_DISCONNECT_NOTIFY_LEN: usize = 148;
/// Total length of an Outgoing-Call-Reply, header included (RFC 2637 §2.8).
const OUTGOING_CALL_REPLY_LEN: usize = 32;
/// Total length of an Incoming-Call-Reply, header included (RFC 2637 §2.10).
const INCOMING_CALL_REPLY_LEN: usize = 24;
/// Total length of a Call-Clear-Request, header included (RFC 2637 §2.12).
const CALL_CLEAR_REQUEST_LEN: usize = 16;
/// Minimum lengths of Stop-Control-Connection Request/Reply (§2.3/§2.4).
const STOP_CONTROL_REQUEST_LEN: usize = 16;
const STOP_CONTROL_REPLY_LEN: usize = 16;
/// RFC 2637 §2.8 Result Code 1 — Connected. Any other value is a call that did
/// NOT come up, and learning an association for it would install state for a
/// call that does not exist.
const RESULT_CONNECTED: u8 = 1;

/// What a control-channel segment yielded.
///
/// Five outcomes rather than `Option`, because the reasons are operationally
/// different and two of them are not errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ControlParse {
    /// A complete, successful Outgoing/Incoming-Call-Reply naming both ids.
    ///
    /// `call_id` belongs to the SENDER of this segment; `peer_call_id` to its
    /// destination. That asymmetry is the whole reason the pair must be learned
    /// here rather than derived from a data packet.
    CallReply { call_id: u16, peer_call_id: u16 },
    /// A complete Call-Disconnect-Notify naming the PAC-allocated call id.
    CallDisconnect { call_id: u16 },
    /// A complete Call-Clear-Request naming the call id to forget (§2.12).
    CallClear { call_id: u16 },
    /// A Stop-Control-Connection Request, or a successful Reply:
    /// tear down the whole channel. A Reply with Result != 1 (not
    /// closed, RFC 2637 §2.4) parses as Ignored and tears nothing down.
    StopControl,
    /// A well-formed control message this stage does not learn from — a
    /// different message type, or a reply whose Result Code says the call did
    /// not connect.
    Ignored,
    /// The message did not fit in this segment.
    ///
    /// Deliberately distinct from [`Self::Ignored`]: nothing is wrong with the
    /// stream, this parser simply does not reassemble. It routes to the
    /// unassociated path, and it is counted separately so "we are not
    /// reassembling" never looks like "there was no call".
    Truncated,
    /// Not a PPTP control message: too short for a header, wrong magic cookie,
    /// or not PPTP Message Type 1.
    NotControl,
}

/// Parse one TCP/1723 segment payload.
///
/// Takes the segment's bytes as given. Every read is bounds-checked against the
/// slice rather than against the declared `Length`, because the declared length
/// is attacker-controlled — a hostile peer that claims 32 bytes and sends 8
/// must yield `Truncated`, not an out-of-bounds read.
pub(crate) fn parse_control_segment(payload: &[u8]) -> ControlParse {
    if payload.len() < CONTROL_HEADER_LEN {
        return ControlParse::NotControl;
    }
    let declared_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    let msg_type = u16::from_be_bytes([payload[2], payload[3]]);
    let cookie = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    if cookie != MAGIC_COOKIE || msg_type != MSG_TYPE_CONTROL {
        return ControlParse::NotControl;
    }
    let ctrl_type = u16::from_be_bytes([payload[8], payload[9]]);
    if ctrl_type == CTRL_CALL_DISCONNECT_NOTIFY {
        if declared_len != CALL_DISCONNECT_NOTIFY_LEN {
            return ControlParse::Ignored;
        }
        if payload.len() < CALL_DISCONNECT_NOTIFY_LEN {
            return ControlParse::Truncated;
        }
        let call_id = u16::from_be_bytes([payload[12], payload[13]]);
        return ControlParse::CallDisconnect { call_id };
    }
    if ctrl_type == CTRL_CALL_CLEAR_REQUEST {
        if declared_len != CALL_CLEAR_REQUEST_LEN {
            return ControlParse::Ignored;
        }
        if payload.len() < CALL_CLEAR_REQUEST_LEN {
            return ControlParse::Truncated;
        }
        let call_id = u16::from_be_bytes([payload[12], payload[13]]);
        return ControlParse::CallClear { call_id };
    }
    if ctrl_type == CTRL_STOP_CONTROL_REQUEST || ctrl_type == CTRL_STOP_CONTROL_REPLY {
        let want = if ctrl_type == CTRL_STOP_CONTROL_REQUEST {
            STOP_CONTROL_REQUEST_LEN
        } else {
            STOP_CONTROL_REPLY_LEN
        };
        if declared_len < want {
            return ControlParse::Ignored;
        }
        if payload.len() < want {
            return ControlParse::Truncated;
        }
        if ctrl_type == CTRL_STOP_CONTROL_REPLY && payload[12] != RESULT_CONNECTED {
            // RFC 2637 §2.4 Result 2 = general error, connection NOT closed.
            return ControlParse::Ignored;
        }
        return ControlParse::StopControl;
    }
    let want_len = match ctrl_type {
        CTRL_OUTGOING_CALL_REPLY => OUTGOING_CALL_REPLY_LEN,
        CTRL_INCOMING_CALL_REPLY => INCOMING_CALL_REPLY_LEN,
        _ => return ControlParse::Ignored,
    };
    if declared_len != want_len {
        return ControlParse::Ignored;
    }
    if payload.len() < want_len {
        return ControlParse::Truncated;
    }
    let call_id = u16::from_be_bytes([payload[12], payload[13]]);
    let peer_call_id = u16::from_be_bytes([payload[14], payload[15]]);
    if payload[16] != RESULT_CONNECTED {
        return ControlParse::Ignored;
    }
    ControlParse::CallReply {
        call_id,
        peer_call_id,
    }
}

/// Turn a control segment into the association it announces.
///
/// `src`/`dst` are the segment's own addresses. The mapping is the load-bearing
/// part: an Outgoing-Call-Reply's `Call ID` is the SENDER's, and `Peer's Call
/// ID` is the destination's. Getting it backwards would build an association
/// that resolves both directions to a handle no data packet can produce, which
/// is indistinguishable from not learning at all until a reply goes unmatched.
pub(crate) fn learn_from_control_segment(
    src: std::net::IpAddr,
    dst: std::net::IpAddr,
    payload: &[u8],
) -> Option<crate::session::pptp::PptpCall> {
    learn_from_control_segment_in_domain(0, src, dst, payload)
}

pub(crate) fn learn_from_control_segment_in_domain(
    routing_domain: u32,
    src: std::net::IpAddr,
    dst: std::net::IpAddr,
    payload: &[u8],
) -> Option<crate::session::pptp::PptpCall> {
    match parse_control_segment(payload) {
        ControlParse::CallReply {
            call_id,
            peer_call_id,
        } => Some(crate::session::pptp::PptpCall::new_in_domain(
            routing_domain,
            src,
            call_id,
            dst,
            peer_call_id,
        )),
        ControlParse::CallDisconnect { .. }
        | ControlParse::CallClear { .. }
        | ControlParse::StopControl
        | ControlParse::Ignored
        | ControlParse::Truncated
        | ControlParse::NotControl => None,
    }
}

#[cfg(test)]
pub(crate) mod fixtures_7699 {
    use super::*;

    /// Build an Outgoing-Call-Reply exactly as RFC 2637 §2.8 lays it out.
    ///
    /// Written from the field layout rather than captured, so the offsets this
    /// parser reads are asserted against the RFC's structure and not against
    /// whatever the parser happens to do.
    pub(crate) fn outgoing_call_reply(call_id: u16, peer_call_id: u16, result: u8) -> Vec<u8> {
        let mut m = Vec::with_capacity(OUTGOING_CALL_REPLY_LEN);
        m.extend_from_slice(&(OUTGOING_CALL_REPLY_LEN as u16).to_be_bytes()); // Length
        m.extend_from_slice(&MSG_TYPE_CONTROL.to_be_bytes()); // PPTP Message Type
        m.extend_from_slice(&MAGIC_COOKIE.to_be_bytes()); // Magic Cookie
        m.extend_from_slice(&CTRL_OUTGOING_CALL_REPLY.to_be_bytes()); // Control Message Type
        m.extend_from_slice(&0u16.to_be_bytes()); // Reserved0
        m.extend_from_slice(&call_id.to_be_bytes()); // Call ID (sender's)
        m.extend_from_slice(&peer_call_id.to_be_bytes()); // Peer's Call ID
        m.push(result); // Result Code
        m.push(0); // Error Code
        m.extend_from_slice(&0u16.to_be_bytes()); // Cause Code
        m.extend_from_slice(&0u32.to_be_bytes()); // Connect Speed
        m.extend_from_slice(&0u16.to_be_bytes()); // Recv Window Size
        m.extend_from_slice(&0u16.to_be_bytes()); // Processing Delay
        m.extend_from_slice(&0u32.to_be_bytes()); // Physical Channel ID
        assert_eq!(
            m.len(),
            OUTGOING_CALL_REPLY_LEN,
            "fixture must match the RFC length"
        );
        m
    }
    /// Build a Call-Disconnect-Notify exactly as RFC 2637 §2.13 lays it out.
    pub(crate) fn call_disconnect_notify(call_id: u16) -> Vec<u8> {
        let mut m = Vec::with_capacity(CALL_DISCONNECT_NOTIFY_LEN);
        m.extend_from_slice(&(CALL_DISCONNECT_NOTIFY_LEN as u16).to_be_bytes()); // Length
        m.extend_from_slice(&MSG_TYPE_CONTROL.to_be_bytes()); // PPTP Message Type
        m.extend_from_slice(&MAGIC_COOKIE.to_be_bytes()); // Magic Cookie
        m.extend_from_slice(&CTRL_CALL_DISCONNECT_NOTIFY.to_be_bytes()); // Control Message Type
        m.extend_from_slice(&0u16.to_be_bytes()); // Reserved0
        m.extend_from_slice(&call_id.to_be_bytes()); // PAC-assigned Call ID
        m.push(1); // Result Code
        m.push(0); // Error Code
        m.extend_from_slice(&0u16.to_be_bytes()); // Cause Code
        m.extend_from_slice(&0u16.to_be_bytes()); // Reserved1
        m.extend_from_slice(&[0; 128]); // Call Statistics
        assert_eq!(
            m.len(),
            CALL_DISCONNECT_NOTIFY_LEN,
            "fixture must match the RFC length"
        );
        m
    }
}

#[cfg(test)]
mod tests_7699 {
    use super::fixtures_7699::call_disconnect_notify;
    use super::fixtures_7699::outgoing_call_reply;
    use super::*;

    fn ip(s: &str) -> std::net::IpAddr {
        s.parse().unwrap()
    }

    /// The pair comes out, and each call id is attributed to the RIGHT peer.
    ///
    /// The attribution is asserted through `resolve`, not by reading the struct:
    /// a data packet is keyed on its DESTINATION, so this is the property the
    /// dataplane actually depends on. Reading the fields back would pass with
    /// the two ids swapped.
    #[test]
    fn a_call_reply_yields_the_pair_attributed_to_the_right_peers_7699() {
        let (s, d) = (ip("198.51.100.7"), ip("203.0.113.9"));
        let msg = outgoing_call_reply(0xAAAA, 0xBBBB, RESULT_CONNECTED);
        let call = learn_from_control_segment(s, d, &msg).expect("a connected reply must learn");

        let mut table = crate::session::pptp::PptpAssociations::default();
        let handle = table
            .install(
                call,
                crate::session::pptp::ControlChannelId::new(s, 49152, d, 1723),
                0,
            )
            .expect("install");
        assert_eq!(
            table.resolve(s, 0xAAAA),
            Some(handle),
            "the reply's own Call ID belongs to its SENDER, so a packet sent TO \\
             the sender carries it"
        );
        assert_eq!(
            table.resolve(d, 0xBBBB),
            Some(handle),
            "Peer's Call ID belongs to the DESTINATION"
        );
        assert_eq!(
            table.resolve(s, 0xBBBB),
            None,
            "the ids must not both resolve under one peer; that is the swapped \\
             attribution, which looks identical until a reply goes unmatched"
        );
    }

    /// A call that did NOT connect must not be learned.
    ///
    /// Installing an association for a failed call puts state in the table for
    /// a call that does not exist, and its 16-bit ids are then reserved against
    /// a future call that reuses them.
    #[test]
    fn a_failed_call_reply_is_not_learned_7699() {
        let (s, d) = (ip("198.51.100.7"), ip("203.0.113.9"));
        for result in [0u8, 2, 3, 7] {
            let msg = outgoing_call_reply(0xAAAA, 0xBBBB, result);
            assert_eq!(parse_control_segment(&msg), ControlParse::Ignored);
            assert!(learn_from_control_segment(s, d, &msg).is_none());
        }
        // CONTROL: the same message with Result Code 1 IS learned, so the
        // assertion above is about the result code and not about a fixture that
        // never parses.
        let ok = outgoing_call_reply(0xAAAA, 0xBBBB, RESULT_CONNECTED);
        assert!(learn_from_control_segment(s, d, &ok).is_some());
    }

    /// The single-segment bound, and its DESIGNED degradation.
    ///
    /// A split message is `Truncated`, distinct from `Ignored`: nothing is
    /// wrong with the stream, this parser simply does not reassemble. It learns
    /// nothing, so the call's data packets take the unassociated path — forward
    /// and count — rather than anything undefined.
    #[test]
    fn a_message_split_across_segments_is_truncated_not_misparsed_7699() {
        let full = outgoing_call_reply(0xAAAA, 0xBBBB, RESULT_CONNECTED);
        for cut in [12usize, 13, 16, 20, OUTGOING_CALL_REPLY_LEN - 1] {
            let partial = &full[..cut];
            assert_eq!(
                parse_control_segment(partial),
                ControlParse::Truncated,
                "a {cut}-byte prefix must report Truncated"
            );
            assert!(
                learn_from_control_segment(ip("198.51.100.7"), ip("203.0.113.9"), partial)
                    .is_none(),
                "a truncated message must learn nothing"
            );
        }
    }

    /// A DECLARED length longer than the bytes present must not read past the
    /// slice.
    ///
    /// The declared length is attacker-controlled. This is the case a parser
    /// that trusts it panics on — and a panic here is a dead AF_XDP worker.
    #[test]
    fn a_lying_declared_length_does_not_read_past_the_segment_7699() {
        let mut m = outgoing_call_reply(0xAAAA, 0xBBBB, RESULT_CONNECTED);
        m.truncate(CONTROL_HEADER_LEN + 2); // claims 32, carries 14
        assert_eq!(parse_control_segment(&m), ControlParse::Truncated);
    }

    /// Not-PPTP is rejected before any field is read by offset.
    #[test]
    fn non_pptp_bytes_are_not_control_7699() {
        assert_eq!(parse_control_segment(&[]), ControlParse::NotControl);
        assert_eq!(parse_control_segment(&[0u8; 8]), ControlParse::NotControl);

        let mut bad_cookie = outgoing_call_reply(1, 2, RESULT_CONNECTED);
        bad_cookie[4] ^= 0xFF;
        assert_eq!(parse_control_segment(&bad_cookie), ControlParse::NotControl);

        let mut bad_msg_type = outgoing_call_reply(1, 2, RESULT_CONNECTED);
        bad_msg_type[3] = 9;
        assert_eq!(
            parse_control_segment(&bad_msg_type),
            ControlParse::NotControl
        );
    }

    /// A control message of another type is Ignored, not misread.
    #[test]
    fn another_control_message_type_is_ignored_7699() {
        let mut other = outgoing_call_reply(1, 2, RESULT_CONNECTED);
        other[8..10].copy_from_slice(&7u16.to_be_bytes()); // Outgoing-Call-Request
        assert_eq!(parse_control_segment(&other), ControlParse::Ignored);
    }
    #[test]
    fn call_disconnect_notify_yields_the_pac_allocated_call_id_11601() {
        let (pac, pns) = (ip("198.51.100.7"), ip("203.0.113.9"));
        let msg = call_disconnect_notify(0xAAAA);
        assert_eq!(
            parse_control_segment(&msg),
            ControlParse::CallDisconnect { call_id: 0xAAAA }
        );
        assert!(
            learn_from_control_segment(pac, pns, &msg).is_none(),
            "a CDN removes an association; it never installs one"
        );
        let mut wrong_length = msg.clone();
        wrong_length[..2].copy_from_slice(&((CALL_DISCONNECT_NOTIFY_LEN - 1) as u16).to_be_bytes());
        assert_eq!(
            parse_control_segment(&wrong_length),
            ControlParse::Ignored,
            "only the fixed RFC 2637 CDN length is accepted"
        );
        assert_eq!(
            parse_control_segment(&msg[..CALL_DISCONNECT_NOTIFY_LEN - 1]),
            ControlParse::Truncated,
            "an incomplete statistics tail must not complete a CDN"
        );
    }
}

#[cfg(test)]
mod inbox_drop_policy_tests_7699 {
    use super::*;

    fn seg(n: u8) -> PendingControlSegment {
        PendingControlSegment { epoch: 0, src: "198.51.100.7".parse().unwrap(),
            dst: "203.0.113.9".parse().unwrap(),
            src_port: PPTP_CONTROL_PORT,
            dst_port: 49152,
            captured_ns: 0,
            payload: vec![n; 8],
        }
    }

    /// A full inbox drops the NEWEST segment, not the oldest.
    ///
    /// `docs/engineering-style.md` prescribes drop-newest and asks for the
    /// rationale at the drop site; this is the assertion that the site actually
    /// implements what it says. It is a CONTENT assertion on purpose: the
    /// buffer's LENGTH and the dropped COUNT are identical under both policies,
    /// which is exactly how a drop-oldest mutation survived the first table
    /// against a cell that checked only those two.
    ///
    /// Why the policy matters here rather than being a style tick: an older
    /// buffered segment is closer to being parsed, so evicting it trades an
    /// association that was about to be learned for one that may not even be a
    /// control message.
    #[test]
    fn a_full_inbox_drops_the_newest_segment_7699() {
        let inbox = PptpControlInbox::default();
        for i in 0..PENDING_CONTROL_CAPACITY {
            assert!(
                inbox.push(seg(i as u8)),
                "segment {i} must fit below capacity"
            );
        }
        assert_eq!(inbox.dropped_count(), 0, "nothing dropped while it fit");

        // The overflow segment carries a payload none of the others can have.
        const OVERFLOW: u8 = 0xFF;
        assert!(
            !inbox.push(seg(OVERFLOW)),
            "the segment past capacity must be REFUSED"
        );
        assert_eq!(inbox.dropped_count(), 1);

        let drained = inbox.take_pending(1);
        assert_eq!(drained.len(), PENDING_CONTROL_CAPACITY);
        assert!(
            drained.iter().all(|s| s.payload[0] != OVERFLOW),
            "the REFUSED segment is in the buffer — push returned false but \
             queued it anyway"
        );
        // Drop-newest keeps the oldest, so the buffer is the first N pushes in
        // order. Under drop-oldest the head would have been evicted and the
        // sequence would start at 1.
        for (i, s) in drained.iter().enumerate() {
            assert_eq!(
                s.payload[0], i as u8,
                "buffer position {i} holds segment {} — the inbox evicted the \
                 OLDEST segment to make room, but an older segment is closer to \
                 being parsed; drop-newest is the documented policy",
                s.payload[0]
            );
        }
    }
}

#[cfg(test)]
mod call_install_retry_fence_tests_12133 {
    use super::*;
    use crate::session::pptp::{ControlChannelId, PptpCall, PptpCallDisconnect};

    fn peers() -> (std::net::IpAddr, std::net::IpAddr) {
        (
            "198.51.100.7".parse().unwrap(),
            "203.0.113.9".parse().unwrap(),
        )
    }

    fn channel() -> ControlChannelId {
        let (pac, pns) = peers();
        ControlChannelId::new(pac, 49152, pns, 1723)
    }

    fn call(a: u16, b: u16) -> PptpCall {
        let (pac, pns) = peers();
        PptpCall::new(pac, a, pns, b)
    }

    #[test]
    fn an_older_reply_and_stale_ack_cannot_replace_a_newer_install_retry_12133() {
        const QUEUE: usize = 41;
        const OTHER_QUEUE: usize = 42;
        let inbox = PptpControlInbox::default();
        let call = call(0x1111, 0x2222);
        let control = channel();

        inbox.record_call_install(call, control, 20, vec![QUEUE]);
        inbox.record_call_install(call, control, 10, vec![OTHER_QUEUE]);
        inbox.mark_call_install_sent(call, control, 10, QUEUE);
        let retry = inbox.take_call_install_retries(1_000_000_000);
        assert_eq!(retry.len(), 1);
        assert_eq!(
            retry[0].learned_ns, 20,
            "an older reply replaced the latest learned timestamp"
        );
        assert_eq!(
            retry[0].unsent_queue_ids,
            vec![QUEUE],
            "the older reply or its stale acknowledgement replaced current recipients"
        );

        inbox.mark_call_install_sent(call, control, 20, QUEUE);
        assert!(
            inbox.take_call_install_retries(2_000_000_000).is_empty(),
            "an acknowledgement for the current learned timestamp did not clear it"
        );
    }

    #[test]
    fn call_disconnect_retry_cancellation_obeys_timestamp_and_call_scope_12133() {
        const QUEUE: usize = 51;
        let inbox = PptpControlInbox::default();
        let control = channel();
        let call_a = call(0x1111, 0x2222);
        let call_b = call(0x3333, 0x4444);
        inbox.record_call_install(call_a, control, 10, vec![QUEUE]);
        inbox.record_call_install(call_b, control, 20, vec![QUEUE]);
        let (pac, _) = peers();

        inbox.forget_call_installs_for_disconnect(PptpCallDisconnect {
            allocator: pac,
            call_id: 0x1111,
            control,
            disconnected_ns: 9,
        });
        let retries = inbox.take_call_install_retries(1_000_000_000);
        assert_eq!(
            retries.len(),
            2,
            "a CDN older than the learned reply canceled a retry"
        );

        inbox.forget_call_installs_for_disconnect(PptpCallDisconnect {
            allocator: pac,
            call_id: 0x1111,
            control,
            disconnected_ns: 10,
        });
        let retries = inbox.take_call_install_retries(2_000_000_000);
        assert_eq!(retries.len(), 1);
        assert_eq!(
            retries[0].call, call_b,
            "a CDN must remove only its call, preserving the later call on the channel"
        );
    }

    #[test]
    fn channel_close_retry_cancellation_preserves_newer_installs_12133() {
        const QUEUE: usize = 61;
        let inbox = PptpControlInbox::default();
        let control = channel();
        let call_a = call(0x1111, 0x2222);
        let call_b = call(0x3333, 0x4444);
        inbox.record_call_install(call_a, control, 10, vec![QUEUE]);
        inbox.record_call_install(call_b, control, 20, vec![QUEUE]);

        inbox.forget_call_installs_for_channel(control, 15);
        let retries = inbox.take_call_install_retries(1_000_000_000);
        assert_eq!(retries.len(), 1);
        assert_eq!(
            retries[0].call, call_b,
            "a close must cancel no-later-than installs and preserve newer ones"
        );

        inbox.forget_call_installs_for_channel(control, 20);
        assert!(
            inbox.take_call_install_retries(2_000_000_000).is_empty(),
            "the close timestamp equal to the learned time must cancel that install"
        );
    }
}

#[cfg(test)]
mod routing_domain_inbox_13681_tests {
    use super::*;

    #[test]
    fn closing_one_routing_domain_does_not_purge_another_domains_reply_13681() {
        let src = "198.51.100.7".parse().unwrap();
        let dst = "203.0.113.9".parse().unwrap();
        let segment = || PendingControlSegment { epoch: 0,            src,
            dst,
            src_port: 49_152,
            dst_port: 1723,
            captured_ns: 1,
            payload: vec![1],
        };
        let inbox = PptpControlInbox::default();
        assert!(inbox.push_in_domain(100_001, segment()));
        assert!(inbox.push_in_domain(100_002, segment()));

        let closed =
            crate::session::pptp::ControlChannelId::new_in_domain(100_001, src, 49_152, dst, 1723);
        assert_eq!(inbox.forget_channel(closed), 1);

        let pending = inbox.take_pending_in_domain(1, 0);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].0, 100_002);
    }
}

#[cfg(test)]
mod tests_15950_parse {
    use super::*;
    fn msg(len:u16, ty:u16, body:&[u8])->Vec<u8>{let mut m=Vec::new(); m.extend_from_slice(&len.to_be_bytes()); m.extend_from_slice(&1u16.to_be_bytes()); m.extend_from_slice(&MAGIC_COOKIE.to_be_bytes()); m.extend_from_slice(&ty.to_be_bytes()); m.extend_from_slice(&0u16.to_be_bytes()); m.extend_from_slice(body); m}
    #[test]
    fn incoming_reply_and_teardowns_parse_15950(){
        // Incoming-Call-Reply len24: CallID, PeerCallID, Result=1, rest
        let mut body=Vec::new(); body.extend_from_slice(&0xAAAAu16.to_be_bytes()); body.extend_from_slice(&0xBBBBu16.to_be_bytes()); body.push(1); body.extend_from_slice(&[0;7]);
        assert_eq!(parse_control_segment(&msg(24,10,&body)), ControlParse::CallReply{call_id:0xAAAA, peer_call_id:0xBBBB});
        let mut bad=body.clone(); bad[4]=2; assert_eq!(parse_control_segment(&msg(24,10,&bad)), ControlParse::Ignored);
        let mut body=Vec::new(); body.extend_from_slice(&0x1234u16.to_be_bytes()); body.extend_from_slice(&[0;2]);
        assert_eq!(parse_control_segment(&msg(16,12,&body)), ControlParse::CallClear{call_id:0x1234});
        assert_eq!(parse_control_segment(&msg(16,3,&body)), ControlParse::StopControl);
        let mut reply=vec![1u8,0,0,0];
        assert_eq!(parse_control_segment(&msg(16,4,&reply)), ControlParse::StopControl);
        reply[0]=2;
        assert_eq!(parse_control_segment(&msg(16,4,&reply)), ControlParse::Ignored, "failed Stop reply must not tear down");
    }
}

#[cfg(test)]
mod tests_15966r_toggle {
    use super::*;
    fn seg(epoch: u64, ns: u64, b: u8) -> PendingControlSegment {
        PendingControlSegment { epoch, src: "198.51.100.7".parse().unwrap(), dst: "203.0.113.9".parse().unwrap(), src_port: 1723, dst_port: 49152, captured_ns: ns, payload: vec![b] }
    }
    #[test]
    fn publisher_epoch_drain_filtering_15966r5() {
        // Steady: entries stamped with current epoch survive drains.
        let inbox = PptpControlInbox::default();
        assert!(inbox.push(seg(5, 1, 1)));
        assert_eq!(inbox.take_pending_in_domain(1_000_000_000, 5).len(), 1, "steady current-epoch reply must install");
        // Stale-enabled drain: worker's view is epoch 7 (publisher flipped
        // twice); an entry captured under epoch 5 is dropped at drain even
        // though no worker observed the disabled generations (all-skip).
        assert!(inbox.push(seg(5, 2, 2)));
        assert_eq!(inbox.take_pending_in_domain(2_000_000_000, 7).len(), 0, "old-epoch entry must drop under a newer view epoch (all-skip safe)");
        // Current-epoch entry under that same view survives (no second purge).
        assert!(inbox.push(seg(7, 3, 3)));
        assert_eq!(inbox.take_pending_in_domain(3_000_000_000, 7).len(), 1, "current-epoch entry must survive lagging drains");
        // Exact-epoch rule: an entry stamped under a NEWER epoch (9) is
        // not eligible under a stale epoch-5 view — after the publisher
        // has moved on, the stale enabled view must not install it.
        assert!(inbox.push(seg(9, 4, 4)));
        assert_eq!(inbox.take_pending_in_domain(4_000_000_000, 5).len(), 0, "future-epoch entry must drop under a stale view");
        // And the equal-epoch entry under that same stale view was kept
        // above at its own drain; strictly-older under current drops:
        assert!(inbox.push(seg(5, 5, 5)));
        assert_eq!(inbox.take_pending_in_domain(5_000_000_000, 7).len(), 0, "strictly-older entry must drop under current view");
    }
}

#[cfg(test)]
mod tests_generation_regression {
    use super::*;
    fn seg(epoch: u64, ns: u64, b: u8) -> PendingControlSegment {
        PendingControlSegment { epoch, src: "198.51.100.7".parse().unwrap(), dst: "203.0.113.9".parse().unwrap(), src_port: 1723, dst_port: 49152, captured_ns: ns, payload: vec![b] }
    }
    #[test]
    fn generation_regression_freeze_must_not_drop_fresh_reply() {
        // Candidate view epoch G=5 published pre-spawn; rollback republishes
        // recovery view. Because stop_inner advanced the publisher epoch,
        // the recovery view is stamped G+1=6 (simulated here by draining
        // under epoch 6), and a FRESH reply captured under the recovery
        // view (epoch 6) must install — a tracker frozen at G would have
        // dropped it as future/stale.
        let inbox = PptpControlInbox::default();
        assert!(inbox.push(seg(6, 1, 1)));
        assert_eq!(inbox.take_pending_in_domain(1_000_000_000, 6).len(), 1, "fresh reply under recovery epoch must not be dropped");
        // Old candidate-epoch entries (5) under recovery (6) still drop.
        assert!(inbox.push(seg(5, 2, 2)));
        assert_eq!(inbox.take_pending_in_domain(2_000_000_000, 6).len(), 0);
    }
}

#[cfg(test)]
mod lockfree_gate_tests_16240 {
    use super::*;
    use crate::session::pptp::{ControlChannelId, PptpCall, PptpCallDisconnect};

    fn seg(b: u8) -> PendingControlSegment {
        PendingControlSegment { epoch: 0, src: "198.51.100.7".parse().unwrap(), dst: "203.0.113.9".parse().unwrap(), src_port: PPTP_CONTROL_PORT, dst_port: 49152, captured_ns: 0, payload: vec![b; 8] }
    }

    fn channel() -> ControlChannelId {
        ControlChannelId::new("198.51.100.7".parse().unwrap(), 49152, "203.0.113.9".parse().unwrap(), 1723)
    }

    /// #16240: inside the 1s interval all four take_* return empty WITHOUT
    /// acquiring the inbox mutex; at/after the interval they drain exactly
    /// as before. RED ON REVERT: remove any take_*'s atomic pre-check and
    /// that take_* increments the lock counter on the gated call; remove
    /// the in-lock gate/mirror store and the boundary assertions fail.
    #[test]
    fn gated_take_star_do_not_lock_and_drain_at_interval_16240() {
        const Q: usize = 7;
        const T0: u64 = 1_000_000_000;
        let inbox = PptpControlInbox::default();
        let control = channel();
        let call = PptpCall::new("198.51.100.7".parse().unwrap(), 0x1111, "203.0.113.9".parse().unwrap(), 0x2222);
        assert!(inbox.push(seg(1)));
        inbox.record_channel_forget(control, 10, vec![Q]);
        inbox.record_call_forget(PptpCallDisconnect { allocator: "198.51.100.7".parse().unwrap(), call_id: 0x1111, control, disconnected_ns: 10 }, vec![Q]);
        inbox.record_call_install(call, control, 10, vec![Q]);
        // First (due) drains: each take_* locks once and hands work out.
        assert_eq!(inbox.take_pending_in_domain(T0, 0).len(), 1);
        assert_eq!(inbox.take_channel_forget_retries(T0).len(), 1);
        assert_eq!(inbox.take_call_forget_retries(T0).len(), 1);
        assert_eq!(inbox.take_call_install_retries_at(T0, 0).len(), 1);
        assert!(inbox.push(seg(2)));
        let locks_after_due = inbox.lock_acquisition_count();
        // Inside the interval: gated, empty, and NO new lock acquisition.
        let gated_at = T0 + CONTROL_DRAIN_INTERVAL_NS - 1;
        assert!(inbox.take_pending_in_domain(gated_at, 0).is_empty());
        assert!(inbox.take_channel_forget_retries(gated_at).is_empty());
        assert!(inbox.take_call_forget_retries(gated_at).is_empty());
        assert!(inbox.take_call_install_retries_at(gated_at, 0).is_empty());
        assert_eq!(inbox.lock_acquisition_count(), locks_after_due, "a gated take_* acquired the inbox mutex — the #16240 lock-free pre-check is missing or bypassed for that take_*");
        // At the interval boundary the in-lock gate is authoritative and
        // the drain timing is unchanged.
        let due_at = T0 + CONTROL_DRAIN_INTERVAL_NS;
        assert_eq!(inbox.take_pending_in_domain(due_at, 0).len(), 1, "segment buffered during the gated window must drain at the interval boundary");
        assert_eq!(inbox.take_channel_forget_retries(due_at).len(), 1);
        assert_eq!(inbox.take_call_forget_retries(due_at).len(), 1);
        assert_eq!(inbox.take_call_install_retries_at(due_at, 0).len(), 1);
        assert!(inbox.lock_acquisition_count() > locks_after_due, "due drains must still take the lock (in-lock gate authoritative)");
    }

    /// #16240: mark_*_sent acks must not disturb the gate — after a due
    /// retry drain, gated calls stay lock-free until the next interval,
    /// and an acked retry is not redelivered at the next due drain.
    #[test]
    fn mark_sent_keeps_gate_until_next_interval_16240() {
        const Q: usize = 9;
        const T0: u64 = 1_000_000_000;
        let inbox = PptpControlInbox::default();
        let control = channel();
        let call = PptpCall::new("198.51.100.7".parse().unwrap(), 0x1111, "203.0.113.9".parse().unwrap(), 0x2222);
        inbox.record_call_install(call, control, 10, vec![Q]);
        assert_eq!(inbox.take_call_install_retries_at(T0, 0).len(), 1);
        inbox.mark_call_install_sent(call, control, 10, Q);
        let locks = inbox.lock_acquisition_count();
        assert!(inbox.take_call_install_retries_at(T0 + 1, 0).is_empty());
        assert_eq!(inbox.lock_acquisition_count(), locks, "gated install retry after mark_*_sent acquired the mutex");
        assert!(inbox.take_call_install_retries_at(T0 + CONTROL_DRAIN_INTERVAL_NS, 0).is_empty(), "acked install retry must not be redelivered at the next due drain");
    }
}
