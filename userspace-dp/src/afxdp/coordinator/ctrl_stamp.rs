//! #18560: the helper advances the `userspace_ctrl` generation stamp at the
//! worker-visible publish instead of leaving it to Go.
//!
//! # The window this closes
//!
//! The XDP shim copies `ctrl.config_generation` / `ctrl.fib_generation` into
//! every redirected packet's metadata, and a worker classifies a packet whose
//! stamp differs from its published validation as a generation mismatch and
//! drops it. Before this module, only Go wrote the stamp, and it did so after
//! the round trip: the helper stored the new `RuntimeView` (workers adopt it on
//! their next poll), finished the rest of the apply, built and serialized the
//! status reply; Go decoded it, ran its post-apply steps, and wrote the ctrl
//! row from `applyHelperStatusLocked`. For that whole interval the shim kept
//! stamping the generation the workers had just left, so every redirected
//! packet was dropped. On the loss cluster an RG move costs a full apply per
//! VIP move plus a FIB bump, and the demoting node counted 3.5k-13k
//! `config_generation_mismatch` drops per run: about 1 ms of line rate per
//! generation change, on the node that is still carrying the flows it is
//! handing over.
//!
//! Writing the stamp immediately after the view store shrinks the window to
//! the gap between the store and each worker's next refresh, plus whatever is
//! already queued in the RX rings. Both orientations inside that gap stay
//! fail-closed (#6592): a worker that has not refreshed yet drops packets
//! stamped ahead of it, and a worker that has refreshed drops packets stamped
//! behind it. Nothing here makes a mismatched packet `Valid`.
//!
//! # Ownership: Go grants, the helper may only advance
//!
//! The ctrl row is one 56-byte array value, so a helper write replaces every
//! field Go owns (enabled, flags, workers, WG ports, heartbeat timeout). Two
//! rules keep that from ever overriding Go:
//!
//! 1. **The helper writes only inside a Go round trip that granted it.** Go
//!    stamps `ctrl_stamp_deadline_mono_ns` on `apply_snapshot` and
//!    `bump_fib_generation` requests (an absolute CLOCK_MONOTONIC deadline,
//!    `ctrlStampGrant` after the request is built). The helper writes only
//!    while that deadline has not passed. Go holds `m.mu` across both round
//!    trips and every Go ctrl write runs under `m.mu`, so Go cannot write ctrl
//!    until the round trip returns. The round trip cannot return before the
//!    grant expires unless the helper has already replied: the full deadline
//!    is at least 3 s, and a shutdown cut (`cutInFlightControlIO`) still
//!    allows 500 ms from the cut, which is never earlier than the grant
//!    (`ctrlStampGrant` is compile-time bounded below
//!    `controlShutdownCutover`). A request that arrives after its grant
//!    expired, or a helper that took too long, simply declines and Go writes
//!    the stamp after the reply exactly as before.
//! 2. **The helper only advances a stamp Go already set.** The write happens
//!    only when the row is enabled, carries the metadata version this helper
//!    validates, and its current stamp is exactly the generation the workers
//!    just left. Every other field is written back byte-for-byte as read. A
//!    disabled row (bootstrap, binding-plan change, fail-closed, link cycle,
//!    teardown) is never touched, so the helper can never enable ctrl or
//!    resurrect a row Go disabled.
//!
//! Go keeps writing the stamp from the status reply as before; that write is
//! now normally a no-op rewrite of the same generation.
//!
//! The map is reopened by pin path on every advance (generation changes are
//! a few per RG move, not per packet), so a shim reload that re-pins the map
//! is followed automatically, and the value size is checked against the shim
//! ABI before any write.

use std::io;

use crate::afxdp::bpf_map::OwnedFd;
pub(crate) use crate::afxdp::bpf_map::ctrl_row::UserspaceCtrlValue;

/// Pin path of the shim's `userspace_ctrl` map. Go creates it
/// (`dataplane.bpfPinPath` + `userspace_ctrl`, pkg/dataplane/dataplane.go).
pub(crate) const USERSPACE_CTRL_PIN_PATH: &str = "/sys/fs/bpf/xpf/userspace_ctrl";

/// The shim's `ctrl.metadata_version` this helper's metadata validation
/// accepts. Go programs the same value (`userspaceMetadataVersion`).
pub(crate) const EXPECTED_CTRL_METADATA_VERSION: u32 =
    crate::afxdp::USERSPACE_META_VERSION as u32;

/// How close to the grant deadline the helper still writes. The slack Go
/// leaves after the deadline (see the module doc) is what actually orders
/// the write before Go can return; this margin only refuses a write that
/// would be issued at the very edge of the grant.
pub(crate) const CTRL_STAMP_DEADLINE_MARGIN_NS: u64 = 50_000_000;

/// The two validation fields the shim stamps into packet metadata.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CtrlStamp {
    pub(crate) config_generation: u64,
    pub(crate) fib_generation: u32,
}

/// Access to the ctrl row. Production opens the pinned map; cells install a
/// recording fake.
pub(crate) trait CtrlMapIo {
    fn lookup(&mut self) -> io::Result<UserspaceCtrlValue>;
    fn update(&mut self, value: &UserspaceCtrlValue) -> io::Result<()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CtrlStampOutcome {
    /// The row now carries the entering stamp.
    Advanced,
    /// The grant had expired (or was about to); Go writes after the reply.
    DeclinedDeadline,
    /// Go holds the row disabled; nothing is written.
    DeclinedDisabled,
    /// The row's metadata version is not the one this helper validates.
    DeclinedVersion,
    /// The row's stamp is not the generation the workers just left, so Go
    /// is not in the steady state this module may advance from.
    DeclinedForeignStamp,
    /// The map could not be opened, read or written.
    Error,
}

/// Whether a write issued at `now_ns` is inside the grant.
pub(crate) fn ctrl_stamp_grant_open(now_ns: u64, deadline_ns: u64) -> bool {
    deadline_ns != 0 && now_ns.saturating_add(CTRL_STAMP_DEADLINE_MARGIN_NS) < deadline_ns
}

/// Advance the ctrl row from `leaving` to `entering`, or decline. The
/// deadline is checked before the read and again immediately before the
/// write, so time spent in the read never extends the grant.
pub(crate) fn advance_ctrl_stamp(
    io: &mut dyn CtrlMapIo,
    leaving: CtrlStamp,
    entering: CtrlStamp,
    deadline_ns: u64,
    now_ns: &mut dyn FnMut() -> u64,
) -> CtrlStampOutcome {
    if !ctrl_stamp_grant_open(now_ns(), deadline_ns) {
        return CtrlStampOutcome::DeclinedDeadline;
    }
    let mut value = match io.lookup() {
        Ok(value) => value,
        Err(_) => return CtrlStampOutcome::Error,
    };
    if value.enabled != 1 {
        return CtrlStampOutcome::DeclinedDisabled;
    }
    if value.metadata_version != EXPECTED_CTRL_METADATA_VERSION {
        return CtrlStampOutcome::DeclinedVersion;
    }
    let current = CtrlStamp {
        config_generation: value.config_generation,
        fib_generation: value.fib_generation,
    };
    if current != leaving {
        return CtrlStampOutcome::DeclinedForeignStamp;
    }
    value.config_generation = entering.config_generation;
    value.fib_generation = entering.fib_generation;
    if !ctrl_stamp_grant_open(now_ns(), deadline_ns) {
        return CtrlStampOutcome::DeclinedDeadline;
    }
    match io.update(&value) {
        Ok(()) => CtrlStampOutcome::Advanced,
        Err(_) => CtrlStampOutcome::Error,
    }
}

/// The pinned `userspace_ctrl` map, opened for one advance. The syscalls
/// live in `bpf_map::ctrl_row` (the #16187 ratchet keeps map syscalls
/// there); this is the safe adapter.
pub(crate) struct PinnedCtrlMap {
    fd: OwnedFd,
}

impl PinnedCtrlMap {
    pub(crate) fn open(path: &str) -> io::Result<Self> {
        Ok(Self {
            fd: crate::afxdp::bpf_map::open_ctrl_row(path)?,
        })
    }
}

impl CtrlMapIo for PinnedCtrlMap {
    fn lookup(&mut self) -> io::Result<UserspaceCtrlValue> {
        crate::afxdp::bpf_map::lookup_ctrl_row(&self.fd)
    }

    fn update(&mut self, value: &UserspaceCtrlValue) -> io::Result<()> {
        crate::afxdp::bpf_map::update_ctrl_row(&self.fd, value)
    }
}

/// Coordinator-held grant and diagnostics.
#[derive(Default)]
pub(crate) struct CtrlStampState {
    /// Absolute CLOCK_MONOTONIC deadline of the Go grant for the request
    /// being handled; 0 outside a granting request.
    pub(crate) grant_deadline_ns: u64,
    pub(crate) advances: u64,
    pub(crate) declines: u64,
    pub(crate) errors: u64,
    /// Last non-advance outcome, so a decline is logged once per change of
    /// reason rather than once per generation.
    last_decline: Option<CtrlStampOutcome>,
    #[cfg(test)]
    pub(crate) test_io: Option<Box<dyn CtrlMapIo + Send + Sync>>,
    #[cfg(test)]
    pub(crate) test_now_ns: Option<u64>,
}

impl CtrlStampState {
    fn record(&mut self, outcome: CtrlStampOutcome, leaving: CtrlStamp, entering: CtrlStamp) {
        match outcome {
            CtrlStampOutcome::Advanced => {
                self.advances = self.advances.saturating_add(1);
                self.last_decline = None;
                return;
            }
            CtrlStampOutcome::Error => self.errors = self.errors.saturating_add(1),
            _ => self.declines = self.declines.saturating_add(1),
        }
        if self.last_decline != Some(outcome) {
            self.last_decline = Some(outcome);
            eprintln!(
                "xpf-userspace-dp: userspace_ctrl stamp not advanced ({outcome:?}) {}/{} -> {}/{}; Go writes it after the reply (#18560)",
                leaving.config_generation,
                leaving.fib_generation,
                entering.config_generation,
                entering.fib_generation
            );
        }
    }
}

impl super::Coordinator {
    /// Open a ctrl-stamp grant for the Go request being handled.
    pub(crate) fn grant_ctrl_stamp(&mut self, deadline_mono_ns: u64) {
        self.ctrl_stamp.grant_deadline_ns = deadline_mono_ns;
    }

    /// Close the grant once the granting request has been handled.
    pub(crate) fn revoke_ctrl_stamp_grant(&mut self) {
        self.ctrl_stamp.grant_deadline_ns = 0;
    }

    /// (advances, declines, errors) for the status projection.
    pub(crate) fn ctrl_stamp_counters(&self) -> (u64, u64, u64) {
        (self.ctrl_stamp.advances, self.ctrl_stamp.declines, self.ctrl_stamp.errors)
    }

    /// Called right after the `RuntimeView` store with the validation the
    /// workers are leaving. Acts only inside a grant and only when the stamp
    /// the shim copies actually changed.
    pub(super) fn advance_ctrl_stamp_after_publish(&mut self, previous: CtrlStamp) {
        let deadline = self.ctrl_stamp.grant_deadline_ns;
        if deadline == 0 {
            return;
        }
        let entering = CtrlStamp {
            config_generation: self.validation.config_generation,
            fib_generation: self.validation.fib_generation,
        };
        if entering == previous {
            return;
        }
        #[cfg(test)]
        if let Some(mut io) = self.ctrl_stamp.test_io.take() {
            let fixed = self.ctrl_stamp.test_now_ns;
            let mut now = || fixed.unwrap_or_else(crate::afxdp::monotonic_nanos);
            let outcome = advance_ctrl_stamp(&mut *io, previous, entering, deadline, &mut now);
            self.ctrl_stamp.test_io = Some(io);
            self.ctrl_stamp.record(outcome, previous, entering);
            return;
        }
        let mut now = crate::afxdp::monotonic_nanos;
        let outcome = match PinnedCtrlMap::open(USERSPACE_CTRL_PIN_PATH) {
            Ok(mut io) => advance_ctrl_stamp(&mut io, previous, entering, deadline, &mut now),
            Err(_) => CtrlStampOutcome::Error,
        };
        self.ctrl_stamp.record(outcome, previous, entering);
    }
}

/// Test double for the pinned ctrl row: a shared value plus write counts, so
/// a cell can install it on a coordinator and inspect what was written.
#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct SharedCtrlRow {
    pub(crate) value: std::sync::Arc<std::sync::Mutex<UserspaceCtrlValue>>,
    pub(crate) updates: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

#[cfg(test)]
impl SharedCtrlRow {
    pub(crate) fn get(&self) -> UserspaceCtrlValue {
        *self.value.lock().expect("ctrl row")
    }
    pub(crate) fn update_count(&self) -> u64 {
        self.updates.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
impl CtrlMapIo for SharedCtrlRow {
    fn lookup(&mut self) -> io::Result<UserspaceCtrlValue> {
        Ok(self.get())
    }
    fn update(&mut self, value: &UserspaceCtrlValue) -> io::Result<()> {
        *self.value.lock().expect("ctrl row") = *value;
        self.updates.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}

#[cfg(test)]
impl super::Coordinator {
    /// Install a shared fake ctrl row holding `value`; returns a handle to it.
    pub(crate) fn install_ctrl_stamp_test_row(&mut self, value: UserspaceCtrlValue) -> SharedCtrlRow {
        let row = SharedCtrlRow::default();
        *row.value.lock().expect("ctrl row") = value;
        self.ctrl_stamp.test_io = Some(Box::new(row.clone()));
        row
    }

    /// The shim stamp of the currently published view (what a steady-state
    /// ctrl row carries).
    pub(crate) fn published_ctrl_stamp(&self) -> CtrlStamp {
        let v = self.ha.runtime.load().validation();
        CtrlStamp {
            config_generation: v.config_generation,
            fib_generation: v.fib_generation,
        }
    }

    pub(crate) fn ctrl_stamp_grant_deadline_for_test(&self) -> u64 {
        self.ctrl_stamp.grant_deadline_ns
    }
}

#[cfg(test)]
#[path = "ctrl_stamp_tests.rs"]
mod ctrl_stamp_tests;
