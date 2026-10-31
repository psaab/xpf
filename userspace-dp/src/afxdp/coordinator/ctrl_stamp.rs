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
//! rules keep that from overriding Go, with one stated residual:
//!
//! 1. **The helper writes only inside a Go round trip that granted it.** Go
//!    stamps `ctrl_stamp_deadline_mono_ns` (an absolute CLOCK_MONOTONIC
//!    deadline, `ctrlStampGrant` = 250 ms after the request is built) on the
//!    requests that carry a snapshot, `apply_snapshot` and
//!    `bump_fib_generation`, and the helper's handlers for exactly those two
//!    verbs open the grant ([`CtrlStampGrantGuard`], dropped when the handler
//!    returns or unwinds). The helper checks the deadline before its read and
//!    again immediately before its write, and refuses within
//!    `CTRL_STAMP_DEADLINE_MARGIN_NS` of it. Go holds `m.mu` across both round
//!    trips and every Go ctrl write runs under `m.mu`, so Go cannot write ctrl
//!    until the round trip returns, and the round trip cannot return before
//!    the grant expires unless the helper has replied: the connection deadline
//!    is at least 3 s, and a shutdown cut (`cutInFlightControlIO`) still allows
//!    500 ms from the cut (`ctrlStampGrant` is compile-time bounded below
//!    both).
//! 2. **The helper only advances a stamp Go already set.** The write happens
//!    only when the row is enabled, carries the metadata version this helper
//!    validates, and its current stamp is exactly the generation the workers
//!    just left. Every other field is written back byte-for-byte as read. A
//!    disabled row (bootstrap, binding-plan change, fail-closed, link cycle,
//!    teardown) is not written.
//!
//! **Residual (review seat W).** Nothing bounds how long the `update` syscall
//! takes to complete after the last deadline check. If the helper is
//! descheduled between that check and the write for longer than the slack Go
//! leaves after the deadline (about 300 ms when a shutdown cuts the round
//! trip, about 2.75 s otherwise), Go can return, write the row (for example
//! disable it), and the helper's late write then restores the row it read:
//! `enabled=1` with the fields as they were. The helper detects that its write
//! completed past the deadline (`CtrlStampOutcome::LateWrite`, counted under
//! `ctrl_stamp_errors_total` and logged), but cannot undo it. The effect is
//! bounded by Go's next ctrl write (every status reply, at least once a
//! second) or, if the helper is stopping, by the shim's heartbeat staleness
//! (`heartbeat_timeout_ms`, 1.5 s). Removing the residual needs the stamp in
//! a row only the helper writes, which is a shim ABI change (#18603).
//!
//! The teardown publish (`stop_inner` stores a default 0/0 view with no
//! snapshot installed) never writes the row: the advance skips any view whose
//! validation has `snapshot_installed == false`. It can run inside an open
//! grant, because a full reconcile under `apply_snapshot` tears down first.
//!
//! Go keeps writing the stamp from the status reply as before; that write is
//! now normally a no-op rewrite of the same generation.
//!
//! The map is reopened by pin path on every advance (generation changes are
//! a few per RG move, not per packet), so a shim reload that re-pins the map
//! is followed automatically. The path is the snapshot's `map_pins.ctrl`, the
//! same one Go programs; its shape is checked against the shim ABI before any
//! write (`bpf_map::ctrl_row`).

use std::io;

pub(crate) use crate::afxdp::bpf_map::ctrl_row::UserspaceCtrlValue;

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
    /// The map could not be opened, read or written, or no pin path is known.
    Error,
    /// The write completed after the grant deadline: Go may already have
    /// written the row, and this write may have replaced it (the stated
    /// residual in the module doc). Counted as an error and logged. It fires
    /// on `now >= deadline`, which over-reports (Go's slack after the deadline
    /// is about 300 ms at least), deliberately: a false alarm is cheaper than a
    /// missed one.
    LateWrite,
}

/// Whether a write issued at `now_ns` is inside the grant.
/// A clock reading of 0 (`monotonic_nanos` failed) never opens a grant.
pub(crate) fn ctrl_stamp_grant_open(now_ns: u64, deadline_ns: u64) -> bool {
    now_ns != 0
        && deadline_ns != 0
        && now_ns.saturating_add(CTRL_STAMP_DEADLINE_MARGIN_NS) < deadline_ns
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
        Ok(()) if now_ns() >= deadline_ns => CtrlStampOutcome::LateWrite,
        Ok(()) => CtrlStampOutcome::Advanced,
        Err(_) => CtrlStampOutcome::Error,
    }
}

/// The pinned `userspace_ctrl` map, opened for one advance. The syscalls
/// live in `bpf_map::ctrl_row` (the #16187 ratchet keeps map syscalls
/// there); this is the safe adapter.
pub(crate) struct PinnedCtrlMap {
    fd: crate::afxdp::bpf_map::CtrlRowFd,
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

/// The Go grant for the request being handled: its absolute CLOCK_MONOTONIC
/// deadline and the ctrl map pin path from the snapshot.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct CtrlStampGrant {
    pub(crate) deadline_ns: u64,
    pub(crate) pin_path: String,
}

/// Revokes the grant when dropped, so a handler that returns early or unwinds
/// never leaves one open (review seat V).
pub(crate) struct CtrlStampGrantGuard {
    slot: std::sync::Arc<std::sync::Mutex<Option<CtrlStampGrant>>>,
}

impl Drop for CtrlStampGrantGuard {
    fn drop(&mut self) {
        // lock_tolerant: a poisoned grant mutex (a handler panicked while
        // holding it) is exactly the case this guard exists for (seat V).
        *crate::sync_util::lock_tolerant(&self.slot) = None;
    }
}

/// Coordinator-held grant and diagnostics.
#[derive(Default)]
pub(crate) struct CtrlStampState {
    /// The open grant, if a granting request is being handled. Shared with
    /// the [`CtrlStampGrantGuard`] that revokes it.
    grant: std::sync::Arc<std::sync::Mutex<Option<CtrlStampGrant>>>,
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
    /// The grant the last test-io advance ran under.
    #[cfg(test)]
    pub(crate) test_last_grant: Option<CtrlStampGrant>,
}

impl CtrlStampState {
    fn record(&mut self, outcome: CtrlStampOutcome, leaving: CtrlStamp, entering: CtrlStamp) {
        match outcome {
            CtrlStampOutcome::Advanced => {
                self.advances = self.advances.saturating_add(1);
                self.last_decline = None;
                return;
            }
            CtrlStampOutcome::Error | CtrlStampOutcome::LateWrite => {
                self.errors = self.errors.saturating_add(1)
            }
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
    /// Open a ctrl-stamp grant for the Go request being handled; it stays
    /// open until the returned guard is dropped. A zero deadline (no grant
    /// from Go) opens nothing.
    pub(crate) fn open_ctrl_stamp_grant(&self, deadline_mono_ns: u64, pin_path: &str) -> CtrlStampGrantGuard {
        *crate::sync_util::lock_tolerant(&self.ctrl_stamp.grant) = (deadline_mono_ns != 0).then(|| CtrlStampGrant {
            deadline_ns: deadline_mono_ns,
            pin_path: pin_path.to_string(),
        });
        CtrlStampGrantGuard {
            slot: std::sync::Arc::clone(&self.ctrl_stamp.grant),
        }
    }

    fn current_ctrl_stamp_grant(&self) -> Option<CtrlStampGrant> {
        crate::sync_util::lock_tolerant(&self.ctrl_stamp.grant).clone()
    }

    /// (advances, declines, errors) for the status projection.
    pub(crate) fn ctrl_stamp_counters(&self) -> (u64, u64, u64) {
        (self.ctrl_stamp.advances, self.ctrl_stamp.declines, self.ctrl_stamp.errors)
    }

    /// Called right after the `RuntimeView` store with the validation the
    /// workers are leaving. Acts only inside a grant and only when the stamp
    /// the shim copies actually changed.
    pub(super) fn advance_ctrl_stamp_after_publish(&mut self, previous: CtrlStamp) {
        let Some(grant) = self.current_ctrl_stamp_grant() else {
            return;
        };
        let deadline = grant.deadline_ns;
        // Seat W: a view with no snapshot installed is the teardown publish
        // (`stop_inner` defaults validation to 0/0). It can run inside an open
        // grant (a full reconcile under `apply_snapshot` tears down first) and
        // must never be stamped into the shim.
        if !self.validation.snapshot_installed {
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
            self.ctrl_stamp.test_last_grant = Some(grant.clone());
            let fixed = self.ctrl_stamp.test_now_ns;
            let mut now = || fixed.unwrap_or_else(crate::afxdp::monotonic_nanos);
            let outcome = advance_ctrl_stamp(&mut *io, previous, entering, deadline, &mut now);
            self.ctrl_stamp.test_io = Some(io);
            self.ctrl_stamp.record(outcome, previous, entering);
            return;
        }
        let mut now = crate::afxdp::monotonic_nanos;
        let outcome = if grant.pin_path.is_empty() {
            CtrlStampOutcome::Error
        } else {
            match PinnedCtrlMap::open(&grant.pin_path) {
                Ok(mut io) => advance_ctrl_stamp(&mut io, previous, entering, deadline, &mut now),
                Err(_) => CtrlStampOutcome::Error,
            }
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
        *crate::sync_util::lock_tolerant(&self.value)
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
        *crate::sync_util::lock_tolerant(&self.value) = *value;
        self.updates.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}

#[cfg(test)]
impl super::Coordinator {
    /// Install a shared fake ctrl row holding `value`; returns a handle to it.
    pub(crate) fn install_ctrl_stamp_test_row(&mut self, value: UserspaceCtrlValue) -> SharedCtrlRow {
        let row = SharedCtrlRow::default();
        *crate::sync_util::lock_tolerant(&row.value) = value;
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

    /// Server cells run without armed workers, so their seed apply never
    /// installs a snapshot (a real apply's refresh or reconcile does). Mark
    /// the published view installed, as that apply would, so the advance
    /// (which skips uninstalled views) is exercised.
    pub(crate) fn mark_snapshot_installed_for_test(&mut self) {
        self.validation.snapshot_installed = true;
        self.republish_runtime_validation();
    }

    pub(crate) fn ctrl_stamp_grant_for_test(&self) -> Option<CtrlStampGrant> {
        self.current_ctrl_stamp_grant()
    }
}

#[cfg(test)]
#[path = "ctrl_stamp_tests.rs"]
mod ctrl_stamp_tests;
