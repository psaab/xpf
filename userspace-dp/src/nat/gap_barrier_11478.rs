//! #11478: deterministic barrier seam for the holder-capture gap.
//!
//! The coordinator's synced-reserve arms captured the incumbent holder mask
//! and then reserved the replacement in TWO `lock_live` acquisitions. A worker
//! OR/release landing between them was destroyed by the eviction while the
//! rollback replayed the stale mask — the Opus F1 phantom-holder and the Sec2
//! gap-OR early-free. The fuse (single-lock capture+evict+install) closes the
//! gap; this seam PROVES it by running a worker op at the exact program
//! position the gap used to occupy.
//!
//! Placement is what makes one test RED pre-fuse and GREEN post-fuse. Each of
//! the four arms calls [`fire_at_capture_gap`] where the capture used to end:
//! pre-fuse that is between the capture read and the reserve, so the worker op
//! lands IN the gap; post-fuse it is immediately before the fused call, so the
//! worker op completes BEFORE the atomic capture. The test bodies do not
//! change between the two — only the production shape does.
//!
//! Thread-local (not global) so parallel `cargo test` threads cannot observe
//! each other's barrier (the #6819 lesson). One-shot so a multi-rule/prefix
//! scan that reaches the seam twice rendezvouses once and ignores the rest.
//! Channel-based (not `std::sync::Barrier`) so a test that never reaches the
//! seam fails loudly on a timeout instead of hanging the suite forever.

use std::cell::{Cell, RefCell};
use std::sync::mpsc::{Receiver, Sender};
use std::time::Duration;

/// How long either side waits for the other before failing loudly. The
/// rendezvous is immediate on a correct test; a timeout always means the
/// import never reached the seam (wrong fixture/decision) or the worker op
/// panicked — both test bugs, never production timing.
const GAP_TIMEOUT: Duration = Duration::from_secs(10);

/// The coordinator-side rendezvous half, installed on the test thread.
struct CoordinatorHalf {
    /// Coordinator → worker: the gap position was reached, perform the op.
    go: Sender<()>,
    /// Worker → coordinator: the op completed, the coordinator may proceed.
    done: Receiver<()>,
}

thread_local! {
    static GAP: RefCell<Option<CoordinatorHalf>> = const { RefCell::new(None) };
    static FIRED: Cell<bool> = const { Cell::new(false) };
}

/// The worker-side rendezvous handle, moved into the spawned worker thread.
pub(crate) struct GapWorker {
    go: Receiver<()>,
    done: Sender<()>,
}

/// Install the barrier on this thread; returns the worker-side handle. The
/// coordinator import under test must run on THIS thread (it does — the test
/// calls `upsert_synced_session_mirror` directly).
pub(crate) fn install() -> GapWorker {
    let (go_tx, go_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    GAP.with(|gap| {
        *gap.borrow_mut() = Some(CoordinatorHalf {
            go: go_tx,
            done: done_rx,
        });
    });
    FIRED.with(|fired| fired.set(false));
    GapWorker {
        go: go_rx,
        done: done_tx,
    }
}

/// Remove the barrier without firing (test cleanup).
pub(crate) fn uninstall() {
    GAP.with(|gap| {
        *gap.borrow_mut() = None;
    });
}

/// Whether the seam fired at least once since [`install`]. Tests assert this
/// so a fixture that never reaches the seam cannot pass vacuously (the worker
/// side would already have panicked on its timeout; this names the cause).
pub(crate) fn fired() -> bool {
    FIRED.with(|fired| fired.get())
}

/// Coordinator side: rendezvous with the gap worker exactly once. Called at
/// the capture-gap position of each synced-reserve arm, gated on
/// `capture_previous_holders` so worker fan-out and rollback-restore reserves
/// (which pass `false`) never rendezvous. No barrier installed → no-op, so
/// every test that does not install one is unaffected.
pub(crate) fn fire_at_capture_gap(capture_previous_holders: bool) {
    if !capture_previous_holders {
        return;
    }
    // One-shot: a multi-rule/prefix scan can reach the seam again after the
    // worker already ran; the second arrival must not block on a dead peer.
    let half = GAP.with(|gap| gap.borrow_mut().take());
    let Some(half) = half else {
        return;
    };
    FIRED.with(|fired| fired.set(true));
    half.go
        .send(())
        .expect("11478 gap worker must be waiting for the coordinator");
    half.done
        .recv_timeout(GAP_TIMEOUT)
        .expect("11478 gap worker op must complete");
}

impl GapWorker {
    /// Worker side: wait for the coordinator to reach the gap, run `op`, then
    /// release the coordinator. `op` runs on the worker thread while the
    /// coordinator blocks inside the seam — a true cross-thread interleaving
    /// at a deterministic program position.
    pub(crate) fn run_at_gap(self, op: impl FnOnce()) {
        self.go
            .recv_timeout(GAP_TIMEOUT)
            .expect("11478 coordinator must reach the gap seam");
        op();
        self.done
            .send(())
            .expect("11478 coordinator must be waiting for the gap op");
    }
}
