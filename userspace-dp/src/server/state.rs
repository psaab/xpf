// Server state types extracted from main.rs (#1048 P2 step 2).
// `PollMode` was already pub at the crate root; `Args` and
// `ServerState` were file-private — widened to pub(crate) here
// (and likewise their fields) so server/handlers/ and main.rs's
// run() loop can both construct and destructure them.

use crate::state_writer::StateWriter;
use crate::{afxdp, ConfigSnapshot, ProcessStatus};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollMode {
    BusyPoll,
    Interrupt,
}

impl PollMode {
    /// The `_` arm selects the SPINNING mode, which is the CPU-expensive
    /// direction — so an unrecognised value burns a core rather than failing
    /// visibly (#7745, from the #6907 re-verification).
    ///
    /// REACHABILITY, measured rather than assumed. From a committed config the
    /// only strings that can arrive here are `"busy-poll"` and `"interrupt"`,
    /// guarded three times before this point:
    ///
    ///   1. `pkg/config/schema_system.go` — `poll-mode` carries
    ///      `ValidateEnum([]string{"busy-poll", "interrupt"})`, so a typo is
    ///      rejected at COMMIT.
    ///   2. `pkg/config/compiler_system.go` — the `poll-mode` case assigns only
    ///      for those two literals; anything else leaves `cfg.PollMode` empty.
    ///   3. `pkg/dataplane/userspace/process.go` — an empty `cfg.PollMode`
    ///      becomes the explicit `"busy-poll"` before `--poll-mode` is passed.
    ///
    /// So the wildcard is reachable only by invoking this binary BY HAND with a
    /// bad `--poll-mode`, which is an operator/debug surface rather than a
    /// configuration fail-open.
    ///
    /// Left as a wildcard deliberately: making it fail closed would refuse a
    /// hand-run debug invocation for a typo while changing nothing a committed
    /// config can express, and the arm's real hazard is documented above where
    /// a reader meets it. If the three guards upstream are ever relaxed, this
    /// becomes live.
    pub(crate) fn from_str(s: &str) -> Self {
        match s {
            "interrupt" => PollMode::Interrupt,
            _ => PollMode::BusyPoll,
        }
    }
}

#[derive(Debug)]
pub(crate) struct Args {
    pub(crate) control_socket: String,
    pub(crate) state_file: String,
    pub(crate) workers: usize,
    pub(crate) ring_entries: usize,
    pub(crate) poll_mode: PollMode,
}

pub(crate) struct ServerState {
    pub(crate) status: ProcessStatus,
    pub(crate) snapshot: Option<ConfigSnapshot>,
    pub(crate) afxdp: afxdp::Coordinator,
    pub(crate) state_writer: Arc<StateWriter>,
    /// #9900 F-094 (GPT-4): set when a request handler panicked (or a
    /// poisoned lock was recovered, which proves one did). A panic can
    /// unwind through multi-step mutations — moved-out binding vecs,
    /// half-applied snapshots, torn coordinator internals — that NO
    /// poison-clear can repair, so cleared poison resumes NOTHING: every
    /// request path refuses while this is set, the daemon shuts down, and
    /// the supervisor restarts it into clean state. Never cleared in-process.
    pub(crate) quarantined_after_panic: bool,
}
