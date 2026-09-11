//! #9654: whether the learned-route import is capped in the forwarding state
//! live workers serve NOW, for helper status.
//!
//! Its own file rather than `status.rs`, which sits at the 1500-line modularity
//! floor (docs/engineering-style.md).

use super::*;

impl super::Coordinator {
    /// #9654: is the learned-route import capped in the forwarding state that
    /// live workers are serving right now?
    ///
    /// Read from the PUBLISHED runtime view (`ha.runtime`, #6592), the state
    /// workers actually load, never from `self.forwarding`. Reconcile installs a
    /// candidate there before any worker starts, and a failed first spawn leaves
    /// it behind. And only while at least one worker record is live: with no
    /// live worker nothing serves or delegates anything, whatever the view says.
    ///
    /// So the answer is `None` (unknown) after a teardown, before the first
    /// worker registers, after a first-worker spawn failure, and once every
    /// worker has died. It is `Some(flag)` otherwise. Every coordinator mutation
    /// takes `&mut self` under the same server lock as this read, so the
    /// records and the view are observed as one state.
    pub fn learned_route_import_capped_now(&self) -> Option<bool> {
        let live = self
            .workers
            .records()
            .values()
            .any(|rec| !rec.handle.runtime_atomics.dead.load(Ordering::Relaxed));
        if !live {
            return None;
        }
        Some(
            self.ha
                .runtime
                .load()
                .forwarding()
                .learned_route_import_capped,
        )
    }
}

#[cfg(test)]
#[path = "learned_route_capped_now_9654_tests.rs"]
mod learned_route_capped_now_9654_tests;
