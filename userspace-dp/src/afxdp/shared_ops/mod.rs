use super::*;
use crate::session::ForwardingGenerationStamp;
use std::sync::atomic::AtomicU64;
use std::sync::{MutexGuard, TryLockError};

/// #4800: calls to [`publish_shared_session`] — one per session published
/// into the cross-worker shared maps, i.e. one per new transit flow (plus
/// its reverse companion) and one per promote / HA import / tunnel install.
///
/// This is the DENOMINATOR for the publish leg of the new-flow-install
/// serialization question. On its own a publish rate says nothing; paired
/// with `SHARED_SESSION_PUBLISH_LOCK_CONTENDED` it says whether the publish
/// mutexes are where new flows queue up.
mod lookup;
mod reverse_synth;
mod store;
pub(super) use lookup::*;
pub(super) use reverse_synth::*;
pub(super) use store::*;
#[cfg(test)]
pub(in crate::afxdp) use store::{nat_ambiguity_lock_stats, reset_nat_ambiguity_lock_stats};
