// Daemon-loop helpers extracted from main.rs (Issue 69.1), then split
// into cohesive submodules (#6234): the former 1.4k-line grab-bag was an
// ownership boundary for four distinct subsystems behind a single
// `use super::super::*` glob. This file is now a narrow re-export facade
// only — every helper lives in one of the submodules below and is reached
// by call sites through the same `server::helpers::<name>` paths as
// before (main.rs's `use server::helpers::*`, the per-verb handlers'
// `use super::super::helpers::{...}`, and the colocated tests).
//
// - `status`       — `refresh_status` projection + capability/forwarding
//                    predicates (`should_run_afxdp`, `reconcile_status_bindings`,
//                    `set_bindings_forwarding_armed`, `forwarding_unsupported_error`).
// - `session_sync` — synced key/entry + NAT64 reverse reconstruction.
// - `planning`     — binding-settle predicates, canonical plan-key hashing,
//                    and RX-queue / binding replanning (one correctness unit).
// - `persistence`  — owned state payload build + lock-free `write_state`.
// - `guards`       — per-connection `catch_unwind` + poison-recovering state
//                    lock (#9900 F-094).
//
// Pure relocation. Bodies are byte-for-byte identical to the pre-split
// source; each submodule declares its own explicit dependencies in place
// of the old crate-root glob.

mod guards;
mod persistence;
mod planning;
mod session_sync;
// #6979: see server/mod.rs — the retirement call site lives here and is bound
// by a test that enters through refresh_status.
pub(crate) mod status;

pub(crate) use guards::*;
pub(crate) use persistence::*;
pub(crate) use planning::*;
pub(crate) use session_sync::*;
pub(crate) use status::*;
