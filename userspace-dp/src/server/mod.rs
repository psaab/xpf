// #1048 P2 step 2: server/ became a directory module so the
// public-API state types and the handler dispatch can live in
// separate sibling files (server/state.rs and server/handlers/).
// (#1345: handlers became a directory module — see server/handlers/mod.rs.)
//
// This file is a thin index — declarations + re-exports only.

// Submodules are private — external callers reach their items only
// through the explicit `pub(crate) use` re-exports below.
pub(crate) mod reinject_9506;
mod handlers;
pub(crate) mod helpers;
pub(crate) mod lifecycle;
// #6979: pub(crate) so the coordinator test can build a ServerState and drive
// refresh_status, binding the retirement CALL SITE rather than the function.
pub(crate) mod state;

#[cfg(test)]
mod tests;

pub(crate) use handlers::{handle_stream, SocketMode};
pub(crate) use state::{Args, PollMode, ServerState};
// Issue 69.1: daemon-loop helpers live in server::helpers and are reached
// directly via `use server::helpers::*` in main.rs and `use super::super::*`
// (transitively through `super::helpers`) elsewhere; no glob re-export here
// so the items don't acquire a second crate-visible path through `server::`.
