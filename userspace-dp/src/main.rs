mod afxdp;
mod event_stream;
// #1219: fairness pure-fns — included here only for `cargo test` so
// `fairness.rs` tests run in the main binary's test suite. The fairness-eval
// binary includes it directly via `#[path]`. No production code in main.rs
// references these functions; gating on #[cfg(test)] avoids a redundant
// production compile while preserving test coverage.
#[cfg(test)]
mod fairness;
mod filter;
mod flowexport;
mod nat;
mod nat64;
mod nptv6;
mod policy;
mod prefix;
mod prefix_set;
mod screen;
mod session;
mod slowpath;
#[cfg(test)]
mod test_zone_ids;
mod state_writer;
#[allow(dead_code)]
mod xsk_ffi;

mod protocol;
mod server;
// Re-export at the crate root so other modules (afxdp/bind, afxdp/coordinator)
// can continue to reach `crate::PollMode` after the move into server/state.rs
// without depending on ancestor-privacy of a private use statement.
pub(crate) use server::{handle_stream, Args, PollMode, ServerState};
use server::helpers::*;

use afxdp::SyncedSessionEntry;
use chrono::Utc;
use protocol::*;
use serde::Serialize;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use state_writer::StateWriter;


fn main() {
    if let Err(err) = server::lifecycle::run() {
        eprintln!("xpf-userspace-dp: {err}");
        std::process::exit(1);
    }
}


#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;
