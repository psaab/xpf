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
mod hot_hash_seed;
mod io_uring_write;
mod ip_proto;
mod nat;
mod fragment_assoc;
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
#[cfg(test)]
mod test_ports;
mod state_writer;
mod tcp_flags;
#[allow(dead_code)]
mod xsk_ffi;

// #9726: build.rs's linked-library checks. build.rs includes the same file with
// `#[path]`; including it here under cfg(test) puts those checks, and the
// versions the build recorded, under `cargo test`. No production code uses it.
#[cfg(test)]
#[path = "../build_support/libversions.rs"]
mod build_libversions;
#[cfg(test)]
#[path = "build_libversions_tests.rs"]
mod build_libversions_tests;

// #5192: test-only drop-order probe. `WorkerUmemInner` must destroy
// its `Umem` (xsk_umem__delete) before the `MmapArea` that backs it
// (munmap); Rust has no compile-time drop-order assertion, so the two
// `Drop` impls record here under `cfg(test)` and a umem test asserts
// the sequence. Production builds compile neither the probe nor the
// recording calls.
#[cfg(test)]
mod drop_order_probe;

// #4971: test-only counting global allocator. Lets the TX hot-path
// regression tests assert that an expected TX backpressure retry
// performs ZERO heap allocations per drain pass. Compiled only under
// `cfg(test)`; production builds keep the system allocator untouched.
#[cfg(test)]
mod test_alloc;
#[cfg(test)]
#[global_allocator]
static TEST_COUNTING_ALLOC: test_alloc::CountingAlloc = test_alloc::CountingAlloc;

mod protocol;
mod server;
// Re-export at the crate root so other modules (afxdp/bind, afxdp/coordinator)
// can continue to reach `crate::PollMode` after the move into server/state.rs
// without depending on ancestor-privacy of a private use statement.
pub(crate) use server::{handle_stream, Args, PollMode, ServerState};
use server::helpers::*;

use chrono::Utc;
use protocol::*;
use std::env;
use std::fs;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

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
