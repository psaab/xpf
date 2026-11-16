//! #19145 cost bench (ignored; run in release with `--ignored --nocapture`).
//!
//! The #19145 fences put one shared-session lock take per steering write,
//! and one `Arc` clone per worker restore, on the RG-activation path that
//! #18641 is shortening. This bench runs the SAME activation on a tree with
//! the fences and on one without (#18641 step 1 alone), and prints:
//! - `update_ha_state`'s wall time;
//! - the helper's own `RG activation [..] timing:` line, which carries each
//!   prewarm phase and the republish.
//!
//! **What it isolates.** The steering map is the recorder-only descriptor, so
//! no BPF syscall is made. The numbers are the CPU and lock cost the fences
//! add, without the syscall cost the lab sees.
//!
//! **Its limits.** The worker queues are not drained during the activation.
//! At this size the per-worker fan-out runs past the queue bound
//! (`MAX_PENDING_WORKER_COMMANDS`), and the refused pushes are cheaper than
//! accepted ones. So the fan-out phase here is not a production number. Only
//! the phase-by-phase comparison between the two trees is.

use super::*;
use crate::afxdp::bpf_map::{RECORDER_ONLY_MAP_FD, clear_session_map_writes};

const SESSIONS: u16 = 8_000;
const WORKERS: u32 = 6;
const ROUNDS: usize = 9;

fn set_rg1(coordinator: &Coordinator, active: bool) {
    coordinator
        .update_ha_state(&[
            HAGroupStatus {
                rg_id: 1,
                active,
                ..HAGroupStatus::default()
            },
            HAGroupStatus {
                rg_id: 2,
                active: true,
                ..HAGroupStatus::default()
            },
        ])
        .expect("update_ha_state");
}

#[test]
#[ignore = "#19145 cost bench: cargo test --release --bins activation_cost_bench -- --ignored --nocapture"]
fn activation_cost_bench_19145() {
    let mut coordinator = Coordinator::new();
    coordinator.set_forwarding_for_test(test_forwarding_state_split_rgs());
    coordinator
        .bpf_maps
        .store(Arc::new(crate::afxdp::coordinator::BpfMaps {
            session_map_fd: Some(crate::afxdp::bpf_map::OwnedFd {
                fd: RECORDER_ONLY_MAP_FD,
            }),
            ..Default::default()
        }));
    let queues: Vec<_> = (0..WORKERS)
        .map(|_| Arc::new(Mutex::new(VecDeque::new())))
        .collect();
    for (id, queue) in queues.iter().enumerate() {
        coordinator.workers.register(
            id as u32,
            WorkerRuntimeRecord::for_test(test_worker_handle(queue.clone())),
            None,
        );
    }
    let clear = |queues: &[Arc<Mutex<VecDeque<WorkerCommand>>>]| {
        for queue in queues {
            queue.lock().expect("queue").clear();
        }
        clear_session_map_writes();
    };
    set_rg1(&coordinator, false);
    for i in 0..SESSIONS {
        coordinator.upsert_synced_session(synced_entry_port(20_000 + i, 1));
        if i % 512 == 0 {
            clear(&queues);
        }
    }
    clear(&queues);
    let shared = coordinator.sessions.synced.lock().expect("shared").len();
    eprintln!("BENCH19145 sessions={SESSIONS} shared_rows={shared} workers={WORKERS}");

    let mut totals_us = Vec::with_capacity(ROUNDS);
    for round in 0..ROUNDS {
        let started = std::time::Instant::now();
        set_rg1(&coordinator, true);
        let took = started.elapsed().as_micros();
        eprintln!("BENCH19145 round={round} activation_us={took}");
        totals_us.push(took);
        clear(&queues);
        set_rg1(&coordinator, false);
        clear(&queues);
    }
    totals_us.sort_unstable();
    eprintln!(
        "BENCH19145 activation_us min={} median={} max={} (rounds={ROUNDS})",
        totals_us[0],
        totals_us[ROUNDS / 2],
        totals_us[ROUNDS - 1]
    );
}
