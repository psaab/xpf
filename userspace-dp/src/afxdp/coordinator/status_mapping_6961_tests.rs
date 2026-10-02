// #6961: bind the `WorkerRuntimeStatus` mapping hop.
//
// `worker_runtime_snapshots` builds every per-worker
// `crate::protocol::WorkerRuntimeStatus` from a long field-by-field literal,
// and NOTHING bound that literal. Substituting any field for a same-typed
// sibling — `new_flow_installs: s.session_create_drops`, or swapping two
// `cos_queue_lease_undergrant_*` counters — compiled and reddened nothing,
// while every counter that reaches gRPC and Prometheus passes through it. The
// concrete failure is a copy-paste when a field is added: the new counter's
// value is then reported under a neighbour's series forever, and the upstream
// counter tests all stay green because the counters themselves are correct.
//
// WHY A BINDING TEST AND NOT A SINGLE SOURCE. The two shapes are allowed to
// differ, so there is no divergence to make impossible: `WorkerRuntimeStatus`
// is a serde WIRE type with omitempty semantics, it draws from FOUR sources
// (the runtime atomics, the 60s window tuple, the cold-path atomics, and
// values computed in the loop), it FLATTENS the nested
// `cos_queue_lease_undergrant` sub-struct into six scalars, it RENAMES the
// window fields (`w.thread_cpu_ns` -> `thread_cpu_ns_60s`), and five atomics
// (`*_window_base`, `window_base_at_ns`, `window_gen`) are internal
// bookkeeping that deliberately never rides the wire. Collapsing that into one
// struct would change the wire contract. So this binds the AGREEMENT instead —
// which is the other half of the rule the #6949 seam followed, not a weaker
// version of it.
//
// WHAT MAKES A SWAP VISIBLE. Every seeded field gets a DISTINCT value. A
// fixture of all zeros, all ones, or any repeated value cannot distinguish
// `st.a = src.a` from `st.a = src.b`: both assertions pass. The distinctness
// IS the test. `distinct_seed` below is injective by construction and
// `seeds_are_distinct_6961` asserts that rather than assuming it.
//
// WHY THE SOURCE IS THE ATOMICS AND NOT THE COUNTERS SNAPSHOT. The chain has
// TWO hops with the same arg-swap shape: `WorkerRuntimeAtomics::snapshot()`
// (atomics -> `WorkerRuntimeCounters`) and then the literal above. Seeding the
// ATOMICS and asserting on the wire status covers both end-to-end, so a swap in
// either reds here.
//
// CORRECTION, measured. An earlier revision of this comment said the upstream
// hop "was equally unbound". That is FALSE and the #6961 mutation matrix caught
// it: cell B1 swaps a field inside `snapshot()` and reds the pre-existing
// `worker_runtime::tests::snapshot_roundtrip` alongside this file's binding.
// That test publishes a fixture whose values are all distinct and asserts each
// field round-trips, which is a sound arg-swap guard for that hop and predates
// #6961. The hop that was genuinely unbound is the ONE THIS FILE IS ABOUT —
// the `worker_runtime_snapshots` literal. Covering the upstream hop too is
// belt-and-braces, not a discovery, and `snapshot_roundtrip` must not be
// deleted on the strength of this file.

use super::*;
use crate::afxdp::worker_runtime::WorkerRuntimeAtomics;
use std::sync::atomic::Ordering as AtomicOrdering;

/// The scalar fields whose name is IDENTICAL on `WorkerRuntimeAtomics` and on
/// `crate::protocol::WorkerRuntimeStatus` — all 30 of them `AtomicU64` -> `u64`,
/// which is exactly why any one can be substituted for any other without a
/// compiler complaint.
///
/// The list is written ONCE and expanded three ways: to seed, to assert, and to
/// enumerate its own names for the completeness ratchet. That matters more than
/// brevity here — a hand-written `assert_eq!(st.a, atomics.a)` per field is a
/// TRANSCRIPTION of the mapping, and a transcription that repeats the mapping's
/// mistake certifies it. Here each name appears once and is used on both sides,
/// so the assertion cannot mirror a swap.
macro_rules! for_each_shared_scalar {
    ($m:ident) => {
        $m!(
            wall_ns,
            active_ns,
            idle_spin_ns,
            idle_block_ns,
            thread_cpu_ns,
            work_loops,
            idle_loops,
            session_volume_high_water,
            cos_queue_lease_acquire_v8_calls,
            cos_queue_lease_acquire_v8_granted_bytes,
            cos_wheel_ticks_advanced_total,
            cos_wheel_ticks_advanced_max,
            cos_queue_lease_undergrant_seqlock_give_up,
            cos_queue_lease_undergrant_cap_zero,
            cos_queue_lease_undergrant_epoch_rotated,
            cos_queue_lease_undergrant_share_exhausted,
            cos_queue_lease_undergrant_class_cap,
            cos_queue_lease_undergrant_outstanding_cap,
            session_table_entries,
            max_sessions,
            nat_reverse_key_collisions,
            nat_reverse_key_collisions_distinct_src,
            session_create_drops,
            session_lookup_miss_no_handle,
            session_lookup_miss_stale_handle,
            session_lookup_miss_key_mismatch,
            session_install_admission_refused,
            session_install_partial,
            new_flow_installs,
            wall_ns_60s,
            active_ns_60s,
            thread_cpu_ns_60s,
            window_ns,
            tid,
        )
    };
}

/// An injective seed. Distinct per field name AND far from every value the
/// mapping could produce by accident: not 0, not 1, not a small count, not a
/// plausible ns reading, and never equal to another field's seed.
fn distinct_seed(index: u64) -> u64 {
    // 0x51_9E_ED_00 base + a large odd stride. Strictly increasing in `index`,
    // so injectivity is immediate and `seeds_are_distinct_6961` proves it.
    0x0000_51_9E_ED_00 + (index + 1) * 1_000_003
}

macro_rules! shared_scalar_names {
    ($($f:ident),* $(,)?) => { &[$(stringify!($f)),*] };
}

/// Every atomic on `WorkerRuntimeAtomics` that is deliberately NOT on the wire.
///
/// These four window BASES plus the seqlock generation are internal rotation
/// bookkeeping: the wire carries the rotated deltas (`wall_ns_60s` and
/// siblings), never the bases the worker subtracts from. Listing them is what
/// lets the ratchet below say "every atomic is either bound or knowingly
/// excluded" instead of silently tolerating an unbound one.
const DELIBERATELY_OFF_WIRE: &[&str] = &[
    // #7919: reply slots for the per-session counter QUERY, not a series. They
    // carry one diagnostic answer for one requested 5-tuple; mapping them onto
    // the per-worker status would publish a request/response payload as
    // telemetry, and the value would be whatever the last query happened to
    // ask. The guard's whole point is that this choice is written down rather
    // than left to a reader of the mapping literal.
    "counter_query_seq",
    "counter_query_found",
    "counter_query_fwd_packets",
    "counter_query_fwd_bytes",
    "counter_query_rev_packets",
    "counter_query_rev_bytes",
    "counter_query_replica",
    "wall_ns_window_base",
    "active_ns_window_base",
    "thread_cpu_ns_window_base",
    "window_base_at_ns",
    "window_gen",
];

fn seeded_worker(coord: &mut Coordinator, worker_id: u32) -> Arc<WorkerRuntimeAtomics> {
    let handle = WorkerHandle {
        stop: Arc::new(AtomicBool::new(false)),
        heartbeat: Arc::new(AtomicU64::new(0)),
        commands: Arc::new(Mutex::new(VecDeque::new())),
        session_export_ack: Arc::new(AtomicU64::new(0)),
        cos_status: Arc::new(ArcSwap::from_pointee(Vec::new())),
        runtime_atomics: Arc::new(WorkerRuntimeAtomics::new()),
        cold_path_atomics: Arc::new(crate::afxdp::cold_path_hist::WorkerColdPathAtomics::new()),
    };
    let atomics = Arc::clone(&handle.runtime_atomics);

    // Seed pass. `index` advances once per field in the macro's order, so no
    // two fields can share a value.
    let mut index: u64 = 0;
    macro_rules! seed {
        ($($f:ident),* $(,)?) => {$(
            atomics.$f.store(distinct_seed(index), AtomicOrdering::Relaxed);
            index += 1;
        )*};
    }
    for_each_shared_scalar!(seed);
    let _ = index;

    // `window_gen` is left EVEN (0) on purpose: that is a committed seqlock
    // state, so `snapshot_window` returns the four seeded window fields rather
    // than `default()`. Seeding it odd would make every window assertion below
    // read 0 and pass vacuously against an unseeded expectation.
    assert_eq!(
        atomics.window_gen.load(AtomicOrdering::Relaxed) % 2,
        0,
        "window_gen must be even or snapshot_window returns default() and the \
         four window assertions go vacuous"
    );

    let rec = WorkerRuntimeRecord::for_test(handle);
    coord.workers.register(worker_id, rec, None);
    atomics
}

/// THE BINDING (#6961). One worker, every shared scalar seeded to its own
/// distinct value, driven through the REAL `worker_runtime_snapshots`.
///
/// Fail-on-swap: substitute any field in the `status.rs` literal for a
/// same-typed sibling — the 30 fields below are ALL `u64`, so the compiler
/// permits every one of the 870 ordered substitutions — and this reds naming
/// the field.
#[test]
fn worker_runtime_status_binds_every_shared_scalar_to_its_own_source_6961() {
    let mut coord = Coordinator::new();
    let atomics = seeded_worker(&mut coord, 3);

    let rows = coord.worker_runtime_snapshots();
    assert_eq!(rows.len(), 1, "one seeded worker must produce one row");
    let st = &rows[0];

    // The map KEY, not an atomic — a distinct value so a row that reported
    // some other worker's id would be visible too.
    assert_eq!(st.worker_id, 3, "worker_id comes from the records map key");

    macro_rules! check {
        ($($f:ident),* $(,)?) => {$(
            assert_eq!(
                st.$f,
                atomics.$f.load(AtomicOrdering::Relaxed),
                concat!(
                    "WorkerRuntimeStatus.", stringify!($f),
                    " does not carry its own source. Every field seeded here has a \
                     DISTINCT value, so this is what an arg swap in the \
                     worker_runtime_snapshots literal (or in \
                     WorkerRuntimeAtomics::snapshot) looks like: the counter is \
                     correct, and it is reported under the wrong name on gRPC and \
                     Prometheus (#6961)."
                )
            );
        )*};
    }
    for_each_shared_scalar!(check);
}

/// The distinctness the binding above depends on, asserted rather than assumed.
///
/// If `distinct_seed` ever collided — a smaller stride, a wrapping base, an
/// index reused — the binding test would keep passing while losing exactly the
/// property it exists for: two fields sharing a value make a swap between them
/// invisible. That degradation is silent, so it gets its own cell.
#[test]
fn seeds_are_distinct_6961() {
    let names: &[&str] = for_each_shared_scalar!(shared_scalar_names);
    let mut seen: std::collections::BTreeMap<u64, usize> = std::collections::BTreeMap::new();
    for i in 0..names.len() {
        let v = distinct_seed(i as u64);
        if let Some(prev) = seen.insert(v, i) {
            panic!(
                "seed collision: {} and {} both seed {v}. A swap between them would be \
                 INVISIBLE to the #6961 binding",
                names[prev], names[i]
            );
        }
        assert_ne!(v, 0, "{} seeded 0 — indistinguishable from unset", names[i]);
    }
    assert_eq!(seen.len(), names.len());
}

/// THE RATCHET (#6961). Every `AtomicU64` on `WorkerRuntimeAtomics` is either
/// bound by the test above or on the documented off-wire list.
///
/// This is the half that survives the future. The issue's concrete scenario is
/// an editor ADDING a field and copy-pasting its mapping; a binding test over
/// today's fields cannot see tomorrow's field at all. Parsing the struct means
/// a new atomic fails here until someone decides — deliberately — whether it
/// rides the wire.
///
/// The field list is read from the definition and never restated: a list
/// written down twice is two lists, and the two drifting apart is the defect.
#[test]
fn every_runtime_atomic_is_bound_or_knowingly_off_wire_6961() {
    let bound: std::collections::BTreeSet<&str> = for_each_shared_scalar!(shared_scalar_names)
        .iter()
        .copied()
        .collect();
    let off_wire: std::collections::BTreeSet<&str> =
        DELIBERATELY_OFF_WIRE.iter().copied().collect();

    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/afxdp/worker_runtime.rs"),
    )
    .expect("read worker_runtime.rs (the #6961 ratchet cannot run)");
    let body = src
        .split_once("pub(crate) struct WorkerRuntimeAtomics {")
        .expect("WorkerRuntimeAtomics definition")
        .1
        .split_once("\n}")
        .expect("end of the struct")
        .0;

    let mut u64_fields: Vec<String> = Vec::new();
    let mut other_fields: Vec<String> = Vec::new();
    for line in body.lines() {
        let t = line.trim();
        if t.starts_with("//") {
            continue;
        }
        let Some(rest) = t.strip_prefix("pub ") else {
            continue;
        };
        let Some((name, ty)) = rest.split_once(':') else {
            continue;
        };
        let (name, ty) = (name.trim(), ty.trim().trim_end_matches(','));
        if name.starts_with('_') {
            continue; // `_pad`
        }
        if ty == "AtomicU64" {
            u64_fields.push(name.to_string());
        } else {
            other_fields.push(name.to_string());
        }
    }

    // A parse that found nothing would make every assertion below vacuously
    // true — the same failure shape this guard exists to catch.
    assert!(
        u64_fields.len() >= 30,
        "parsed only {} AtomicU64 fields from WorkerRuntimeAtomics; the parse broke, so this \
         ratchet is vacuous. FIX THE PARSE — do not delete the guard",
        u64_fields.len()
    );

    for f in &u64_fields {
        assert!(
            bound.contains(f.as_str()) || off_wire.contains(f.as_str()),
            "WorkerRuntimeAtomics.{f} is a u64 counter that NOTHING binds. Either add it to \
             for_each_shared_scalar! (if worker_runtime_snapshots puts it on the wire under \
             the same name) or to DELIBERATELY_OFF_WIRE with a reason. Leaving it unbound is \
             how #6961 happened: the mapping literal is the only thing that says where this \
             value goes, and a copy-paste there reports it under a neighbour's series \
             forever."
        );
    }

    // The exclusion list must not rot into a dumping ground: every name on it
    // has to still exist on the struct.
    for f in &off_wire {
        assert!(
            u64_fields.iter().any(|u| u == f),
            "DELIBERATELY_OFF_WIRE names {f}, which is no longer an AtomicU64 field on \
             WorkerRuntimeAtomics. Remove the stale entry — a stale exclusion silently \
             widens what the ratchet tolerates"
        );
    }

    // Two non-u64 atomics, and the decision for each is recorded here rather
    // than left to the reader:
    //
    //   `dead`            — ON THE WIRE, bound by
    //                       worker_runtime_status_binds_dead_and_panic_message_6961.
    //   `holders_retired` — DELIBERATELY OFF THE WIRE (#6979). It is not worker
    //                       telemetry; it is a one-shot latch saying the NAT
    //                       holder-bit reclaim for this dead worker has already
    //                       run, so the 1 Hz sweep does not re-walk every
    //                       allocator's live_by_flow on every tick. An operator
    //                       reading status wants `dead` and the panic message;
    //                       whether the internal reclaim has fired is a
    //                       coordinator implementation detail, and putting it on
    //                       the wire would invite it to be read as a second
    //                       liveness signal. The reclaim's OUTCOME is already
    //                       observable — the freed ports reappear in the pool
    //                       allocator's occupancy.
    assert_eq!(
        other_fields,
        vec!["dead".to_string(), "holders_retired".to_string()],
        "a non-u64 atomic appeared on WorkerRuntimeAtomics. Decide whether it rides the wire \
         and bind it; this assertion exists so a new one cannot slip past the u64 sweep above"
    );
}

/// `dead` and `panic_message` are the two fields the loop COMPUTES rather than
/// copies, and they are coupled: `panic_message` is read from the record's
/// panic slot only when `dead` is set, and is otherwise forced empty.
///
/// Both cases are asserted because only one of them can distinguish the
/// coupling from an unconditional read. A live worker whose panic slot happens
/// to hold text must still report an EMPTY message — that is the gate, and a
/// dead-only fixture cannot see it.
#[test]
fn worker_runtime_status_binds_dead_and_panic_message_6961() {
    // (a) dead worker: the slot's text rides the wire.
    let mut coord = Coordinator::new();
    let atomics = seeded_worker(&mut coord, 1);
    atomics.dead.store(true, AtomicOrdering::Relaxed);
    *coord
        .workers
        .records()
        .get(&1)
        .expect("seeded worker")
        .panic
        .lock()
        .expect("panic slot") = Some("worker 1 panicked: distinct-6961".to_string());

    let rows = coord.worker_runtime_snapshots();
    assert!(rows[0].dead, "dead must carry the atomic");
    assert_eq!(
        rows[0].panic_message, "worker 1 panicked: distinct-6961",
        "a dead worker's rendered panic payload must ride the wire verbatim"
    );

    // (b) LIVE worker with a non-empty slot: the message must be suppressed.
    // Without this case, replacing the `if dead { .. } else { String::new() }`
    // with an unconditional slot read would stay green.
    let mut coord = Coordinator::new();
    let _atomics = seeded_worker(&mut coord, 2);
    *coord
        .workers
        .records()
        .get(&2)
        .expect("seeded worker")
        .panic
        .lock()
        .expect("panic slot") = Some("stale text from a previous life".to_string());

    let rows = coord.worker_runtime_snapshots();
    assert!(!rows[0].dead, "worker 2 was never marked dead");
    assert_eq!(
        rows[0].panic_message, "",
        "a LIVE worker must report no panic message even when the slot holds text; \
         panic_message is gated on `dead`, not a raw slot read"
    );
}

/// Rows are per-worker and keyed by the map key, so two workers must not have
/// their bodies transposed — the same arg-swap defect one level up.
///
/// `records` is a `BTreeMap`, so the rows come out in worker-id order; the two
/// workers are seeded on the SAME field values by construction, which is why
/// this asserts on `worker_id` and on a field that differs between them rather
/// than on the shared seeds.
#[test]
fn worker_runtime_status_rows_are_not_transposed_across_workers_6961() {
    let mut coord = Coordinator::new();
    let a = seeded_worker(&mut coord, 11);
    let b = seeded_worker(&mut coord, 22);
    // Give the two workers DIFFERENT values on one field, so a transposition
    // is visible at all. Equal values across workers would make the rows
    // interchangeable and the assertion vacuous.
    a.new_flow_installs
        .store(0xAAAA_1111, AtomicOrdering::Relaxed);
    b.new_flow_installs
        .store(0xBBBB_2222, AtomicOrdering::Relaxed);

    let rows = coord.worker_runtime_snapshots();
    assert_eq!(rows.len(), 2);
    let row_a = rows
        .iter()
        .find(|r| r.worker_id == 11)
        .expect("worker 11 row");
    let row_b = rows
        .iter()
        .find(|r| r.worker_id == 22)
        .expect("worker 22 row");
    assert_eq!(
        row_a.new_flow_installs, 0xAAAA_1111,
        "worker 11's row carries worker 22's counters — the rows are transposed"
    );
    assert_eq!(
        row_b.new_flow_installs, 0xBBBB_2222,
        "worker 22's row carries worker 11's counters — the rows are transposed"
    );
}

/// The SECOND same-typed group in the same literal: the cold-path scalars.
///
/// `cold_path_sample_phase`, `cold_path_ns_per_tsc_q32`,
/// `cold_path_wrapper_ns_baseline`, `cold_path_wrapper_underflow_count` and
/// `cold_path_snapshot_failed` are five `u64` fields written next to each other
/// in the literal, so any pair of them can be transposed exactly as freely as
/// the thirty above. They are bound separately because they do NOT share a name
/// with their source — the literal strips a `cold_path_` prefix
/// (`cold_path_sample_phase: cold.sample_phase`) — so the name-once macro
/// cannot express them, and because the fifth comes from a DIFFERENT call
/// (`snapshot_failed_count()`) than the other four (`snapshot()`).
///
/// Each gets a distinct value, and the values are distinct from the thirty
/// above as well: a cross-group transposition is no less possible than an
/// in-group one.
#[test]
fn worker_runtime_status_binds_the_cold_path_scalars_6961() {
    use crate::afxdp::cold_path_hist::{ClockSource, WorkerColdPathAtomics};

    let mut coord = Coordinator::new();
    let handle = WorkerHandle {
        stop: Arc::new(AtomicBool::new(false)),
        heartbeat: Arc::new(AtomicU64::new(0)),
        commands: Arc::new(Mutex::new(VecDeque::new())),
        session_export_ack: Arc::new(AtomicU64::new(0)),
        cos_status: Arc::new(ArcSwap::from_pointee(Vec::new())),
        runtime_atomics: Arc::new(WorkerRuntimeAtomics::new()),
        cold_path_atomics: Arc::new(WorkerColdPathAtomics::new()),
    };
    let cold = Arc::clone(&handle.cold_path_atomics);
    coord
        .workers
        .register(9, WorkerRuntimeRecord::for_test(handle), None);

    // Five distinct values, none of them 0, none equal to another. 0 would be
    // fatal here specifically: `sample_phase == 0` with all-zero samples is the
    // "never sampled" branch, so a zero seed would take a DIFFERENT path
    // through the literal than the one under test.
    const SAMPLE_PHASE: u64 = 0x0C01D_0001;
    const NS_PER_TSC_Q32: u64 = 0x0C01D_0002;
    const WRAPPER_NS_BASELINE: u64 = 0x0C01D_0003;
    const WRAPPER_UNDERFLOW: u64 = 0x0C01D_0004;
    for (a, b) in [
        (SAMPLE_PHASE, NS_PER_TSC_Q32),
        (NS_PER_TSC_Q32, WRAPPER_NS_BASELINE),
        (WRAPPER_NS_BASELINE, WRAPPER_UNDERFLOW),
        (SAMPLE_PHASE, WRAPPER_UNDERFLOW),
    ] {
        assert_ne!(
            a, b,
            "cold-path seeds must be distinct or a swap is invisible"
        );
    }

    cold.sample_phase
        .store(SAMPLE_PHASE, AtomicOrdering::Relaxed);
    cold.ns_per_tsc_q32
        .store(NS_PER_TSC_Q32, AtomicOrdering::Relaxed);
    cold.wrapper_ns_baseline
        .store(WRAPPER_NS_BASELINE, AtomicOrdering::Relaxed);
    cold.wrapper_underflow_count
        .store(WRAPPER_UNDERFLOW, AtomicOrdering::Relaxed);
    cold.clock_source
        .store(ClockSource::ClockGettime.as_u8(), AtomicOrdering::Relaxed);
    // `cold_window_gen` stays EVEN so `snapshot()` returns Some rather than
    // None; the None branch emits empty/zero fields and would make every
    // assertion below pass against the wrong thing.
    assert_eq!(
        cold.cold_window_gen.load(AtomicOrdering::Relaxed) % 2,
        0,
        "cold_window_gen must be even or snapshot() returns None and this test goes vacuous"
    );

    let rows = coord.worker_runtime_snapshots();
    let st = &rows[0];

    assert_eq!(
        st.cold_path_sample_phase, SAMPLE_PHASE,
        "cold_path_sample_phase does not carry cold.sample_phase (#6961)"
    );
    assert_eq!(
        st.cold_path_ns_per_tsc_q32, NS_PER_TSC_Q32,
        "cold_path_ns_per_tsc_q32 does not carry cold.ns_per_tsc_q32 (#6961)"
    );
    assert_eq!(
        st.cold_path_wrapper_ns_baseline, WRAPPER_NS_BASELINE,
        "cold_path_wrapper_ns_baseline does not carry cold.wrapper_ns_baseline (#6961)"
    );
    assert_eq!(
        st.cold_path_wrapper_underflow_count, WRAPPER_UNDERFLOW,
        "cold_path_wrapper_underflow_count does not carry cold.wrapper_underflow_count (#6961)"
    );
    // A STRING field next to four u64s: its own type group of one on this
    // struct, but it can still be mapped from the wrong source, and "" is what
    // both an unset clock and a dropped mapping produce — so the fixture uses
    // a clock source whose rendering is non-empty.
    assert_eq!(
        st.cold_path_clock_source, "clock_gettime",
        "cold_path_clock_source does not carry cold.clock_source.as_str() (#6961)"
    );
    // The fifth u64 comes from `snapshot_failed_count()`, NOT from `cold`. A
    // clean seqlock read leaves it 0, and 0 here is the truthful value rather
    // than a dropped field — which is why it is asserted against the same
    // accessor the mapping should be using rather than against a literal.
    assert_eq!(
        st.cold_path_snapshot_failed,
        cold.snapshot_failed_count(),
        "cold_path_snapshot_failed does not carry snapshot_failed_count() (#6961)"
    );
}
