---
status: DRAFT v1 — pending adversarial plan review
issue: #1209 (#1187 follow-on)
phase: refactor; behavior preservation; significant call-site sweep
---

## 1. Issue framing

`BindingLiveState` (`userspace-dp/src/afxdp/umem/mod.rs:203+`) carries
~50 `AtomicU64` / `AtomicU32` counters. Workers update them on the
hot path with `fetch_add`. The coordinator reads them via
`snapshot()` on every status poll (1 Hz status loop).

#1187 partially batched RX/TX disposition counters via `BatchCounters`,
but most of `BindingLiveState`'s ~50 atomics still take per-packet or
per-batch RMW operations. Each `fetch_add` is a locked-RMW
instruction (~10-30 cycles + cache-line ownership transfer when the
coordinator reads).

Per Codex CoS findings retrospective:

> Some RX/TX counters are batched, but hot paths still update shared
> atomics in BindingLiveState and owner profile structures... per-worker
> local telemetry block, cache-line aligned [...] periodic bulk publish
> to shared snapshot... reduces worker/coordinator cache-line bouncing
> and makes NUMA behavior less dependent on scrape/control-call timing.

## 2. Honest scope/value framing

Pure performance / cache-locality refactor. No user-facing behavior
change.

**Estimated win**: each removed worker-side `fetch_add` saves ~10-30
cycles. With ~30 atomic fields touched on a typical batch and 14.8M
pps line rate per worker, the total per-worker cost is several percent
of one core. Eliminating it on the hot path is a real win.

**Risk**: the field sweep is wide (~50 fields, dozens of call sites).
Easy to introduce subtle bugs in counter semantics if the unprivileged
"local block + bulk publish" mode doesn't preserve every existing
read-side guarantee.

**If reviewers think the diff size + risk doesn't justify the cycles
saved, PLAN-NEEDS-MAJOR is reasonable. The cycles are unambiguous;
the question is operational.**

## 3. Concrete design

### 3.1 Field classification

Each `BindingLiveState` field falls into one of three categories:

**A. Scrape-only** (vast majority). Worker writes; only coordinator
reads via snapshot. Examples: `rx_packets`, `rx_bytes`, `validated_packets`,
`policy_denied_packets`, all `cos_*` counters, `flow_cache_*`. These
move to a per-worker local block + bulk publish.

**B. Cross-worker** (shared writes). Multiple workers update;
read by coordinator AND by other workers. Examples: TBD — need to
audit. Likely candidates: anything related to shared lease accounting
or owner-profile aggregation.

**C. Heartbeat / liveness** (latency-sensitive read). Coordinator reads
need to be near-realtime, not 100ms-stale. Example: `last_heartbeat`.
These stay as cross-worker atomics.

### 3.2 Local block

```rust
#[repr(C, align(64))]
pub(super) struct BindingLiveLocal {
    // ~50 u64 fields, cache-line aligned, packed for spatial locality.
    // Worker writes without atomics.
    pub(super) rx_packets: u64,
    pub(super) rx_bytes: u64,
    // ... all scrape-only counters
}

pub(super) struct BindingLiveState {
    // Live per-worker block, written without atomics.
    pub(super) local: UnsafeCell<BindingLiveLocal>,

    // Published copy, atomic-pointer flipped on bulk publish.
    pub(super) published: AtomicPtr<BindingLiveLocal>,

    // Cross-worker atomics (category B + C)
    pub(super) last_heartbeat: AtomicU64,
    // ...
}
```

`local` is `UnsafeCell` — single-writer (the owning worker thread)
discipline enforced by code review. Workers update without atomics.

`published` points at a heap-allocated copy of `local` published at
a periodic cadence (existing `COS_STATUS_INTERVAL_NS = 100ms` is the
natural anchor — tied to the worker tick that already exists). Bulk
publish: clone `local` into a fresh box, atomic-store the pointer,
old box freed when the next publish swaps it out (or on Drop of the
state if we use `Arc` instead of `Box` with manual lifecycle).

### 3.3 Snapshot read

```rust
pub(super) fn snapshot(&self) -> BindingLiveSnapshot {
    let published = self.published.load(Ordering::Acquire);
    // SAFETY: `published` always points at a valid box owned by Self.
    let local = unsafe { *published };
    BindingLiveSnapshot {
        rx_packets: local.rx_packets,
        // ...
        last_heartbeat: self.last_heartbeat.load(Ordering::Relaxed),
    }
}
```

### 3.4 Worker hot-path write

```rust
// Old:
binding.live.rx_packets.fetch_add(n, Ordering::Relaxed);

// New:
unsafe { (*binding.live.local.get()).rx_packets += n; }
```

Or via a helper to keep call sites tidy:

```rust
binding.live.bump_rx_packets(n);  // calls into UnsafeCell write
```

### 3.5 Publish cadence

The 1Hz status loop already calls `snapshot()` on every binding. Move
the publish to BEFORE the snapshot read — one pass per second:

```rust
// Existing: worker_loop tick at COS_STATUS_INTERVAL_NS gate
fn worker_publish_telemetry(binding: &mut BindingWorker) {
    // Allocate a fresh box from worker-local buffer pool (no allocation
    // on hot path; double-buffered with two pre-allocated boxes).
    let new = box_clone_from_local(&binding.live.local);
    let old = binding.live.published.swap(Box::into_raw(new), Ordering::Release);
    // Reclaim the old box for next publish (single-buffer recycle).
}
```

## 4. Public API preservation

`BindingLiveSnapshot` (the read shape consumed by
`Coordinator::refresh_bindings` and the Prometheus collector) is
unchanged. Internal storage shape changes; consumers see the same
fields.

## 5. Hidden invariants

- **Snapshot consistency.** A snapshot must reflect a self-consistent
  view: e.g., `rx_packets` and `rx_bytes` from the same instant.
  Bulk publish guarantees this (whole local block flipped atomically
  via pointer swap); the prior `fetch_add` model did NOT guarantee it
  (each field was separately atomic).
- **No cross-worker writes to local block.** Code review enforces
  single-writer; the only API to mutate local should be on the
  owning worker thread. Helper functions hide the UnsafeCell.
- **Heartbeat field stays cross-worker.** Watchdog readers (peer-side
  liveness check, supervisor) cannot tolerate 100ms-stale heartbeat.
  Stays atomic.
- **Owner-profile aggregation.** TBD — need to audit which counters
  are owner-profile related and decide if they fit category A or B.

## 6. Risk

| Class | Level | Why |
|---|---|---|
| Behavioral regression (counter semantics) | MED-HIGH | ~50 fields swept; one mistake = silent wrong telemetry |
| Snapshot tearing | LOW | Whole-block pointer swap is atomic |
| UnsafeCell discipline | MED | Compile time can't enforce single-writer; relies on code review |
| Lifecycle bugs (use-after-free of old published box) | MED | Need careful Drop / swap dance |
| Diff size | HIGH | ~30 file changes (every call site that touches BindingLiveState) |

## 7. Test plan

- `cargo build --release` clean
- `cargo test --release` 977+ pass
- `protocol_test.go` and `metrics_test.go` (Go side) — wire-compatibility check
  that the published JSON / Prometheus shape matches pre-refactor
- `perf stat -e LLC-load-misses,LLC-store-misses,instructions` on
  worker thread under iperf-c P=12 load: LLC-misses-per-packet ≤ 0.5×
  pre-refactor (the inverse of the gain — should drop)
- Aggregate throughput within ±1% of pre-refactor
- 5×flake on `afxdp::umem::tests::*`
- Manual smoke: `show binding 0` output identical pre/post

## 8. Out of scope

- True multi-writer counters (e.g., shared lease accounting). Stay
  atomic and padded.
- Owner-profile aggregation rework — separate effort if needed.
- Coordinator-side caching of snapshots (if scrape rate ever matters).
- Removing `BindingLiveSnapshot` indirection — it stays as the public
  read shape.

## 9. Open questions for adversarial review

1. **Lifecycle of the published box.** Two designs sketched:
   - (a) Fresh `Box` on every publish; atomic-swap pointer; old box
     reclaimed by the publisher (double-buffer recycle).
   - (b) Pre-allocate two boxes; alternate pointer between them.
   Pick one. (b) avoids any allocation on the publish path; (a) is
   simpler.
2. **Single-writer enforcement.** UnsafeCell in `BindingLiveState`
   allows multiple `&` references → multiple workers reading the
   same local. We need a runtime check (cfg(debug_assertions))
   asserting only the owning worker writes? Or rely on code review?
3. **Field classification.** The plan estimates "vast majority" are
   scrape-only. Need a complete audit before code touches anything.
   Ask reviewer to enumerate the cross-worker / heartbeat exceptions.
4. **Owner-profile impact.** Per Codex review, "owner profile
   structures" also have shared atomics. Should those move to the
   same double-buffer model, or stay separate?
5. **Cadence**. Does 1 Hz publish (driven by status loop) leave too
   much skew between worker observation and coordinator read? At line
   rate, 1 second of un-published RX/TX counters is ~14.8M packets
   delta. Operators will see "rate" graphs showing accurate values
   only after the publish — fine for Prometheus/monitoring (which
   already aggregate at ≥1Hz).

## 10. Verdict request

PLAN-READY → execute (estimated: 1 week of work + plan-review for
the lifecycle design).
PLAN-NEEDS-MINOR → tighten lifecycle / single-writer enforcement.
PLAN-NEEDS-MAJOR → revise (different approach, e.g., per-batch flush
into pre-published struct).
PLAN-KILL → diff complexity not worth the cycles saved.
