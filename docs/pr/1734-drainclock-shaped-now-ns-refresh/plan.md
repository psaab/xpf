# #1734 — DrainClock: bounded `now_ns` refresh across shaped drain

**Status:** DRAFT v1 — pending adversarial plan review

## 1. Issue framing

`#1734` (sub-issue of `#1731`, the MEASURE-GATED CoS-MQFQ hardening
umbrella, finding #5) reports that the shaped TX drain reuses one
frozen `now_ns` for the entire drain pass:

- `tx/drain/mod.rs:96-101` builds `DrainCtx { now_ns, .. }` once. The
  `now_ns` it captures is `loop_now_ns`, sampled **once at the top of
  the worker poll loop** (`worker/loop_body/mod.rs:311`) — before the
  RX batch loop (`MAX_RX_BATCHES_PER_POLL = 4`, up to `RX_BATCH_SIZE`
  frames each) and the entire shaped drain run.
- `tx/drain/phase_shaped.rs:44-72` (`shaped_initial_drain`) and
  `:108-150` (`shaped_reingest_budget`) both loop
  `while should_enter_shaped_drain(binding) { drain_shaped_tx(binding,
  ctx.now_ns, ...) }`, passing the **frozen** `ctx.now_ns` into every
  iteration.

`drain_shaped_tx(binding, now_ns, ...)` threads that `now_ns` into:

- **Root + queue token refill** — `refill_cos_tokens(tokens, rate,
  burst, last_refill_ns, now_ns)` (`token_bucket.rs:252`). Refill is
  `elapsed_ns = now_ns - *last_refill_ns; added = elapsed * rate / 1e9`
  and then **stamps `*last_refill_ns = now_ns`**.
- **Park / wake-estimate** — `cos_root_can_service_after_prime(root,
  now_ns)` (`tx_completion.rs:277`) compares
  `cos_tick_for_ns(now_ns)` against each parked queue's
  `next_wakeup_tick`; `estimate_cos_queue_wakeup_tick(.., now_ns, ..)`
  computes the next runnable tick.
- **v8 shared-lease top-up** — `prime_cos_root_for_service` →
  `advance_cos_timer_wheel(root, now_ns)` +
  `maybe_top_up_cos_root_lease(root, lease, now_ns)`, and the
  per-queue `maybe_top_up_cos_queue_lease(.., now_ns, ..)`.
- **EWMA rate accounting** — `account_*` in `cos/fairness.rs:49`
  computes `dt_ns = now_ns - last_ns`, defers the roll when
  `dt_ns < EWMA_MIN_DT_NS (100_000 = 100 µs)`, and stamps
  `flow_bucket_last_tx_ns[b] = now_ns`.

**The frozen-clock mechanism (precise):**

1. First `drain_shaped_tx` of a pass: `refill_cos_tokens` sees
   `last_refill_ns` from a *prior* poll tick, computes a real
   `elapsed`, refills, then sets `*last_refill_ns = now_ns`.
2. Second and all later iterations of the **same** pass:
   `*last_refill_ns == now_ns` (frozen) ⇒ the
   `if now_ns <= *last_refill_ns` guard at `token_bucket.rs:267`
   fires ⇒ **zero tokens added** even though real wall time has
   advanced (each batch moves ≤ 64 frames through `sendto`/UMEM and
   takes real µs). The pass keeps *consuming* tokens but never
   *accrues* them. With a fresh clock per selection, real elapsed
   time would refill the bucket mid-pass.
3. EWMA: the second+ commit in a pass has `dt_ns = now_ns - last_ns`
   where `last_ns` was just stamped to `now_ns` ⇒ `dt_ns = 0 <
   100 µs` ⇒ the roll is always deferred within a pass ⇒ the smoothed
   per-bucket rate is one-poll-tick stale.
4. Park/wake: `cos_tick_for_ns(now_ns)` is frozen, so a parked queue
   whose `next_wakeup_tick` falls *during* the drain is not seen as
   runnable until the next poll tick samples a fresh `loop_now_ns`.

This is exactly finding #5 in `docs/research/1731-cos-mqfq-generalize/
plan.md` §4.5, which the three plan reviewers DOWNGRADED from "perf" to
**"correctness-hardening; measure-first"** (plan §3 row 5, §4.5, §6).

## 2. Honest scope / value framing

The win is **structural correctness of the shaper's internal
accounting across a multi-selection drain**, not a headline throughput
number. Concretely:

- **Token under-refill** caps how much a long, high-throughput shaped
  drain can move in one poll tick: once mid-pass refill is frozen, the
  root/queue buckets drain to zero and the pass ends early (queues
  park), deferring the residual backlog to the next poll tick. At
  realistic poll cadences and per-pass durations this is a *small*
  effect — the next poll tick re-samples the clock and refills — so it
  shows up as a mild latency/burstiness artifact, not a sustained
  throughput cliff. **This must be measured, not asserted.**
- **EWMA staleness** is a fairness/telemetry-accuracy effect (the v7
  per-bucket smoothed rate lags by one poll tick), not a forwarding
  bug.
- **Park/wake** staleness defers at most one poll tick of service for
  a queue whose wakeup lands mid-drain.

The poll loop already calls `monotonic_nanos()` **per drain-loop
iteration** (`phase_shaped.rs:45,48,123,126`) purely for the latency
histogram. The proposed fix **reuses that already-paid clock read** to
advance the drain's working `now_ns`, so the steady-state hot-path cost
is **zero additional VDSO calls** — we are spending a syscall we
already spend.

**If reviewers conclude the perf/correctness gain is too small to
justify the churn, PLAN-KILL is an acceptable verdict.** The #1731
reviewers explicitly flagged this as a possible no-op; the measurement
gate (§6) is the decider. If the fake-clock test + a perf/counter
trace show the freeze never materially under-refills at realistic batch
sizes, we narrow to a fake-clock-tested correctness hardening with NO
perf claim, or PLAN-KILL.

## 3. What's already shipped / partially batched

- `monotonic_nanos()` (`afxdp/neighbor.rs:3`) — `CLOCK_MONOTONIC`
  reader, already called twice per drain-loop iteration for the
  latency histogram (`start_ns` before `drain_shaped_tx`, end after).
- `DrainCtx<'a>` (`tx/drain/mod.rs:20-25`) carries `now_ns: u64` by
  value today; `drain_shaped_tx` takes `now_ns: u64` by value.
- The batch-anchored timestamp design is **intentional within a single
  batch commit** (`fairness.rs:37-40`, plan r1 SMR-F3 + Codex#3): one
  `apply_cos_*_result` commit samples once. The fix MUST NOT make the
  timestamp incoherent *within* a single `drain_shaped_tx` /
  `submit_cos_batch` commit — only *between* successive selections.

## 4. Concrete design

Introduce a `DrainClock` value type local to the shaped-drain phase
that owns the working `now_ns` and refreshes it in a **bounded** way,
reusing the latency-histogram clock read so no extra VDSO call is
added on the hot path.

```rust
// tx/drain/phase_shaped.rs (or a new tx/drain/clock.rs sibling)

/// Bounded re-sampling clock for the shaped drain phase.
///
/// `now_ns` starts at the poll-loop's `loop_now_ns` (one sample for
/// the whole tick) and is refreshed from the latency-histogram
/// `monotonic_nanos()` reads the drain loop *already* performs — so
/// no additional VDSO/clock_gettime is spent in steady state. A
/// monotonic guard keeps `now_ns` non-decreasing across selections so
/// token refill / EWMA dt never see a backward step on a transient
/// `monotonic_nanos() == 0` failure.
struct DrainClock {
    now_ns: u64,
}

impl DrainClock {
    #[inline]
    fn new(initial_now_ns: u64) -> Self {
        Self { now_ns: initial_now_ns }
    }

    /// Current working timestamp for this selection's accounting.
    #[inline]
    fn now(&self) -> u64 {
        self.now_ns
    }

    /// Advance from a fresh `monotonic_nanos()` sample that the
    /// caller already took for the latency histogram. Monotonic:
    /// never moves backward, never adopts a 0 (clock failure)
    /// sample.
    #[inline]
    fn observe(&mut self, sampled_ns: u64) {
        if sampled_ns > self.now_ns {
            self.now_ns = sampled_ns;
        }
    }
}
```

### Loop transformation (`shaped_initial_drain`)

Today each iteration does:

```rust
let start_ns = monotonic_nanos();
let serviced = drain_shaped_tx(binding, ctx.now_ns, shared_recycles);
... let delta = monotonic_nanos().saturating_sub(start_ns); ...   // histogram
```

The end-of-iteration `monotonic_nanos()` already exists. Rework so the
**end** sample both feeds the histogram AND advances the clock for the
**next** selection:

```rust
let mut clock = DrainClock::new(ctx.now_ns);
while should_enter_shaped_drain(binding) {
    let start_ns = monotonic_nanos();
    let serviced = drain_shaped_tx(binding, clock.now(), shared_recycles);
    let end_ns = monotonic_nanos();                       // already paid
    if let Some(serviced) = serviced.as_ref() {
        let bucket = bucket_index_for_ns(end_ns.saturating_sub(start_ns));
        ... histogram (unchanged) ...
        *did_work = true;
        clock.observe(end_ns);   // bounded refresh — 1 read/selection, already taken
    } else {
        ... noop counter ...
        break;
    }
}
```

`shaped_reingest_budget` is reworked the same way. The two phases share
**one** `DrainClock` so the timestamp is coherent across the whole
drain pass (initial + re-ingest) and only ever moves forward.

**Coherence within a single selection:** `drain_shaped_tx` still
receives ONE `now_ns` value (`clock.now()`) for the entire
prime → refill → service → commit → EWMA chain of that selection. We
refresh **between** selections, never inside one. This preserves the
intentional single-commit batch-anchoring (`fairness.rs:37-40`) that
the #1731 reviewers flagged as load-bearing.

**Bounded-ness:** exactly one `clock.observe()` per serviced
selection, fed by a `monotonic_nanos()` the loop already calls. No
per-packet clock read is introduced. (Each `drain_shaped_tx`
services at most one queue/one batch ≤ `TX_BATCH_SIZE = 64` frames, so
"per selection" is already coarser than per-packet.)

### Re-ingest `now_ns` for `ingest_cos_pending_tx_with_provenance`

`shaped_reingest_budget` also passes `ctx.now_ns` into
`ingest_cos_pending_tx_with_provenance` (enqueue path → `now_ns`
stamps enqueue time for fairness/CoDel ordering). Use `clock.now()`
there too so enqueue timestamps reflect the advanced clock.

## 5. Public API preservation

- `DrainCtx` keeps its `now_ns: u64` field (the *initial* sample); the
  refreshing is internal to the shaped phase. No external signature
  change.
- `drain_shaped_tx(binding, now_ns, shared_recycles)` signature
  unchanged — it still takes `now_ns: u64` by value.
- `refill_cos_tokens`, `cos_root_can_service_after_prime`,
  `estimate_cos_queue_wakeup_tick`, `prime_cos_root_for_service`,
  `maybe_top_up_cos_*_lease`, `account_*` — all unchanged.
- `drain_phase_drain_cos` entry point unchanged.

## 6. Hidden invariants the change must preserve

1. **Single-commit coherence:** one `drain_shaped_tx` call uses one
   timestamp for prime/refill/service/EWMA. Refresh is strictly
   between selections.
2. **Monotonicity:** `now_ns` must never step backward (token refill's
   `now_ns <= last_refill_ns` guard and EWMA `dt = now - last` both
   misbehave on a backward step). `DrainClock::observe` enforces
   non-decreasing and rejects 0 samples (transient clock failure).
3. **No extra VDSO on the hot path:** the refresh reuses the
   latency-histogram `monotonic_nanos()` read. Net steady-state
   clock-read count per iteration is unchanged (2: one start, one end;
   the end now does double duty).
4. **Allocation-free:** `DrainClock` is a single-`u64` stack value;
   zero heap. Honors the `DrainCtx` zero-alloc contract.
5. **Telemetry attribution unchanged:** the latency histogram still
   uses `end - start` for *this* iteration; we only reuse `end` to
   seed the *next* iteration's `now`.
6. **Re-ingest provenance unchanged:** `count_pps = false` on
   re-ingest stays false; only the `now_ns` argument advances.

## 7. Risk assessment

| Class | Rating | Notes |
|---|---|---|
| Behavioral regression | LOW | Mid-pass `now_ns` only ever advances; refill/EWMA/park math is identical, just fed a fresher (correct) clock. The frozen clock was the *buggy* input. |
| Lifetime / borrow-checker | LOW | `DrainClock` is a local `u64` wrapper; no borrows held across `&mut binding` calls. |
| Performance regression | LOW–MED | Reuses an existing clock read ⇒ no new VDSO. The ONLY way this regresses is if advancing the clock mid-pass causes *more* refill work — but refill is O(1) arithmetic, and more accurate refill is the intended behavior. Smoke must confirm no best-effort or shaped regression. |
| Architectural mismatch (#961 / #946-P2) | LOW | Not a rearchitecture; a scoped clock-threading fix in one phase file. The #1731 reviewers already endorsed this exact shape as "engineer-ready, measure-first." |

## 8. Test plan

- `cargo build` clean (release).
- **Fake-clock unit test (the gate):** a test that drives a
  `DrainClock`-equivalent across several selections and proves:
  (a) token refill *accrues* between selections when the clock
  advances (vs the frozen-clock baseline that adds zero on iteration
  2+), and (b) a wake/park estimate computed at an advanced clock sees
  a queue as runnable that the frozen clock would still consider
  parked. Drive `refill_cos_tokens` and `estimate_cos_queue_wakeup_tick`
  directly with a scripted clock so no real `monotonic_nanos()` is
  needed.
- `DrainClock` unit tests: monotonic guard (backward sample ignored),
  zero-sample rejected, forward sample adopted.
- 5×flake on the new fake-clock test.
- Full `cargo test --release` suite.
- Go suite (`go test ./...`) — expected untouched (Rust-only change),
  run for completeness.
- **Smoke on `loss:xpf-userspace-fw0/fw1`** full matrix:
  - Pass A (CoS disabled): v4+v6 × push+reverse single-stream
    (0 retrans) + `-P 12 -R` multi-stream line-rate v4+v6.
  - Pass B (CoS enabled): per-class 5201-5206 × v4+v6 × push+reverse
    (24 cells). **Large-shape throughput specifically confirmed not to
    regress** — the issue frames the freeze as a throughput risk
    "through large shapes," so the shaped classes are the cells that
    matter most here.

## 9. Measurement gate (decides ship vs narrow vs kill)

Per #1731 §4.5 + §6, BEFORE claiming any throughput win:

- The fake-clock test MUST show the frozen clock under-refills across a
  multi-selection pass (proves the mechanism is real, not theoretical).
- Smoke MUST show shaped-class throughput is **≥ baseline** (no
  regression) — and ideally that long-shape throughput / burstiness
  improves or is unchanged.
- If smoke shows the fix is a pure no-op on throughput (likely, since
  the next poll tick re-refills), we still ship it as a
  **correctness-hardening** change (the internal accounting is now
  coherent and unit-pinned) but make NO perf claim in the PR body —
  avoiding the unverified-perf-claim kill class (MEMORY #1317).

## 10. Out of scope (explicitly)

- Re-sampling `now_ns` inside the RX batch loop or the trivial/backup
  drain phases (#1734 is shaped-drain-specific).
- Any change to `loop_now_ns` sampling cadence in the worker loop.
- The other #1731 findings (#1, #2, #3, #4, #6) — owned by sibling
  issues #1732/#1733 and the umbrella.
- CoDel / FQ-CoDel (#1731 finding #4).

## 11. Open questions for adversarial review

1. **Is the freeze real at realistic batch sizes, or a no-op?**
   Is a single shaped-drain pass long enough (enough selections × real
   µs/batch) that mid-pass token under-refill materially shortens the
   pass before the next poll tick re-refills? If not, is this worth
   shipping even as correctness-hardening, or PLAN-KILL?
2. **Reusing the histogram `monotonic_nanos()` read** — is the
   end-of-iteration sample semantically correct to seed the *next*
   selection's `now`, or does the time between `end_ns` and the next
   `drain_shaped_tx` call introduce a (negligible) backdated skew that
   matters?
3. **Monotonic guard sufficiency** — `observe` rejects backward and
   zero samples. Is there any path where a *legitimately* larger
   `last_refill_ns` (set by a concurrent peer worker on a shared lease)
   interacts badly with an advanced per-worker `now_ns`? (Leases are
   shared across workers; refill stamps are per-bucket.)
4. **EWMA dt semantics** — advancing `now_ns` mid-pass means the
   second commit in a pass now gets a *non-zero* `dt_ns` (real elapsed)
   instead of 0. Does crossing `EWMA_MIN_DT_NS` more often change the
   smoothed-rate behavior in a way that affects #1217 fairness
   contract compliance? Could it *worsen* fairness?
5. **Within-batch coherence** — confirm `drain_shaped_tx` does not
   internally re-enter a second selection such that one `clock.now()`
   value spans two logically distinct commits (which would break the
   single-commit anchoring invariant).
6. **Is fixing only the shaped phase the right scope?**
   `phase_backup.rs:79-80,159-165` also loops passing `ctx.now_ns` into
   `transmit_prepared_batch` / `transmit_batch` (the unshaped backup
   transmit), and `phase_trivial.rs:31,49` uses `ctx.now_ns` for
   `maybe_wake_tx`. Those paths do NOT drive CoS token refill / EWMA /
   park accounting (they are the post-CoS / non-CoS transmit fallback),
   so the frozen clock there has no shaper-accounting consequence — the
   plan deliberately scopes to shaped only. Reviewers: confirm there is
   no shaper-accounting state reached through the backup path that would
   also be under-refilled by a frozen clock, leaving a half-fix.
