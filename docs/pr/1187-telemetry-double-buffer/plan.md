---
status: DRAFT v1 — pending adversarial plan review
issue: #1187
phase: Extend existing BatchCounters to cover disposition + screen_drops + tx_errors
---

## 1. Issue framing

Issue #1187 calls out MESI thrashing: `BindingLiveState` has ~50
atomics that the worker writes per-packet and the coordinator reads
on the status poll. At 14.8M pps, every counter increment on the
worker side is an L1-d cache-line invalidation request that the
coordinator core may be holding.

**Important context the issue body does not cite:** `BatchCounters`
(`afxdp/mod.rs:308-389`) already exists. It's a per-poll local
struct holding 12 fast counters (`rx_packets`, `rx_bytes`,
`rx_batches`, `metadata_packets`, `validated_packets`,
`validated_bytes`, `forward_candidate_packets`, `session_hits`,
`session_misses`, `session_creates`, `snat_packets`,
`dnat_packets`). It's threaded through `telemetry.counters` and
flushed to `BindingLiveState` at well-defined points
(`worker/lifecycle.rs:111,150,303`). The double-buffer pattern is
already half-shipped.

The gap is the *remaining* hot per-packet counters that bypass
`BatchCounters` and write to `BindingLiveState` directly:

| Site | Counters bypassed |
|---|---|
| `disposition.rs:87,92,104,117,130,158,166,179,192,205,218,231` | `validated_packets` (already in batch but written here too?), `exception_packets`, `config_gen_mismatches`, `fib_gen_mismatches`, `unsupported_packets`, `local_delivery_packets`, `policy_denied_packets`, `route_miss_packets`, `neighbor_miss_packets`, `discard_route_packets`, `next_table_packets` (~10 distinct counters, each fires per-packet on its disposition outcome) |
| `poll_stages.rs:276` | `screen_drops` |
| `tx/cos_classify.rs:803`, `worker/mod.rs:1653`, `cos/queue_service/service.rs:80,229,385,533` | `tx_errors` (6 sites) |

These all sit on the per-packet hot path and currently take the
`fetch_add(1, Ordering::Relaxed)` MESI hit per fire.

## 2. Honest scope/value framing

**The win:** every per-packet counter that moves from atomic
`fetch_add` → batched local++ saves one cache-line write per
packet for that counter. At 14.8M pps the per-counter saving is
~14.8 Mops/s of avoided RFO. The aggregate depends on traffic
mix:

- For pure-forward traffic on existing sessions, *most* of the
  counters fire 0× per packet (they're disposition-specific) — the
  only hot ones are `validated_packets` (already batched),
  `forward_candidate_packets` (already batched), `session_hits`
  (already batched). The proposed extension hits packets that
  diverge from happy-path forwarding.
- For traffic that exercises exception paths (config gen
  mismatch during reconcile, route miss, neighbor miss, policy
  deny), each of those packets pays the atomic. Worst case is
  during config reload when `config_gen_mismatches` /
  `fib_gen_mismatches` fires every packet for the duration of the
  reconcile.

**Realistic expected gain:** very small under steady-state happy-
path forwarding (~0% — the hot counters are already batched).
Visible during config reload windows (~50-100ms per reconcile)
and exception-rich workloads. *If reviewers conclude the gain is
too small to justify the churn, PLAN-KILL is acceptable.*

**The architectural value:** the current code is half-batched and
half-direct. Routing all hot per-packet counters through one
mechanism is a net legibility win regardless of the cycle
saving. After this PR, any new per-packet counter has one place
to live.

## 3. What's already shipped

- `BatchCounters` struct with 12 fields, `flush()` method, and
  `Default` impl (`afxdp/mod.rs:308-389`).
- `telemetry.counters: &'a mut BatchCounters` plumbed through
  `WorkerCtx<'a>` (`afxdp/types/runtime.rs:242`).
- Flush points at end-of-poll-binding and on shutdown
  (`worker/lifecycle.rs:111,150,303`).
- Write sites at `poll_descriptor.rs:59,379,2216` for
  `validated_packets`, `session_hits`, `rx_packets`.

This PR composes with that infrastructure; it does not replace
or rewrite it.

## 4. Concrete design

### 4.1 Extend `BatchCounters`

Add fields for every hot counter that's currently bypassing the
batch. Conservative selection — only counters that fire per-
packet on the worker poll path:

```rust
struct BatchCounters {
    touched: bool,
    // existing 12 fields...

    // disposition.rs
    exception_packets: u64,
    config_gen_mismatches: u64,
    fib_gen_mismatches: u64,
    unsupported_packets: u64,
    local_delivery_packets: u64,
    policy_denied_packets: u64,
    route_miss_packets: u64,
    neighbor_miss_packets: u64,
    discard_route_packets: u64,
    next_table_packets: u64,

    // poll_stages.rs
    screen_drops: u64,

    // tx_errors fires from tx/cos_classify.rs, worker/mod.rs,
    // cos/queue_service/service.rs (6 sites total)
    tx_errors: u64,
}
```

That's 12 new fields. Total `BatchCounters` size goes from
~108 bytes (12 × `u64` + `bool` + padding) to ~204 bytes
(24 × `u64` + bool). Stays well under one cache line worth of
spill but *does* fit two cache lines now — call out for review.

### 4.2 Route writes through the batch

`disposition.rs` currently takes `&BindingLiveState`. Change
signatures to take `&mut BatchCounters`. Two options:

- **Option A:** thread `&mut BatchCounters` through wherever
  disposition is called. Caller responsibility.
- **Option B:** add `disposition.rs` functions that take both
  `&BindingLiveState` (for cold field reads) and
  `&mut BatchCounters` (for the writes), and switch hot
  `fetch_add` sites to write through the batch.

Option B is the smaller diff. Pick Option B unless reviewers
prefer Option A's stricter encapsulation.

### 4.3 Extend `flush()`

Mirror the existing 12-counter flush block — `if self.X != 0 { live.X.fetch_add(...); self.X = 0; }`. The 12 added fields each get one such block.

### 4.4 Caller updates

- `disposition.rs` signatures change from `(live: &BindingLiveState, ...)` to `(live: &BindingLiveState, counters: &mut BatchCounters, ...)`. Update all callers (~5-10 sites).
- `poll_stages.rs:276` writes `screen_drops` — switch to `counters.screen_drops += 1`.
- `tx_errors` write sites: `tx/cos_classify.rs:803`, `worker/mod.rs:1653`, `cos/queue_service/service.rs:80,229,385,533`. These are 6 distinct call sites, each needs `&mut BatchCounters` in scope. Investigate whether `WorkerCtx` is available — if not, may need to pass through, which expands the diff.

## 5. Public API preservation

`BindingLiveState` field types and visibilities are unchanged.
`BatchCounters` is `struct` private to `afxdp`. No external API
changes.

## 6. Hidden invariants the change must preserve

- **Counter monotonicity:** `flush()` only adds; it never
  decrements. Tests / Prometheus collectors must continue to see
  monotonically increasing values.
- **Flush punctuality:** `flush()` fires at end of each
  `poll_binding`. Counter delay is bounded by one poll cycle
  (~50µs at line rate). Coordinator status poll runs once/s; can
  always catch up.
- **Order independence:** the existing 12 counters don't depend
  on flush order. The new 12 are also independent (each is its
  own atomic).
- **Crash safety:** if a worker panics between increment and
  flush, those counters are lost. Same as today — `BatchCounters`
  doesn't survive a panic, the existing 12 already have this
  behavior.

## 7. Risk assessment

| Class | Level | Why |
|---|---|---|
| Behavioral regression | LOW | Same flush semantics as the existing 12 batched counters; counters delay bounded by one poll cycle |
| Borrow-checker | LOW-MED | `&mut BatchCounters` adds another `&mut` parameter through disposition.rs / `tx_errors` sites; may collide with existing `&mut binding.tx_pipeline` etc. |
| Test breakage | LOW | Existing tests read final atomic values via `live.X.load()` — those still work after flush |
| Performance regression | LOW | 12 added fields fit in 2 cache lines; per-packet write now updates a private cache line; flush does N atomic adds per poll cycle (vs N atomic adds per packet today) |

## 8. Test plan

- `cargo build --release`: clean
- `cargo test --release`: 974/974 pass
- 5x flake check on a disposition-counter-touching test
- Smoke matrix on loss userspace cluster: 30 cells, 0 retrans
  (Pass A baselines + Pass B per-class CoS)
- **Verify counter visibility**: after smoke, `show binding`
  output should show non-zero `route_miss`, `neighbor_miss`,
  `policy_denied`, etc. counters when the relevant disposition
  fires (e.g., kill the route to trigger `route_miss`).

## 9. Out of scope

- 64-byte padding around `BindingLiveState` (separate refactor; the issue mentions it but it's invasive — every `BindingLiveState` instance becomes 64-byte-aligned which affects allocation patterns).
- NUMA-aware placement of `BindingLiveState` (also separate; coordinator is single-threaded today).
- Removing cold counters from `BindingLiveState` (e.g., `bound`, `xsk_registered`, `socket_fd` — these are written once at bind, no MESI churn).
- Per-CPU counters (would need re-aggregation in coordinator; large redesign).

## 10. Open questions for adversarial review

1. **Is the win measurable?** If the hot counters (`validated_packets`, `forward_candidate_packets`, `session_hits`) are already batched, what's the absolute cycle gain at 14.8M pps for the proposed extension during steady-state happy-path? If the answer is "essentially zero", PLAN-KILL is the right call.

2. **`BatchCounters` size growth (108 → 204 bytes)**: does spilling into a second cache line on the worker's hot stack cost more than the saving from atomic→batched conversions?

3. **`tx_errors` fan-out**: the 6 write sites span `tx/cos_classify.rs`, `worker/mod.rs`, and 4 `cos/queue_service/service.rs` sites. Does plumbing `&mut BatchCounters` through all these worth the diff size, or is `tx_errors` better left direct given it fires only on actual TX errors (rare)?

4. **Disposition.rs signature change**: many callers currently pass `(meta, live, ...)`. Adding `&mut BatchCounters` to the parameter list — is there a way to bundle this with `live` into a context type, or is the explicit param the cleaner option given the rest of the codebase's style?

5. **Should `screen_drops` even move?** It fires only on screen check rejections — fairly rare in practice. Maybe leave it direct.

## 11. Verdict request

PLAN-READY → execute the extension.
PLAN-NEEDS-MINOR → tweak scope (e.g., drop `screen_drops`/`tx_errors` from scope).
PLAN-NEEDS-MAJOR → revise (e.g., the size-growth concern justifies a different shape).
PLAN-KILL → premise wrong (e.g., expected cycle gain is too small to justify the churn — happy path counters are already batched, exception-path counters fire too rarely to matter).
