---
status: REVISED v7 — Codex round-6 NEEDS-MINOR fixes: scrub stale "Option A" text at lines 95 and 194 (§4.4 no longer uses Option A/B framing); correct §4.4 framing about cold-path firing rate ("operator/RPC-driven cold path, not worker per-packet" — coordinator/inject.rs is RPC injection, not 1Hz status poll)
issue: #1187
phase: Extend BatchCounters via TelemetryContext to cover hot disposition counters
---

## 1. Issue framing

`BindingLiveState` (`afxdp/umem/mod.rs:197`) holds ~50 atomics
that the worker writes per-packet on disposition outcomes and the
coordinator reads on the 1Hz status poll. At 14.8M pps, every
direct `fetch_add(1, Ordering::Relaxed)` is a cache-line
invalidation request that the coordinator core may be holding —
classic MESI ping-pong on the QPI/UPI bus.

**The real motivation (per Gemini Pro 3.1 round-1 reframe): DDoS
resilience and congestion isolation.** Exception paths in a
firewall *are* attack paths:
- SYN flood → `screen_drops` fires per dropped packet
- Volumetric attack on a blocked port → `policy_denied_packets`
  per dropped packet
- Misrouted traffic during reconcile → `route_miss_packets`,
  `next_table_packets`
- Neighbor cache stale → `neighbor_miss_packets`

If these counters write through unbatched atomics during an
attack, the worker core continuously incurs RFO stalls from the
coordinator's status reads, dropping the worker's processing
capacity. Batching these counters is **mandatory for
cross-interface congestion isolation**, not an optional
optimization.

**Existing infrastructure** (`afxdp/mod.rs:308-389`):
`BatchCounters` already exists with 12 fast counters and a
`flush()` method. A few fields (e.g., `forward_candidate_packets`) are *defined*
in `BatchCounters` AND have a separate direct-write site at
`disposition.rs:161`. The direct-write site is on the cold
coordinator-inject path, not the hot worker path — so it's a
*consistency* issue, not a hot-path leak. The hot path already
routes correctly through `telemetry.counters` at
`poll_descriptor.rs:213,1706`.

## 2. Honest scope/value framing — corrected per Codex round-1

**v1 scope was too broad.** Codex round-1 found 5 substantive
issues, all valid:

1. **`tx_errors` is not architecturally ready for batching.**
   Real fan-out is much wider than 6 sites: also `umem/mod.rs`,
   `tx/drain.rs`, `tx/transmit.rs`, `cos/queue_service/mod.rs`,
   `worker/cos.rs`. `BatchCounters` is created *after* the first
   `drain_pending_tx()` call in `worker/lifecycle.rs:59`, so a
   TX-only error during early drain would be silently lost. Also
   `tx_errors` is the generic superset of dedicated counters
   like `tx_submit_error_drops`; partial batching makes
   snapshots inconsistent. **DROP `tx_errors` from this PR.**
   It needs its own design (separate ticket).
2. **Perf model overstated.** Steady happy-path forwarding gains
   ~0% (those counters are already batched). Real saving is
   `14.8M × event_fraction × counters_per_event`, not
   `14.8M × N_added_counters`. A 1% exception rate saves ~148k
   atomic ops/sec; a 100ms config-reload window saves ~1.5M-3M
   atomic ops total — much smaller than the issue body implies.
3. **Size math wrong.** `BatchCounters` is currently 12 u64 +
   bool ≈ **104 bytes** (not 108), spanning 2 cache lines.
   Adding 11 fields → 23 u64 + bool ≈ **192 bytes**, spanning
   **3 cache lines** (not 2). The cold lines aren't touched on
   happy path so the cache cost is OK, but the plan must stop
   claiming a 2-line structure.
4. **Disposition API plan underspecified.** `record_disposition()`
   is called from BOTH worker hot path
   (`poll_descriptor.rs:2071`) AND cold coordinator injection
   (`coordinator/inject.rs:43`). A mandatory `&mut BatchCounters`
   parameter breaks the cold caller. Use existing
   `TelemetryContext` (`types/runtime.rs:239`) for hot path,
   split hot/cold recording functions, OR pass `Option<&mut
   BatchCounters>`.
5. **Site table misleading.** `validated_packets` write at
   `disposition.rs:87` is NOT happy-path RX; happy path is at
   `poll_descriptor.rs:58` where it's already batched. The
   `forward_candidate_packets` write at `disposition.rs:161` is
   inside `record_forwarding_disposition::ForwardCandidate`,
   which is reached from coordinator inject (cold path), NOT
   from the hot worker forwarding branch. The hot path already
   routes `forward_candidate_packets` through
   `telemetry.counters.forward_candidate_packets` at
   `poll_descriptor.rs:213` and `:1706`. So `disposition.rs:161`
   is a *cold* path write — fixing it is consistency cleanup,
   not a hot-path perf fix. Update the framing accordingly.

**v2 scope (narrowed):**

A. **No change to `disposition.rs:161`** — it's on the cold
   coordinator-inject path. Hot path already routes correctly.
   Section 4.4 documents the rationale (leave the
   cold direct write).
B. **Add 8 new fields to `BatchCounters`** for the disposition
   path:
   - `screen_drops` (DDoS-critical; SYN flood)
   - `policy_denied_packets` (DDoS-critical; blocked port flood)
   - `route_miss_packets` (reconcile-critical)
   - `neighbor_miss_packets` (NDP/ARP storm-critical)
   - `discard_route_packets` (rare but per-packet on path)
   - `next_table_packets` (per-packet on inter-VRF leak path)
   - `local_delivery_packets` (per-packet for slow-path)
   - `exception_packets` (NOT a sum — fires only on metadata-disposition exceptions and HAInactive today; this PR preserves that semantics, does not extend it to count `PolicyDenied` / `NoRoute` / `MissingNeighbor` / `DiscardRoute` / `NextTableUnsupported` paths which only call `record_exception()` without bumping `exception_packets`)
C. **Defer**: `config_gen_mismatches`, `fib_gen_mismatches`,
   `unsupported_packets`. These fire only during reconcile and
   are gated by other expensive work (`record_exception()` does
   mutex + timestamp + string + deque). Adding them is small
   incremental win; defer to a follow-up.
D. **Defer all of `tx_errors`.** Codex round-1 finding #1.

## 3. What's already shipped

- `BatchCounters` struct and `flush()` (`afxdp/mod.rs:308-389`)
- `TelemetryContext` (`types/runtime.rs:239`) which already
  threads `&mut BatchCounters` through the hot path via
  `WorkerCtx`
- 12 fast counters batched: `rx_packets`, `rx_bytes`,
  `rx_batches`, `metadata_packets`, `validated_packets` (RX
  side), `validated_bytes`, `forward_candidate_packets` (also
  written via the cold coordinator-inject path at
  `disposition.rs:161`; left direct in this PR — see §4.4),
  `session_hits`, `session_misses`,
  `session_creates`, `snat_packets`, `dnat_packets`
- Flush at `worker/lifecycle.rs:111,150,303`

This v2 PR composes with that infrastructure.

## 4. Concrete design

### 4.1 Extend `BatchCounters`

Add 8 fields:

```rust
struct BatchCounters {
    touched: bool,
    // existing 12 fields...

    // NEW (v2 narrowed scope):
    screen_drops: u64,
    policy_denied_packets: u64,
    route_miss_packets: u64,
    neighbor_miss_packets: u64,
    discard_route_packets: u64,
    next_table_packets: u64,
    local_delivery_packets: u64,
    exception_packets: u64,
}
```

Total: 20 u64 + bool ≈ **168 bytes**. Current `BatchCounters`
already spans **2 cache lines** (104 bytes). Appending 8 new
fields grows it to **~3 cache lines**.

Important caveat: Rust struct layout is unspecified by default.
We do *not* add `#[repr(C)]` here — the compiler may reorder
fields. The intended invariant is that the existing 12 counters
keep their happy-path access pattern unchanged and the 8 new
counters sit in cold lines that are only touched on disposition
divergence. **In practice** the rustc layout heuristic places
same-type fields contiguously, so 20 `u64`s should pack
sensibly. If this becomes a measured perf concern, a follow-up
PR can add `#[repr(C)]` + an explicit field order — defer that
until measurement justifies the constraint.

### 4.2 Routing through `DispositionCounters<'a>` enum (Codex finding #4)

Both `record_disposition()` and `record_forwarding_disposition()`
are called from both hot and cold paths. The implementation uses a
single `DispositionCounters<'a>` enum to dispatch at call time:

```rust
pub(super) enum DispositionCounters<'a> {
    Hot(&'a mut BatchCounters),
    Cold(&'a BindingLiveState),
}
```

- **Hot callers** (`poll_descriptor.rs:2071`, `poll_descriptor.rs:2096`)
  pass `DispositionCounters::Hot(telemetry.counters)`. Per-packet
  counter increments land in the `BatchCounters` and flush at the
  end of the poll tick.

- **Cold callers** (`coordinator/inject.rs:43`, `coordinator/inject.rs:59`)
  pass `DispositionCounters::Cold(live)` and write directly to
  `BindingLiveState` atomics. The coordinator path doesn't have a
  `BatchCounters` in scope and fires at RPC rate, not per-packet.

Each `bump_*` method on `DispositionCounters` carries `#[inline]`
so the Hot/Cold dispatch is devirtualized by the compiler at
each call site.

(§4.4 leaves the cold `ForwardCandidate` arm's direct write to
`live.forward_candidate_packets` because it's only reachable
from coordinator inject, not the hot path.)

### 4.3 Extend `flush()`

Mirror the existing pattern — `if self.X != 0 { live.X.fetch_add(...); self.X = 0; }`. 8 new blocks.

### 4.4 `disposition.rs` cold-path `ForwardCandidate` write (out of scope for this PR)

`record_forwarding_disposition`'s `ForwardCandidate` arm does
`live.forward_candidate_packets.fetch_add(...)` inside the
`DispositionCounters::Cold` branch. The hot worker forwarding
branches DO NOT reach this site — the hot path increments
through `telemetry.counters.forward_candidate_packets` at
`poll_descriptor.rs:213,1706`. The cold-branch write
is reached only from coordinator inject.

The PR keeps the cold `ForwardCandidate` arm direct: the
coordinator-inject caller passes `DispositionCounters::Cold(live)`,
the write is operator/RPC-driven, not on the worker per-packet
path, and there's no MESI-thrashing concern. If review-time
measurement shows it matters, a follow-up PR can build a
coordinator-side counter-batching mechanism — out of scope here.

### 4.5 `screen_drops` site (MANDATORY batching, no fallback)

`poll_stages.rs` had `binding_live.screen_drops.fetch_add(1)`.
**This PR threads `&mut BatchCounters` into `stage_screen_check`**
so that screen_drops increments go through the batch rather than
writing directly to `BindingLiveState`.

`stage_screen_check` receives `counters: &mut BatchCounters`
directly (not `TelemetryContext`) — it only needs the counter
field, not the full telemetry context, and narrowing the
dependency keeps the signature minimal.

Both round-2 reviewers (Codex + Gemini Pro 3.1) explicitly
rejected the "leave it direct" fallback because SYN flood is a
primary attack vector — unbatched `screen_drops` increments
during a flood would re-create the exact RFO storm this PR
exists to eliminate.

## 5. Public API preservation

- `BindingLiveState` field types and visibilities unchanged.
- `BatchCounters` is `struct` private to `afxdp`.
- `record_disposition()` callers update to either hot or cold
  variant.
- No external API changes.

## 6. Hidden invariants the change must preserve

- **Counter monotonicity:** `flush()` only adds; never decrements.
- **Flush punctuality:** bounded by one poll cycle (~50µs at line rate).
- **Order independence:** counters are independent atomics — no flush-order dependency.
- **Crash safety:** worker panic between increment and flush loses those counts. Same as today for the existing 12.
- **Cold-path consistency:** the coordinator inject path keeps
  direct writes (rare; status correctness, not perf).

## 7. Risk assessment

| Class | Level | Why |
|---|---|---|
| Behavioral regression | LOW | Same flush semantics as existing 12 counters; coordinator inject keeps direct writes |
| Borrow-checker | LOW-MED | Splitting hot/cold disposition recorder may force refactor of intermediate callers |
| Test breakage | LOW | Tests read final `live.X.load()` values — unchanged after flush |
| Perf regression | LOW | 8 new fields grow `BatchCounters` from ~2 → ~3 cache lines. Layout is unspecified (no `#[repr(C)]`), but rustc's same-type-contiguous heuristic should keep the existing 12 counters in their happy-path lines. If measurement shows otherwise, a follow-up `#[repr(C)]` + explicit field order can pin the layout |
| Cross-talk on attack/congestion | **the win** | Eliminates RFO storm during SYN flood / policy denial / route miss |

## 8. Test plan

- `cargo build --release`: clean
- `cargo test --release`: 974/974 pass
- 5x flake check on a disposition-touching test
- Smoke matrix on loss userspace cluster: 30 cells, 0 retrans
- **Counter visibility verification**: trigger each disposition
  (kill route → `route_miss`; flood blocked port →
  `policy_denied`; etc.) and confirm `show binding` reflects
  non-zero counters within 1s.
- **DDoS isolation regression**: optional —
  during a SYN flood targeted at an interface served by worker
  N, verify another interface served by the same worker
  continues to forward at line rate. (May be hard to set up;
  defer to a follow-up validation.)

## 9. Out of scope

- `tx_errors` batching — separate PR with its own design (Codex finding #1).
- `config_gen_mismatches`, `fib_gen_mismatches`, `unsupported_packets` — small incremental wins, deferred.
- 64-byte padding around `BindingLiveState` — separate refactor; affects allocation patterns globally.
- NUMA-aware placement.
- Per-CPU counters (large redesign).

## 10. Open questions for adversarial review

1. **Hot/cold split shape**: does `record_disposition_hot` /
   `record_disposition_cold` cleanly split, or is the shared
   body too entangled to factor? Implementation phase will tell.

2. ~~Should screen_drops thread through TelemetryContext?~~
   **Resolved (round-3): yes, mandatory; threading `TelemetryContext`
   not `&mut BatchCounters`.** See §4.5.

3. ~~3 cache lines vs 2?~~ **Resolved (round-3+round-5):** ~3
   lines is fine; rustc's same-type-contiguous heuristic should
   keep the existing 12 counters in their happy-path lines. No
   strong "no new line touched" guarantee without `#[repr(C)]`.
   See §4.1 caveat.

4. **Should the v2 plan also fold in the Codex-deferred
   counters** (`config_gen_mismatches` etc.) once `tx_errors`
   is dropped from scope, so the diff size is similar to v1?
   Or keep the strict narrow scope?

5. **Is the "DDoS isolation" framing testable in CI?** The
   smoke matrix doesn't exercise an active SYN flood. Should
   we add a flood-test cell to the matrix as part of this PR?

## 11. Verdict request

PLAN-READY → execute the narrowed v2 scope.
PLAN-NEEDS-MINOR → tweak (e.g., include or exclude specific deferred counters).
PLAN-NEEDS-MAJOR → revise (e.g., the hot/cold split is wrong, need a different shape).
PLAN-KILL → premise wrong (unlikely given Gemini Pro 3.1 round-1 PLAN-READY with strong DDoS-isolation reframe).
