---
status: DRAFT v1 — pending adversarial plan review (PLAN-KILL is on the table)
issue: #1188
phase: Investigate consolidating per-tick ArcSwap loads in worker_loop
---

## 1. Issue framing

Issue #1188 claims `BindingWorker` / `worker_loop` performs "up
to 8 separate `ArcSwap` pointers on every iteration" and asserts
this saturates the QPI/UPI bus.

**Reality check** (`userspace-dp/src/afxdp/worker/mod.rs:445-490`):
worker_loop has **11** `Arc<ArcSwap<...>>` parameters in its
signature, but the per-call-frequency varies wildly:

| Arc field | When loaded | Cost |
|---|---|---|
| `shared_validation` | Once at init (line 488); per-tick refresh on config-gen change (line 721) | 1 cached + occasional |
| `shared_forwarding` | Once at init via `load_full()` (line 489) | 1 cached |
| `shared_cos_owner_worker_by_queue` | Once at init (line 490) | 1 cached |
| `shared_cos_owner_live_by_queue` | Once at init | 1 cached |
| `shared_cos_root_leases` | Once at init | 1 cached |
| `shared_cos_queue_leases` | Once at init | 1 cached |
| `shared_cos_queue_vtime_floors` | Once at init | 1 cached |
| `ha_state` | Per-tick refresh (line 801) | 1/tick |
| `shared_fabrics` | Per-tick refresh (line 908) | 1/tick |
| `local_tunnel_deliveries` | Reference-only on tunnel paths | rare |
| `cos_status` | Read by status path, not hot | rare |

**Actual atomic load count on hot path**: ~3 `.load()` calls per
poll tick (`shared_validation` refresh + `ha_state` + `shared_fabrics`).
A poll tick processes a batch of ~64 packets, so per packet
the cost is ~3/64 = **0.047 atomic loads/packet**. At 14.8M pps
that's ~700k atomic loads/sec — not nothing but two orders of
magnitude smaller than the issue body's "hundreds of millions
per second" claim.

The issue body's QPI/UPI saturation framing is exaggerated.
But the underlying observation — that there are *some* per-tick
atomic loads worth consolidating — is real.

## 2. Honest scope/value framing

**Pessimistic case:** the proposed `ImmutableRuntime`
consolidation lumps `shared_validation`, `ha_state`, and
`shared_fabrics` into a single `Arc<ArcSwap<ImmutableRuntime>>`.
Worker does one `.load()` per tick. That saves 2 atomic ops per
tick. At ~10k ticks/sec per worker × 8 workers = 160k ops/sec
saved. Trivial.

**Plausible case:** the *coordinator side* cost grows. Today,
when only HA state changes, only `ha_state` is republished. With
consolidation, ANY change rebuilds the entire `ImmutableRuntime`
snapshot. HA changes are rare (failover events), but config
reload and fabric updates each force a full snapshot rebuild.
That's net negative on coordinator CPU.

**The architectural win:** consistency. Today, a worker that
loads `ha_state` but not `shared_fabrics` in the same tick can
see torn updates between them. Bundling them into a single
snapshot guarantees consistency. *That* is the legitimate value
proposition — not bus traffic.

**If reviewers conclude:**
- the per-tick atomic-load saving is too small (~2-3 ops/tick),
- AND the consistency argument doesn't justify forcing every
  control-plane mutation to rebuild the entire snapshot,

then **PLAN-KILL is the right call.** This refactor would be
churn for negligible gain.

## 3. What's already shipped

- 11 `Arc<ArcSwap<...>>` fields in worker_loop signature
- Worker caches `forwarding`, `cos_*` states in local `mut`
  variables at init; only reloads on explicit triggers
  (config-gen mismatch, RG transition).
- `ha_state` and `shared_fabrics` reload per-tick
- `shared_validation` reloads on config-gen change

## 4. Concrete design (if not killed)

1. Define `ImmutableRuntime` containing the 3 per-tick-loaded states:
   ```rust
   struct ImmutableRuntime {
       validation: ValidationState,
       ha_runtime: BTreeMap<i32, HAGroupRuntime>,
       fabrics: Vec<FabricLink>,
   }
   ```
2. Replace 3 separate `Arc<ArcSwap<...>>` with one `Arc<ArcSwap<ImmutableRuntime>>`.
3. Coordinator update path: when any of the 3 states change, rebuild full snapshot, swap.
4. Worker: single `.load()` per tick → `&ImmutableRuntime` reference passed down.

**The cost question:** rebuild requires cloning the unchanged 2
states. `ValidationState` is a small struct; `BTreeMap<i32, HAGroupRuntime>`
is bounded by # of redundancy groups (typically 1-4); `Vec<FabricLink>`
is tiny. Cloning all three on each update is cheap, but not free.

## 5. Public API preservation

worker_loop signature changes (3 separate params → 1 consolidated).
Coordinator builds the snapshot. Internal-only change.

## 6. Hidden invariants the change must preserve

- HA RG transitions must propagate to workers within the same
  poll tick they fire on the coordinator side.
- Config-gen mismatch detection must continue to trigger
  validation refresh.
- Fabric link changes must be visible by next tick.

## 7. Risk assessment

| Class | Level | Why |
|---|---|---|
| Behavioral regression | LOW | Same data, single pointer |
| Coordinator CPU cost | **MED** | Snapshot rebuild on every state change of any of the 3 |
| Borrow-checker | LOW | Single `Arc<ArcSwap<...>>` is cleaner than 3 |
| Performance regression | LOW | Worker side strictly faster (1 load vs 3) |
| Architectural mismatch | LOW-MED | Consistency win is real; bus-traffic-saturation framing is wrong |

## 8. Test plan

- `cargo build --release`: clean
- `cargo test --release`: 974/974 pass
- 5x flake check on `make test-failover` — HA path is most affected
- Smoke matrix on loss userspace cluster: 30 cells, 0 retrans
- **HA stress**: rapid `request chassis cluster failover` cycle to
  verify coordinator snapshot rebuild keeps up

## 9. Out of scope

- The 5 `shared_cos_*` fields (loaded once at init, cached) — no
  per-tick load reduction available
- `local_tunnel_deliveries`, `cos_status` (not on hot path)
- `dynamic_neighbors` — already a `ShardedNeighborMap`, not a
  bare `ArcSwap`
- Parameter-list cleanup of worker_loop's 30+ args (separate
  refactor, larger scope)

## 10. Open questions for adversarial review

1. **Is this PLAN-KILL?** Per-packet atomic-load savings ~700k/sec. Is the consistency argument alone worth the churn, or is this churn-for-aesthetics?

2. **Coordinator rebuild cost:** the snapshot must be rebuilt on every change of any of {validation, ha_runtime, fabrics}. Concretely: under a config reload that triggers all three within a 100ms window, the coordinator does 3 rebuilds. Each rebuild clones ~3 small structs. Is this measurable?

3. **Why NOT also consolidate the `shared_cos_*` fields?** The plan keeps them as 5 separate `Arc<ArcSwap<...>>`. Justify: they're loaded once at init, cached in mut locals, and CoS reload is rare. But if we're consolidating for consistency, why exclude these?

4. **Tear semantics:** today, a config-reload + HA failover within microseconds of each other could leave a worker seeing new validation but old ha_runtime in the same tick. Does that actually cause an observable bug, or is the codepath already tolerant?

5. **Comparison with #946 / #945 context-object work:** is the right fix here actually a `WorkerSnapshot` parameter type that bundles all the args worker_loop takes (~30 params), rather than a narrow `ImmutableRuntime` for 3 of them?

## 11. Verdict request

PLAN-READY → execute consolidation as designed.
PLAN-NEEDS-MINOR → tweak (e.g., include or exclude specific fields).
PLAN-NEEDS-MAJOR → revise (e.g., adopt the broader WorkerSnapshot framing).
**PLAN-KILL → premise wrong**: the cited "hundreds of millions of atomic operations per second" is wrong by ~1000×; the actual saving is ~2-3 ops/tick; the consistency argument is real but minor; the coordinator rebuild cost may even net out negative. If the cycle math doesn't justify it, kill.
