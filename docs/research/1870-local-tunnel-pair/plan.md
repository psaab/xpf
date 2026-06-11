# Plan: #1870 — local-tunnel `UpsertLocal` pair dropped at `max_sessions` while shared maps hold both entries

**Revision:** v1
**Date:** 2026-06-11
**Branch:** `research/1870-local-tunnel-pair` (off origin/master `9a536f810`)
**Issue:** #1870 (I13 exclusion follow-up from the #1861 converged plan, Codex
r1 C3 disposition; filed before #1861 /engineer per the §10 scope commitment)
**Mode:** /research — PLAN-READY or PLAN-KILL only. PLAN-KILL / close-as-fixed
is explicitly invited (§11 Q1). No production code in this phase.

---

## 1. Problem statement

`maybe_enqueue_local_tunnel_session` (`userspace-dp/src/afxdp/tunnel.rs:281`)
publishes the local-tunnel forward + synthesized-reverse session pair into the
three shared maps **unconditionally** (`tunnel.rs:306-321` via
`publish_shared_session`, `shared_ops.rs:780`), then enqueues
`WorkerCommand::UpsertLocal` × 2 to every worker (`tunnel.rs:329-331`). The
apply side (`session_glue/mod.rs:556-569`) routes through the **capped**
`SessionTable::install_with_protocol_with_origin` (`session/mod.rs:748`, cap
check at `:758`) and discards the `bool` result. At `max_sessions` the pair is
not installed in any at-cap worker table while the shared maps already hold
both entries.

#1871 (merged 2026-06-11, `6a11c52f5`) shipped the install-transaction
machinery for the packet hot path — `can_admit` pair preflight,
drop-on-refusal, the `create_drops`/`admission_refused`/`install_partial`
counter trio exported end-to-end — but **left the `UpsertLocal` arm
untouched** (verified on current master: the arm still calls the capped
install and drops the result).

## 2. Verified current behavior (origin/master `9a536f810`)

### 2.1 The producer (coordinator-side TUN reader thread)

`run_local_tunnel_endpoint`'s read loop (`tunnel.rs:73-95`) builds a
`LocalTunnelTxPlan` per local-origin packet
(`build_local_origin_tunnel_tx_request`, `tunnel.rs:146`). Both pair entries
carry `origin: SessionOrigin::SyncImport` — the forward entry at
`tunnel.rs:202`, the synthesized reverse at `shared_ops.rs:668`
(`synthesized_synced_reverse_entry`). Per-key re-enqueue is gated at ≥5 s
(TCP) / ≥1 s (other) by the `local_sessions` last-seen map
(`tunnel.rs:294-305`).

### 2.2 The exact at-cap interleaving

With every worker table at `max_sessions` (`len() == max_sessions`):

1. `local_sessions.insert(key, now_ns)` — re-enqueue suppressed for 1 s/5 s
   (`tunnel.rs:305`).
2. `publish_shared_session(forward)` + `publish_shared_session(reverse)` —
   shared maps + owner-RG indexes now hold **both** entries
   (`tunnel.rs:306-321`).
3. `UpsertLocal(forward)`, `UpsertLocal(reverse)` pushed to all N worker
   queues (`tunnel.rs:327-333`).
4. Each worker's `apply_worker_commands` consumes both commands;
   `install_with_protocol_with_origin` hits `len() >= max_sessions` at
   `session/mod.rs:758-761`, bumps `create_drops` (NEW since #1871 — this was
   the write-only counter), returns `false`; the arm discards it
   (`session_glue/mod.rs:560`).
5. `wait_for_local_tunnel_session_install` (`tunnel.rs:335,353`) returns as
   soon as the queues drain — drain ≠ install success, so the 1 ms wait
   provides no protection.

Result: shared maps hold the pair; **zero** worker tables hold either entry.

**Partial variant:** with exactly one free slot (`len() == max_sessions - 1`)
the forward install succeeds and the reverse fails — a worker table holding
the forward entry only, shared maps holding both. The pair has no preflight
(`can_admit(2)` is never consulted on this path).

**Per-worker variant:** worker tables are independent; workers below cap admit
the pair while at-cap workers drop it — divergence is per-worker, not global.

### 2.3 What diverges, and for how long

- **Worker fast path:** per-worker `SessionTable` misses fall back to
  shared-map lookups (mutex per packet) — traffic still flows, degraded
  (verified in the #1861 research walk, plan row I13: "YES-ish — per-packet
  shared-map lookups service traffic").
- **HA bulk export:** `handle_export_owner_rg_sessions` exports from the
  **worker table** — while all workers are at cap, local-tunnel sessions are
  absent from owner-RG bulk exports even though the shared maps (and the
  owner-RG shared indexes) hold them.
- **Incremental HA deltas:** unaffected either way — `SyncImport` origin
  suppresses `push_delta` in the install path (`session/mod.rs:797`), and the
  uncapped upsert path pushes no deltas at all.
- **Self-healing:** the install retries on the next ≥1 s/5 s re-enqueue window
  once table capacity frees; while the table stays at cap the divergence
  window is unbounded.

### 2.4 Honest residue vs #1871

#1871 closed the **silence** half of the original filing, partially:

- The at-cap `UpsertLocal` drop now increments `create_drops`
  (`session/mod.rs:759`), which is exported per-worker as
  `session_create_drops` → `ProcessStatus` → Prometheus. The issue's "minimum
  first step regardless of the chosen semantics: count the dropped
  `UpsertLocal` installs" is therefore **already shipped**, modulo
  attribution (the counter aggregates all non-preflighted at-cap install
  refusals; post-#1871 the packet hot path refuses via `admission_refused`
  *before* install, so `create_drops` increments now come predominantly from
  the `UpsertLocal` arm — making it a usable, if unlabeled, signal).
- The **divergence behavior is unchanged**: shared maps and worker tables
  still disagree at cap, partial forward-only installs still occur, and the
  bulk-export gap remains. That behavioral residue is this plan's target.

## 3. Why the #1871 pattern does not transplant directly

The #1871 fix is a **preflight before side effects** on the packet hot path:
`can_admit(needed)` runs on the same thread that owns the `&mut SessionTable`,
before any shared/NAT/flow-cache mutation, so refusal can drop the packet with
zero published state. The local-tunnel path inverts the topology:

- The **producer** (TUN reader thread) performs the side effects (shared-map
  publish) but cannot see any worker's table occupancy — tables are per-worker
  `&mut`-exclusive.
- The **consumers** (N workers) see occupancy but run after the publish, and
  each can independently admit or refuse.

A coordinator-side preflight is impossible without new cross-thread occupancy
plumbing; a consumer-side refusal cannot unwind the publish (another worker
may have admitted — rollback is incoherent at N>1). The design space is
therefore the arbitration the issue names: align `UpsertLocal` with the
capped family (and keep divergence) or with the uncapped sync family (and
eliminate it).

## 4. Design paths

### Path A (recommended): move `UpsertLocal` into the uncapped sync-family install

Replace the arm's capped install with the sync-family entry point:

```rust
WorkerCommand::UpsertLocal(entry) => {
    // #1870: local-tunnel pair entries are coordinator-authoritative
    // replicas of state ALREADY published to the shared maps — the
    // same family as the UpsertSynced replica fan-out (entries carry
    // SessionOrigin::SyncImport, tunnel.rs:202 / shared_ops.rs:668).
    // Routing them through the capped install let max_sessions refuse
    // the worker-table copy while the shared maps kept both entries
    // (unbounded shared-map/local-table divergence at cap).
    // allow_replace_local=true preserves the pre-#1870 replace
    // semantics of install_with_protocol_with_origin (which clobbers
    // any same-key entry below cap); the data is locally generated,
    // so the "don't let peer data clobber local sessions" guard does
    // not apply.
    debug_assert!(
        entry.origin.is_peer_synced(),
        "UpsertLocal entries must carry a sync-family origin; a local \
         origin would have pushed an HA delta on the old install path"
    );
    let installed = sessions.upsert_synced_with_origin(
        SessionInstall {
            key: entry.key,
            decision: entry.decision,
            metadata: entry.metadata,
            origin: entry.origin,
            now_ns,
            protocol: entry.protocol,
            tcp_flags: entry.tcp_flags,
        },
        /* allow_replace_local = */ true,
    );
    debug_assert!(installed, "upsert_synced_with_origin(_, true) is infallible");
}
```

**Equivalence proof below cap** (`install_with_protocol_with_origin` vs
`upsert_synced_with_origin(…, true)`, for entries with `SyncImport` origin):

| Step | capped install (`session/mod.rs:748`) | uncapped upsert (`session/mod.rs:834`) |
|---|---|---|
| cap check + `create_drops` | yes (`:758-761`) | none |
| local-clobber guard | none | bypassed by `allow_replace_local=true` (`:855-860`) |
| `remove_entry(&key)` | yes (`:775`) | yes (`:866`) |
| epoch, record fields (`closing`, timeouts, wheel_tick) | identical | identical |
| slab insert + `key_to_handle` + `index_forward_nat_key` + `push_to_wheel` | identical | identical |
| `push_delta` | suppressed: `origin.is_peer_synced()` is true for `SyncImport` (`:797`) | never pushes |
| return | `true` below cap | `true` always (only `false` exit is the bypassed guard) |

So below cap the change is **behavior-identical**; at cap the install now
proceeds, eliminating the divergence class. The discarded result becomes
provably-infallible (pinned by `debug_assert!` per the #1855 contract — both
asserts compile out in release, where the behavior is identical anyway).

**Why uncapping is sound here (the arbitration argument):**

1. The entries are already in the **uncapped** shared maps — worker-table
   refusal does not bound memory, it only creates disagreement. The
   worker-table copy is a bounded echo (≤ shared-map content).
2. The `UpsertSynced` replica fan-out (`replicate_session_upsert`,
   `session_glue/mod.rs:596`) already installs **every locally-created
   session** into **every other worker** uncapped (#1861 row I11). The
   local-tunnel pair joining that family adds ≤ 2 entries per distinct
   local-origin tunnel flow per ≥1 s/5 s window — a strict subset of an
   existing, much larger uncapped surface.
3. Entries expire via the timer wheel like any session; the producer is
   rate-limited per key and prunes its dedupe map (`tunnel.rs:339-351`).
4. **It does not preempt the I11 arbitration — it centralizes it.** Whatever
   the eventual sync-family cap decision is (cap, soft-cap, headroom), it
   will then cover `UpsertLocal` automatically instead of leaving a second,
   differently-divergent path.

**Counter semantics ride-along:** after Path A, `UpsertLocal` stops
contributing to `session_create_drops`. That is a *truthful* change — the
event is no longer a drop — and restores the trio's intended semantics:
`create_drops` = at-cap refusals of non-preflighted *capped* installs.
Document in `userspace-dp/src/session/README.md` (#1861 section).

### Path B: keep the cap, add attribution

Keep the capped install; on `false`, bump a dedicated
`local_tunnel_install_drops` counter (new wire field via the additive
pattern). Rejected as primary: the observability half is already ~shipped by
#1871 (§2.4), the divergence and partial-pair behavior remain, the HA
bulk-export gap remains, and it spends a wire field on attributing an event
Path A removes outright.

### Path C: rollback the shared publish on refusal

Producer publishes, workers refuse, someone unpublishes. Incoherent: workers
admit/refuse independently, so the shared entry must stay if *any* worker
admitted; the producer would need an N-way ack aggregation for two map
entries' worth of state, on a path with a 1 ms drain wait. Killed on
complexity-to-benefit.

### Path D: coordinator-side preflight

Requires cross-thread occupancy visibility (atomic len mirrors per worker) and
is still racy against in-flight packet-path installs between check and apply.
Killed.

## 5. Test plan (deterministic at-cap pins, debug AND release — #1855 contract)

New tests in `userspace-dp/src/afxdp/tests.rs` (reusing the #1871 at-cap
harness style: `set_max_sessions_for_test`, direct `apply_worker_commands`
invocation with a rigged queue) — names indicative:

1. `upsert_local_pair_installs_at_cap` — fill table to cap with distinct
   entries; enqueue the `UpsertLocal` forward+reverse pair (SyncImport
   origin, reverse via `synthesized_synced_reverse_entry` shape); apply;
   assert **both** keys resolve in the table, `len() == cap + 2`,
   `create_drops()` unchanged, `admission_refused()` unchanged,
   `install_partial()` unchanged. This pins the exact §2.2 interleaving
   through the fixed code.
2. `upsert_local_pair_no_partial_at_cap_minus_one` — one free slot; apply the
   pair; assert both installed (pre-fix this was the forward-only partial
   pin; the test documents the old failure mode in a comment).
3. `upsert_local_below_cap_replaces_existing_local_entry` — pre-install a
   `ForwardFlow`-origin session under the same key below cap; apply
   `UpsertLocal`; assert the entry is replaced and carries `SyncImport`
   origin (pins `allow_replace_local=true` = pre-change replace semantics,
   guarding against a future "tidy-up" to `false`).
4. Session-level: `upsert_synced_with_origin_allow_replace_is_infallible_at_cap`
   in `userspace-dp/src/session/tests.rs` if not already pinned by #1871's
   additions (verify before writing; do not duplicate).

Both profiles: `cargo test --release` (full suite) and debug
`cargo test session::` + the new afxdp tests run in both via the standard
gates. No live-cluster dependency — the interleaving is fully deterministic
in-process. Parent smokes post-merge; **failover smoke is warranted** since
the change touches a session-install path with HA bulk-export implications
(noted for the parent in the return).

## 6. Observability

No new wire fields, no protocol bump. Changes are semantic only:
`session_create_drops` stops counting `UpsertLocal` refusals because they no
longer occur (§4 Path A ride-along). The #1871 trio descriptors in
`pkg/api/metrics_descriptors.go` stay accurate (they describe at-cap install
refusals — still true). README note per §4.

## 7. Documentation

- `userspace-dp/src/session/README.md` — extend the #1861
  admission/transaction-boundary section: `UpsertLocal` is in the uncapped
  sync-family (with the §4 rationale), `create_drops` no longer includes it.
- `session_glue/mod.rs` arm comment (in the code, per the snippet).
- `worker_queue.rs:1-21` poison-recovery comment mentions the UpsertLocal
  pair — unaffected (commands remain individually self-contained); no edit.

## 8. Blast radius

- One arm in `session_glue/mod.rs` (~15 lines), tests, README. No protocol,
  no Go-side, no coordinator/producer change, no hot-path packet code.
- Risk surface: worker tables can now exceed `max_sessions` by local-tunnel
  pair volume — bounded by the §4 argument; identical in kind to the
  pre-existing I11 surface.
- Behavior below cap: provably identical (§4 table).

## 9. Failure modes considered

- **Same-key collision with a live local session:** preserved replace
  semantics (test 3). A refusal semantics (`allow_replace_local=false`) would
  *newly* let a stale non-tunnel session block the tunnel steering decision
  after a route change — a regression; rejected.
- **Future producer enqueues `UpsertLocal` with a local origin:** the old
  path would have pushed an HA delta, the new one never does — caught by the
  `debug_assert!(entry.origin.is_peer_synced())`.
- **Memory exhaustion via local-tunnel flow spray:** requires the local host
  stack to originate unbounded distinct flows into a TUN endpoint; those
  flows already grow the uncapped shared maps today. No new surface.

## 10. Non-goals / scope

- The global sync-family cap arbitration (#1861 row I11: should
  `upsert_synced_with_origin` be capped at all, and how, across HA activation
  prewarm + replica fan-out) stays open — this plan deliberately joins the
  existing family rather than deciding its future. If reviewers want it
  tracked, a dedicated I11 issue gets filed at /engineer time.
- No kernel/BPF `session_map_fd` publish from the `UpsertLocal` arm (the
  existing asymmetry vs `handle_upsert_synced` is pre-existing and
  unobserved-broken; out of scope).
- No change to the producer (publish ordering, 1 ms drain wait, refresh
  windows).

## 11. Open questions for adversarial review (PLAN-KILL invited)

1. **Close-as-fixed instead?** Is §2.4's "create_drops now counts it" enough
   to close #1870 with only a pin test of current behavior? The plan says no
   — the divergence/bulk-export residue is real and the fix is ~15 lines —
   but a reviewer may weigh the at-cap scenario as rare enough to not touch.
2. **`allow_replace_local=true` vs HA-computed:** `handle_upsert_synced`
   computes it from HA state (`synced_entry_allows_local_replace`). The plan
   argues constant `true` because the data is locally generated, not peer
   data — is there an HA interleaving (e.g. standby receiving peer-synced
   state for the same inner-flow key) where clobbering is wrong?
3. **Is the SyncImport origin itself correct for local-tunnel entries?**
   Pre-existing choice (delta suppression + peer-replace semantics ride on
   it). Out of scope to change, but a reviewer may argue the fix should not
   further entrench it.
4. **`len() > max_sessions` consumers:** does anything assume
   `len() <= max_sessions` as an invariant (allocation sizing, telemetry,
   percentage gauges)? Walk during /engineer; the I11 surface already
   violates it today, so any such consumer is already broken.
