# Plan: #1870 — local-tunnel `UpsertLocal` pair dropped at `max_sessions` while shared maps hold both entries

**Revision:** v5
v5 folds round-4 (Codex PLAN-NEEDS-CHANGES ×1 Low): the two remaining
absolute "no worker-RX consumer" shorthands (§2.3 counter-signal bullet, §4
point 2) qualified to "no normal local-origin worker-RX path/consumer" with
a §2.3 back-reference. Codex r4 confirmed r3-1/r3-2 otherwise fully folded.

v4 folded round-3 (Codex PLAN-NEEDS-CHANGES ×2 Low, AGY PLAN-READY no
findings):
- **Codex r3-1 (Low, accepted):** stale full-pair self-heal wording in §1,
  the §2.3 counter-signal bullet, the §4 arm comment, and Path E narrowed to
  reverse-half-only; forward stays absent until a later successful
  re-enqueue.
- **Codex r3-2 (Low, accepted):** "no RX consumer" made precise — worker RX
  has a generic exact-key local lookup (`shared_ops.rs:528`,
  `session_glue/mod.rs:911`) that normal local-origin traffic never reaches,
  and no forward-wire alias exists for default-NAT entries because the
  forward-wire index only inserts when `wire_key != key`
  (`session/mod.rs:1478`). Consequently §5 test 1 must assert via exact
  forward-key lookup, NOT `find_forward_wire_match` (which never holds
  these entries) — test spec corrected.

v3 folded round-2 (Codex PLAN-NEEDS-CHANGES ×2, AGY PLAN-READY ×2 Low, SMR
PLAN-READY-contingent):
- **Codex r2-1 (Medium, accepted):** the v2 "self-heals on first traversing
  packet" claim holds only for the **reverse** half. Inbound tunnel replies
  are decapped and traverse `resolve_flow_session_decision`
  (`poll_descriptor/mod.rs:121,257`) and materialize the reverse shared hit;
  but local-origin packets ride TUN → coordinator → TX (`tunnel.rs:72-101`)
  and never traverse worker RX resolution, and no RX packet matches the
  forward key — so the **forward** entry stays absent until a successful
  re-enqueue after capacity frees (≥1 s/5 s windows). §2.3 reworded
  accordingly; severity framing unchanged (the forward entry has no RX
  consumer on the worker, which is also why its absence was never observed).
- **Codex r2-2 = AGY r2-1 (Low, accepted):** `allow_replace_local=true` also
  changes **at-cap same-key replacement**: the old capped install refused
  before reaching `remove_entry` (`session/mod.rs:758` precedes `:775`), so
  at cap a stale same-key local entry could never be replaced (and a local
  hit shadows the shared scope, blocking materialization too —
  `shared_ops.rs:528`); the new path replaces it without growing the table.
  Pinned by new test 4b (at-cap replace, `len()` stays at cap).
- **AGY r2 verification adopted:** `should_keep_synced_hit_transient` can
  NEVER apply to local-tunnel entries — it requires
  `is_translated_forward_session_key`, and local-tunnel decisions carry
  `NatDecision::default()` (no rewrites; `tunnel.rs:176`,
  `promote.rs:32-59`). The §2.3 exception caveat is deleted as impossible
  for this traffic class. AGY r2 also independently confirmed
  SyncImport/SharedMaterialize residency equivalence across promotion,
  demote/refresh, export, GC, and BPF-map deletion (matches SMR r2 C1).

v2 folded round-1 convergence (Claude SMR PLAN-NEEDS-CHANGES, Codex
PLAN-NEEDS-CHANGES, AGY PLAN-READY-with-findings):
- **SMR F1 = Codex 1 = AGY 1 (all three independently):** the v1 §2.3 "HA
  bulk-export gap" claim was FALSE — `export_forward_sessions_for_owner_rgs`
  skips `is_peer_synced()` origins (`session_glue/mod.rs:439-441`), so
  local-tunnel `SyncImport` entries are never bulk-exported at any occupancy.
  HA-implications leg deleted; §2.3 rewritten.
- **SMR F2 (AGY E.2 concurs):** "unbounded divergence window" was
  overstated — `materialize_shared_session_hit` (`session_glue/mod.rs:949` →
  `:850-876`) already installs shared-scope hits into the worker table via
  the UNCAPPED upsert on the first traversing packet, so the at-cap drop
  self-heals per flow per worker almost immediately. Severity reframed to
  Low-Medium; the fix is now argued as coherence + counter hygiene.
- **Codex 2 (Medium, accepted):** `session_create_drops` descriptor text
  (`pkg/api/metrics_descriptors.go:553-560`) and the session README
  (`session/README.md:88-99`) explicitly name "UpsertLocal replicas" — Path A
  requires Go-side help-text + README updates; v1's "no Go-side" claim
  corrected (§6/§8). No wire change.
- **Codex 3 (Medium, accepted):** add an explicit pin that
  `UpsertLocal(SyncImport)` entries are NOT bulk-exported (permanent
  by-origin design, not a cap artifact) so the expected behavior is decided
  and guarded (§5 test 5).
- **Codex 4 (Low, accepted):** add a two-worker fan-out pin (one table at
  cap, one below) pinning the per-worker divergence class end-to-end through
  `apply_worker_commands` (§5 test 2).
- **AGY 2 (Low, accepted):** tests assert install outcomes with `assert!`
  (release-profile-effective per the #1855 contract); production keeps
  `debug_assert!` (§5).
- **SMR F4:** Q2 resolved — `allow_replace_local=true` is correct; producer
  cannot run unless the tunnel resolution is `ForwardCandidate`
  (`tunnel.rs:171-175`), so the data is authoritative-local (§4). Codex
  Checks concur ("correct for preserving current replacement semantics").
- **SMR F6:** pins assert hot-path reachability + origin, not just `len()`.
- **SMR F7:** Q4 resolved — all `max_sessions` consumers are telemetry-only
  (AGY C concurs, including the Go side); no `len() <= max_sessions`
  invariant consumer exists.

**Date:** 2026-06-11
**Branch:** `research/1870-local-tunnel-pair` (off origin/master `9a536f810`)
**Issue:** #1870 (I13 exclusion follow-up from the #1861 converged plan, Codex
r1 C3 disposition; filed before #1861 /engineer per the §10 scope commitment)
**Mode:** /research — PLAN-READY or PLAN-KILL only.

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
not installed in an at-cap worker's table while the shared maps already hold
both entries.

**Severity (verified, rounds 1-3): Low-Medium.** The reverse entry re-enters
the worker table on the first reply packet through the **uncapped** reactive
materialization path; the forward entry — which has no worker-RX consumer for
normal local-origin traffic — stays absent until the next successful
re-enqueue after capacity frees (§2.3). The drop is already counted via
#1871's `create_drops` export (§2.4). What remains is an incoherence — the proactive
prewarm is capped while the reactive install of identical state is not — plus
a polluted counter signal and a transient partial-pair window. The fix is
~12 lines and provably behavior-identical below cap.

#1871 (merged 2026-06-11, `6a11c52f5`) shipped the install-transaction
machinery for the packet hot path — `can_admit` pair preflight,
drop-on-refusal, the `create_drops`/`admission_refused`/`install_partial`
counter trio exported end-to-end — but **left the `UpsertLocal` arm
untouched** (verified on current master).

## 2. Verified current behavior (origin/master `9a536f810`)

### 2.1 The producer (coordinator-side TUN reader thread)

`run_local_tunnel_endpoint`'s read loop (`tunnel.rs:73-95`) builds a
`LocalTunnelTxPlan` per local-origin packet
(`build_local_origin_tunnel_tx_request`, `tunnel.rs:146`), and errors out
unless the tunnel resolution disposition is `ForwardCandidate`
(`tunnel.rs:171-175`) — so the producer only runs where the tunnel's RG
resolution permits local forwarding (modulo the deliberate
`allow_unseeded_tunnel_local` prewarm window, `shared_ops.rs:693-708`). Both
pair entries carry `origin: SessionOrigin::SyncImport` — the forward entry at
`tunnel.rs:202`, the synthesized reverse at `shared_ops.rs:668`. Per-key
re-enqueue is gated at ≥5 s (TCP) / ≥1 s (other) by the `local_sessions`
last-seen map (`tunnel.rs:294-305`).

### 2.2 The exact at-cap interleaving

With a worker table at `max_sessions` (`len() == max_sessions`):

1. `local_sessions.insert(key, now_ns)` — re-enqueue suppressed for 1 s/5 s
   (`tunnel.rs:305`).
2. `publish_shared_session(forward)` + `publish_shared_session(reverse)` —
   shared maps + owner-RG indexes now hold **both** entries
   (`tunnel.rs:306-321`).
3. `UpsertLocal(forward)`, `UpsertLocal(reverse)` pushed to all N worker
   queues (`tunnel.rs:327-333`).
4. Each worker's `apply_worker_commands` consumes both commands;
   `install_with_protocol_with_origin` hits `len() >= max_sessions` at
   `session/mod.rs:758-761`, bumps `create_drops` (exported since #1871),
   returns `false`; the arm discards it (`session_glue/mod.rs:560`).
5. `wait_for_local_tunnel_session_install` (`tunnel.rs:335,353`) returns as
   soon as the queues drain — drain ≠ install success, so the 1 ms wait
   provides no protection (and does not hang either).

**Partial variant:** with exactly one free slot (`len() == max_sessions - 1`)
the forward install succeeds and the reverse fails. The pair has no preflight
(`can_admit(2)` is never consulted on this path).

**Per-worker variant:** worker tables are independent; below-cap workers
admit the pair while at-cap workers drop it.

### 2.3 What actually diverges, and for how long (corrected in v2)

- **Worker fast path, reverse half:** inbound tunnel replies are decapped
  and traverse `resolve_flow_session_decision`
  (`poll_descriptor/mod.rs:121,257`); the first reply at an at-cap worker
  hits the shared scope (`lookup_session_across_scopes`) and is installed
  into the worker table by `materialize_shared_session_hit`
  (`session_glue/mod.rs:949` → `:850-876`) via the **uncapped**
  `upsert_synced_with_origin(…, false)`, origin relabeled
  `SharedMaterialize`. The `should_keep_synced_hit_transient` arm
  (`session_glue/mod.rs:932-945`) can never block this for local-tunnel
  entries: it requires `is_translated_forward_session_key`, and local-tunnel
  decisions carry `NatDecision::default()` — no rewrites (`tunnel.rs:176`,
  `promote.rs:32-59`; verified AGY r2). So the reverse-half divergence
  window is ~one reply packet per worker per flow.
- **Worker fast path, forward half:** local-origin packets ride
  TUN → coordinator → TX (`tunnel.rs:72-101`) and never traverse worker RX
  resolution, so the forward entry is NOT reactively materialized — it stays
  absent until a successful re-enqueue after capacity frees (≥1 s/5 s
  windows). Worker RX would consult it only through the generic exact-key
  local lookup (`lookup_session_across_scopes` checks the local table before
  the shared scope, `shared_ops.rs:528`, called with `flow.forward_key` at
  `session_glue/mod.rs:911`) — i.e. only if the inner forward 5-tuple
  arrived unencapsulated at a worker, which normal local-origin tunnel
  traffic never does; and there is no forward-wire alias to match, because
  NAT is default so `wire_key == key` and the forward-wire index only
  inserts when they differ (`session/mod.rs:1478`, `shared_ops.rs:827`).
  The absence is functionally inert for normal traffic; the prewarm simply
  fails its purpose (Codex r2-1, precision per Codex r3-2).
- **HA:** none. Incremental deltas are suppressed for `SyncImport` origin
  (`session/mod.rs:797`), and bulk export skips all peer-synced origins
  permanently (`export_forward_sessions_for_owner_rgs`,
  `session_glue/mod.rs:439-441`) — local-tunnel sessions are never
  bulk-exported at any occupancy, by origin design, cap-independent. (v1
  claimed an at-cap bulk-export gap here; refuted independently by all three
  round-1 reviewers.)
- **Counter signal:** each at-cap prewarm attempt bumps `create_drops` twice
  (once per pair entry) — the reverse half self-reverses on the next reply
  packet and the forward half is functionally inert (no normal local-origin
  worker-RX path reaches it, §2.3),
  yet at cap with active local-tunnel traffic this steadily inflates a
  counter whose other contributors are genuine losses.

### 2.4 Honest residue vs #1871

#1871 closed the **silence** half of the original filing: the at-cap
`UpsertLocal` drop increments `create_drops` (`session/mod.rs:758-761`),
exported per-worker as `session_create_drops` → `ProcessStatus` → Prometheus
(verified end-to-end by Codex and AGY round 1: `worker/loop_body/mod.rs:198`,
`server/helpers.rs:148`). The issue's "minimum first step: count the dropped
`UpsertLocal` installs" is **already shipped**, modulo attribution.

The behavioral residue this plan targets: the capped/uncapped incoherence
between the proactive prewarm and the reactive materialization of the same
entries (§2.3), the partial forward-only interleaving at cap-1, and the
misleading `create_drops` contributions.

## 3. Why the #1871 pattern does not transplant directly

The #1871 fix is a **preflight before side effects** on the packet hot path:
`can_admit(needed)` runs on the thread that owns the `&mut SessionTable`,
before any shared/NAT/flow-cache mutation, so refusal drops the packet with
zero published state. The local-tunnel path inverts the topology: the
producer (TUN reader thread) performs the side effects but cannot see any
worker's occupancy; the N consumers see occupancy but run after the publish
and admit/refuse independently. A coordinator-side preflight needs new
cross-thread occupancy plumbing and is racy anyway; a consumer-side refusal
cannot unwind a publish another worker may have admitted. The design space is
the arbitration the issue names: align `UpsertLocal` with the capped family
(keep the incoherence) or the uncapped sync family (eliminate it).

## 4. Design paths

### Path A (recommended): move `UpsertLocal` into the uncapped sync-family install

Replace the arm's capped install with the sync-family entry point:

```rust
WorkerCommand::UpsertLocal(entry) => {
    // #1870: local-tunnel pair entries are coordinator-authoritative
    // replicas of state ALREADY published to the shared maps. Routing
    // them through the capped install let max_sessions refuse the
    // worker-table copy while the reactive shared-hit materialization
    // (materialize_shared_session_hit) reinstalls the reverse entry
    // uncapped on the next reply packet — a futile cap that only
    // polluted create_drops and delayed/voided the prewarm.
    // allow_replace_local=true preserves the pre-#1870 replace
    // semantics (the capped install clobbers any same-key entry below
    // cap); the data is locally generated — the producer only runs
    // when the tunnel resolution is ForwardCandidate (tunnel.rs:171),
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

**Equivalence proof below cap** (`install_with_protocol_with_origin`,
`session/mod.rs:748` vs `upsert_synced_with_origin(…, true)`,
`session/mod.rs:834`, for `SyncImport`-origin entries) — independently
re-verified by all three round-1 reviewers, no divergence found:

| Step | capped install | uncapped upsert |
|---|---|---|
| cap check + `create_drops` | yes (`:758-761`) | none |
| local-clobber guard | none | bypassed by `allow_replace_local=true` (`:855-860`) |
| `remove_entry(&key)` | yes | yes |
| epoch, record fields (`closing`, timeouts, `wheel_tick`) | identical | identical |
| slab insert + `key_to_handle` + `index_forward_nat_key` + `push_to_wheel` | identical | identical |
| `push_delta` | suppressed: `SyncImport.is_peer_synced()` (`:797`) | never pushes |
| return | `true` below cap | `true` always (only `false` exit is the bypassed guard) |

**Why uncapping is sound here:**

1. The entries are already in the **uncapped** shared maps; worker-table
   refusal does not bound memory, it only creates disagreement.
2. The reactive materialization of the reverse entry is already uncapped
   (`materialize_shared_session_hit`, §2.3) — at cap the reverse entry lands
   in the same table either way; Path A makes it arrive proactively, under
   the intended origin label (`SyncImport` instead of `SharedMaterialize` —
   residency-equivalent across promotion, demote/refresh, export, GC, and
   BPF-map deletion; verified independently by SMR r2 and AGY r2). The
   forward entry has no reactive path and no normal local-origin worker-RX
   consumer (§2.3); Path A simply makes the prewarm do what it was written
   to do.
3. The `UpsertSynced` replica fan-out (`replicate_session_upsert`,
   `session_glue/mod.rs:596`) already installs every locally-created session
   into every other worker uncapped (#1861 row I11); local-tunnel pairs are
   a strict subset of an existing, much larger uncapped surface, rate-limited
   per key (≥1 s/5 s) and expired by the timer wheel like any session.
4. **It does not preempt the I11 arbitration — it centralizes it.** Whatever
   the eventual sync-family cap decision is, it will then cover `UpsertLocal`
   automatically instead of leaving a second, differently-divergent path.

**Counter + docs ride-along (Codex 2):** after Path A, `UpsertLocal` stops
contributing to `session_create_drops` — truthful, since the event is no
longer a drop. Two existing doc surfaces explicitly name "UpsertLocal
replicas" as a covered site and must be updated in the same PR:
`pkg/api/metrics_descriptors.go:553-560` (help text only — **no wire or
series change**) and `userspace-dp/src/session/README.md:88-99`.

### Path B: keep the cap, add attribution

Keep the capped install; bump a dedicated counter on `false`. Rejected: the
observability is already ~shipped (§2.4), the incoherence and partial-pair
window remain, and it spends a wire field attributing an event Path A removes.

### Path C: rollback the shared publish on refusal

Workers admit/refuse independently; the shared entry must stay if any worker
admitted; requires N-way ack aggregation for two map entries. Killed.

### Path D: coordinator-side preflight

Needs cross-thread occupancy mirrors and is racy against packet-path installs
between check and apply. Killed.

### Path E: close-as-fixed (#1871 counted it; materialization heals it)

Seriously weighed in round 1; rejected by all three reviewers. Do-nothing
leaves (a) `create_drops` polluted at cap by non-loss events inside the trio
#1871 just shipped, (b) the capped/uncapped incoherence between the
proactive prewarm and the reactive reinstall of the same reverse state, (c)
the partial forward-only interleaving. Path A is ~12 lines and provably equivalent below
cap; the consistency fix is worth that much churn (AGY: "Path A is the only
logically coherent architecture"; Codex: "#1871 fixed visibility, not the
shared-map/worker-table disagreement").

## 5. Test plan (deterministic pins, debug AND release — #1855 contract)

Tests use `assert!` on outcomes (release-effective; AGY 2); production code
keeps `debug_assert!`. New tests in `userspace-dp/src/afxdp/tests.rs` (or
`session_glue/tests.rs` where the fixtures live — reuse the #1871 at-cap
harness style: `set_max_sessions_for_test`, direct `apply_worker_commands`
with a rigged queue):

1. `upsert_local_pair_installs_at_cap` — fill table to cap; apply the
   `UpsertLocal` forward+reverse pair (SyncImport origin, reverse via the
   `synthesized_synced_reverse_entry` shape); assert both keys resolve via
   exact forward-key lookup (`entry_with_origin` / `lookup_with_origin`)
   with `SyncImport` origin, `len() == cap + 2`, and `create_drops()` /
   `admission_refused()` / `install_partial()` all unchanged. Pins the §2.2
   interleaving through the fixed code. Do NOT assert via
   `find_forward_wire_match`: with default NAT, `wire_key == key` and the
   forward-wire index never holds these entries (`session/mod.rs:1478`;
   Codex r3-2).
2. `upsert_local_fanout_diverged_workers_converge` (Codex 4) — two worker
   queues + two tables, one at cap and one below; fan the pair out to both
   (as `tunnel.rs:327-333` does); apply on both; assert both tables hold
   both entries. Pins the per-worker divergence class end-to-end.
3. `upsert_local_pair_no_partial_at_cap_minus_one` — one free slot; apply the
   pair; assert both installed (pre-fix: forward-only partial; documented in
   a comment).
4. `upsert_local_below_cap_replaces_existing_local_entry` — pre-install a
   `ForwardFlow`-origin same-key session below cap; apply; assert replaced
   with `SyncImport` origin and `create_drops()` still 0 (pins
   `allow_replace_local=true` = status-quo replace semantics, and guards
   against a future revert to the capped install).
   4b. `upsert_local_at_cap_replaces_existing_local_entry_without_growth`
   (Codex r2-2 / AGY r2-1) — table AT cap including a same-key
   `ForwardFlow`-origin entry; apply `UpsertLocal`; assert the entry is
   replaced (`SyncImport` origin) and `len()` stays exactly at cap. This is
   a deliberate at-cap semantic change vs the old capped install, which
   refused before reaching `remove_entry` (`session/mod.rs:758` precedes
   `:775`) and so could never replace at cap — leaving a stale local entry
   that also shadowed the shared scope (`shared_ops.rs:528`), blocking
   reactive materialization until expiry. The new behavior is strictly
   better (replacement does not grow the table) and is pinned explicitly.
5. `upsert_local_entries_stay_out_of_owner_rg_bulk_export` (Codex 3) —
   install the pair via the new arm, run
   `export_forward_sessions_for_owner_rgs` for the owning RG, assert no
   delta is emitted for either entry. Decides and pins the expected behavior:
   exclusion is permanent by-origin design (`session_glue/mod.rs:439-441`),
   not a cap artifact.
6. Session-level `upsert_synced_with_origin_allow_replace_is_infallible_at_cap`
   in `userspace-dp/src/session/tests.rs` (verified round 1: no existing pin).

Gates: full `cargo test --release` + debug `cargo test session::` + the new
tests in both profiles; `go test ./...` (descriptor text change touches
`pkg/api`). No live-cluster dependency for the pins. Parent smokes
post-merge; failover smoke recommended since a session-install path changes,
even though the verified HA delta/export surfaces are untouched.

## 6. Observability

No new wire fields, no protocol bump, no metric series change. Semantic doc
updates only: `session_create_drops` help text in
`pkg/api/metrics_descriptors.go:553-560` drops the "UpsertLocal replicas"
clause (Codex 2); the #1861 trio descriptors otherwise stay accurate.

## 7. Documentation

- `userspace-dp/src/session/README.md` (#1861 section, `:88-99`) —
  `UpsertLocal` moves to the uncapped sync-family with the §4 rationale;
  `create_drops` no longer includes it.
- `session_glue/mod.rs` arm comment (per the §4 snippet).
- `pkg/api/metrics_descriptors.go` help text (§6).
- `worker_queue.rs:1-21` poison-recovery comment — unaffected (commands
  remain individually self-contained); no edit.

## 8. Blast radius

One arm in `session_glue/mod.rs` (~15 lines), tests, README, one Go help-text
string. No protocol change, no producer change, no hot-path packet code.
Worker tables can exceed `max_sessions` by local-tunnel pair volume — bounded
by §4 arguments; identical in kind to the pre-existing I11 surface, and all
`max_sessions` consumers are telemetry-only (round-1 verified, both Rust and
Go sides; slab grows dynamically, no `len() <= max_sessions` invariant
consumer exists).

## 9. Failure modes considered

- **Same-key collision with a live local session:** preserved replace
  semantics (test 4). Refusal semantics would newly let a stale non-tunnel
  session block the tunnel steering decision after a route change; rejected.
- **Future producer enqueues `UpsertLocal` with a local origin:** the old
  path would have pushed an HA delta, the new one never does — caught by
  `debug_assert!(entry.origin.is_peer_synced())`.
- **Memory exhaustion via local-tunnel flow spray:** requires the local host
  stack to originate unbounded distinct flows into a TUN endpoint; those
  flows already grow the uncapped shared maps today, and the reactive
  materialization already installs them uncapped per worker. No new surface.

## 10. Non-goals / scope

- The global sync-family cap arbitration (#1861 row I11) stays open — this
  plan joins the existing family rather than deciding its future. A dedicated
  I11 issue gets filed at /engineer time if reviewers want it tracked.
- No change to bulk-export origin semantics (local-tunnel sessions remain
  excluded by design — now pinned by test 5, not silently assumed).
- No kernel/BPF `session_map_fd` publish from the `UpsertLocal` arm
  (pre-existing asymmetry vs `handle_upsert_synced`; out of scope).
- No change to the producer (publish ordering, 1 ms drain wait, refresh
  windows).

## 11. Open questions for adversarial review

1. **Close-as-fixed** — weighed as Path E, rejected 3-of-3 in round 1.
2. **`allow_replace_local=true` vs HA-computed** — resolved round 1 (SMR F4,
   Codex Checks, AGY B): the producer only runs under `ForwardCandidate`
   resolution; the data is authoritative-local; the guard only protects
   non-peer-synced entries anyway, so the flag choice only governs the
   local-collision case where replace is the status quo.
3. **Is `SyncImport` the right origin for local-tunnel entries?**
   Pre-existing choice (delta suppression + bulk-export exclusion + replace
   semantics ride on it). Out of scope to change; test 5 pins its export
   consequence so the choice is at least explicit. A reviewer arguing for a
   dedicated origin variant should weigh it as a separate issue.
4. **`len() > max_sessions` consumers** — resolved round 1 (SMR F7, AGY C):
   telemetry-only on both sides; no invariant consumer.
