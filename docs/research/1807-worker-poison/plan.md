# #1807 — Worker-side command-queue poison recovery (permanent deafness + silent producer drops)

Status: DRAFT v2 — round-1 findings folded (Codex + AGY both PLAN-NEEDS-MAJOR: audit was incomplete), pending round-2 confirm

## Issue framing

U9/#1790 (PR #1806) made the COORDINATOR side recover poisoned
worker-command mutexes via `poisoned.into_inner()`. The WORKER side still
treats poison as absence-of-work, permanently:

1. `worker/loop_body/mod.rs:597` —
   `commands.try_lock().map(|q| !q.is_empty()).unwrap_or(false)`:
   poisoned ⇒ `has_commands == false` forever; the worker never enters
   command processing again.
2. `session_glue/mod.rs:472` (`apply_worker_commands`) — `try_lock()` match
   Err arm returns empty results; same deafness (this is the arm actually
   consuming the queue when called).

Additionally — full production audit (round-1: BOTH reviewers found the
v1 "4 sites" scope false; complete inventory):

3. `session_glue/mod.rs:598` (`replicate_session_upsert`) — `if let Ok`
   silently DROPS the UpsertSynced replica for a poisoned worker.
4. `session_glue/mod.rs:609` (`replicate_session_delete`) — same, drops
   DeleteSynced.
5. `shared_ops.rs:180` and `shared_ops.rs:216` — drop activation prewarm
   `UpsertSynced` on poison.
6. `tunnel.rs:322` — drops `UpsertLocal`; `tunnel.rs:354` treats poison
   as "not drained" until timeout.
7. `cos/cross_binding.rs:136` — treats poison as enqueue failure
   (cross-worker shaped-TX request lost).
8. `tx/drain/mod.rs:519` — same, and the comment at :523 calls a
   poisoned mutex "unrecoverable" — that comment directly contradicts
   the recovery invariant and must be removed/rewritten.
9. Coordinator retrofit: the five #1790 ha.rs sites (:58, :129, :203,
   :358, :420) recover WITHOUT clear_poison — retrofit them to the
   shared helper for one consistent policy.

Combined effect after one worker panic mid-push: coordinator pushes
accumulate unboundedly in a queue the worker never drains (the #835
unbounded-growth concern), HA commands (DemoteOwnerRGs, UpsertSynced,
ExportOwnerRGSessions) are lost on that worker, and session replication to
it silently stops.

## Honest scope/value framing

Small, surgical: 4 sites, one policy ("poison = recover via into_inner,
consistent with #1790's coordinator policy"). The queue data is plain
`VecDeque<WorkerCommand>` — a panic mid-`push_back` can at worst leave a
fully-pushed or not-pushed element (VecDeque push_back has no
partially-visible state observable after into_inner; the deque may have
been mid-grow, but Rust's UnwindSafe story here is the same one #1790
already accepted coordinator-side). If reviewers think worker-side recovery
needs a different policy than coordinator-side (e.g. drain-and-clear
instead of process-as-is), that's a design finding to fold. PLAN-KILL
acceptable if they show recovery is unsound for this data structure.

## What's already shipped / composes with

- #1790 coordinator policy + `ha_tests.rs` 3-worker poison-1 regression
  (PR #1806): `match lock() { Ok(g) => g, Err(p) => p.into_inner() }`.
- #925 worker supervisor (panic containment) — the poison producer.
- #835 plan-kill record: queues are unbounded by design; detection-only.

## Concrete design

**One shared helper pair (round-1 Codex requirement), e.g. in a small
`worker_queue.rs` module (or alongside the WorkerCommand type):**

```rust
/// Lock a worker-command queue, recovering and CLEARING poison.
/// Policy (#1807, extends #1790): a panic that poisoned the queue
/// already happened and was contained ([#925] supervisor); the deque
/// holds the committed prefix of every completed push — discarding it
/// would lose acknowledged HA/session commands. clear_poison restores
/// the fast unpoisoned path for subsequent accesses.
fn lock_recover<'m>(m: &'m Mutex<VecDeque<WorkerCommand>>) -> MutexGuard<'m, VecDeque<WorkerCommand>> {
    match m.lock() {
        Ok(g) => g,
        Err(p) => { m.clear_poison(); POISON_RECOVERIES.fetch_add(1, Relaxed); p.into_inner() }
    }
}
/// try_lock variant: WouldBlock → None (unchanged skip semantics);
/// Poisoned → recover + clear + Some(guard).
fn try_lock_recover<'m>(...) -> Option<MutexGuard<'m, ...>> { ... }
```

DECIDED (round-1, both reviewers): **clear-after-recovery**, applied
uniformly — without it the hot-loop "Poisoned arm is cold" claim is false
forever after the first poison. The coordinator ha.rs sites are
retrofitted to the same helper in this PR.

Application: site 1 (loop_body:597) uses try_lock_recover for the
has-commands peek; site 2 (session_glue:472) uses try_lock_recover and
processes the recovered deque; producer sites (session_glue:598/:609,
shared_ops:180/:216, tunnel:322, cos/cross_binding:136, tx/drain:519)
use lock_recover (or try_lock_recover preserving each site's current
WouldBlock disposition — audit each); tunnel.rs:354 drain-wait treats a
recovered guard as a normal read. Any production access intentionally
left unconverted must be explicitly justified in the PR body.

Data-integrity wording (round-1 Codex): the recovered deque holds the
**committed prefix** of any multi-push section that panicked between
pushes (e.g. ha.rs:61+:68, tunnel.rs:323+:325) — not just "fully pushed
or not pushed". Consumers already tolerate partial command batches
(commands are individually self-contained); document this at the helper.

Counter (round-1 Codex): a hidden static is NOT an operator surface.
Wire `worker_command_queue_poison_recoveries_total` deliberately through
the existing status path — the U4 SESSION_PUBLISH_ERRORS_SHARED pattern:
static in the helper module → coordinator/status.rs accessor →
server/helpers.rs → protocol.go → pkg/api/metrics_userspace.go (both-
sides grep rule applies).

## Public API preservation

No signature changes (internal match arms only). Counter addition follows
the existing status/protocol pattern ONLY if exposed; default: log-only
eprintln + static counter readable via existing debug surface — decide
with reviewers (wire-protocol changes need both-sides grep per memory).

## Hidden invariants

- Hot loop: site 1 runs every poll tick. The new match compiles to the
  same fast path for Ok; Poisoned arm is cold. No allocs added.
- UnwindSafe/data-integrity: consuming a deque that a panicking thread was
  mutating — same acceptance as #1790; document at the site.
- Lock-ordering unchanged (single mutex, no nesting).

## Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | poison path only; today's behavior is the bug |
| Lifetime/borrow | LOW | guard from into_inner has same scope |
| Performance | LOW | hot-loop match shape — verify no codegen regression (objdump spot-check optional) |
| Architectural mismatch | LOW | extends the accepted #1790 policy |

## Test plan

- Unit (session_glue tests module): poison a queue (spawn thread that
  panics while holding the lock), then (a) apply_worker_commands processes
  queued commands, (b) replicate_session_upsert/delete still deliver,
  (c) loop_body has_commands path — exercised indirectly via (a) or via a
  small extracted helper if testable.
- Mirror of U9's ha_tests 3-worker poison-1: end-to-end worker-side variant
  if the harness supports it.
- cargo test --release full; 5x flake on new tests.
- Smoke: Pass A + **failover gate mandatory** (`make test-failover`) —
  session-sync/HA-adjacent hot-loop change.

## Out of scope

- Bounding the queues (#835 plan-kill stands).
- Supervisor/restart policy changes (#925).
- New wire-protocol status fields (unless reviewers demand observability
  beyond a counter/log).

## Open questions for adversarial review

1. RESOLVED round 1: clear-after-recovery, uniformly, coordinator
   retrofitted in this PR.
2. RESOLVED round 1 (Codex): process recovered queues — WorkerCommand is
   an owned enum (types/runtime.rs:215); #1790 tests already assert
   recovery preserves commands (ha_tests.rs:414); drain-discard would
   lose committed HA commands. Wording: committed prefix.
3. RESOLVED round 1: full status/protocol plumbing per the U4 pattern.
4. RESOLVED round 1: complete inventory above (sites 1-9); round-2
   reviewers verify NO production access remains unconverted/unjustified.
5. Open: hot-loop codegen — confirm the helper keeps the empty-queue
   fast path tight (helper #[inline]; Poisoned arm cold).
6. Open (new): is clear_poison correct when MULTIPLE threads race the
   recovery (clear_poison is idempotent; two recoverers both take
   committed state — confirm no double-processing hazard given guards
   serialize)?
