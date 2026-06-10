# #1807 — Worker-side command-queue poison recovery (permanent deafness + silent producer drops)

Status: DRAFT v1 — pending adversarial plan review

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

Additionally (found during this research, same family, MISSED by U9 —
these are producer-side in session_glue, not ha.rs):

3. `session_glue/mod.rs:598` (`replicate_session_upsert`) —
   `if let Ok(mut pending) = commands.lock()` silently DROPS the
   UpsertSynced replica for a poisoned worker.
4. `session_glue/mod.rs:609` (`replicate_session_delete`) — same, drops
   DeleteSynced.

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

Site 1 (loop_body:597):
```rust
let has_commands = match commands.try_lock() {
    Ok(q) => !q.is_empty(),
    Err(std::sync::TryLockError::WouldBlock) => false, // unchanged: skip this tick
    Err(std::sync::TryLockError::Poisoned(p)) => !p.into_inner().is_empty(),
};
```
(into_inner on TryLockError::Poisoned yields the guard; q dropped
immediately — this also CLEARS the poison? No: into_inner does not clear
poison; `Mutex::clear_poison` exists since 1.77. Decision point: call
`commands.clear_poison()` after first recovery so subsequent ticks take the
fast Ok path, or recover on every access. RECOMMENDED: clear_poison once
recovered — matches intent, removes per-tick Err-path cost. Verify #1790
coordinator-side precedent: if coordinator did NOT clear, choose one policy
and apply to both sides in this PR for consistency, coordinator included
if trivial.)

Site 2 (session_glue:472): same match shape; Poisoned arm proceeds with
`p.into_inner()` exactly as the Ok arm (take the deque, process), then
clear_poison per the chosen policy. WouldBlock arm unchanged (empty
results).

Sites 3+4 (replicate_session_*): replace `if let Ok` with the #1790
match-recover pattern so replicas are pushed even to a poisoned queue.

Counters: add `worker_command_queue_poison_recoveries` (per-worker or
global static following U4's SESSION_PUBLISH_ERRORS_SHARED pattern) so
operators can see recovery happened. Optional but cheap; recommended since
poison indicates a prior panic worth alerting on.

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

1. clear_poison after recovery vs recover-every-access — and should the
   coordinator side (U9) adopt the same in this PR for consistency?
2. Is processing a deque recovered from a mid-push panic sound, or should
   the recovery policy be drain-discard + log (lose the queue once but
   restore liveness)? #1790 chose process-as-is coordinator-side — does the
   worker consume path raise new concerns (commands acted on vs just
   exported)?
3. Counter exposure: static + log only, or full status/protocol plumbing?
4. Are there MORE worker-side queue accesses this audit missed? Reviewers
   should grep `commands.lock\|commands.try_lock` across userspace-dp
   themselves.
5. Hot-loop codegen: does the 3-arm match keep the empty-queue fast path
   branch-predictable (it should — Poisoned is cold)?
