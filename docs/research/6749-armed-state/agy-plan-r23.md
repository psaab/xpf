# AGY plan review — round 23 — #6749 armed-state plan v8.18 (0e4604ac4)

**Reviewer:** AGY (hostile, zero-tool-call inline-evidence
constraint). Prompt: `/tmp/agy-6749-r23-final.txt` (130,800 bytes —
the r23 assembly at 147,799 bytes exceeded the kernel's 128 KiB
MAX_ARG_STRLEN for a single argv string (first dispatch died with
`Argument list too long`, exit 126); transport-trimmed to the r22
size class by eliding the fold narrative + r22 convergence prose
(carried by the boilerplate deltas), the standing §6 wire items 1-9,
and three excerpt tails — all elision points marked inline; the r22
disposition table, all normative v8.18 text, §9, and the hazard
budget retained in full). Raw output: `/tmp/agy-6749-r23.out`.
Background bash `bt61rhgmk` (direct `agy --print-timeout 9m
--print`).

**Verdict: DEMAND-REVISION** (3 BLOCKER + 2 MAJOR + 1 MINOR).

---

1. **[BLOCKER] GO-LOCAL re-sync drain loops forever on peer-synced
   restart-only configs** (daemon_apply_commit.go:331-402; plan §5-C
   Deltas 1 & 5): SyncApply promotes a topology/identity-changing
   peer config (ActivePair().revision advances to R) but returns
   early before `applyConfigLocked` (:381-402), so
   `m.acceptedCommitRevision` never advances; the GO-LOCAL rule
   (`ActivePair().revision > m.acceptedCommitRevision` AND no live
   registration) fires on the next poll, the drain's revised
   `applyConfigLocked` hits the same guard and skips — the
   inequality stays true forever, an unbounded retry loop acquiring
   `applySem` and logging until the daemon restarts. (Resolution:
   the GO-LOCAL rule must evaluate restart-only-ness before firing,
   or the guard must record a restart-suppression marker for R.)
   SMR r23 SMR23-1 independently confirmed (cadence correction: the
   loop rides the debt's 60s backoff floor, not the 1s poll).
2. **[BLOCKER] Rollback executor registered before Phase-1 boot
   Load** (daemon_run.go:130; plan §1/§5-C/§9 (b)): the plan's edge
   ("timer armed only AFTER the boot apply") is contradicted by the
   registration point — `SetRollbackExecutor` runs before
   `loadAndBootstrapConfig`/`initManagers`/
   `setupDataplaneAndInitialConfig`; a persisted confirm window
   re-armed by Load can fire during boot with nil/partial managers
   (panic or out-of-order rollback). (Resolution: move the
   registration into Phase 4 after the boot apply, or gate
   `executeConfirmedRollback` on an atomic boot-complete flag.)
   SMR r23 SMR23-2 confirmed + enumerated the mechanism options and
   the expiry-during-boot semantics.
3. **[BLOCKER] `syncSnapshotLocked` status-loop catch-up lacks a
   daemon-level completion-tail trigger** (process_status.go:10-140;
   plan §5-C (ii), §6): the catch-up leg publishes asynchronously
   inside the manager's background status loop — no `ApplyConfig`
   frame, no `ApplyResult`, no daemon wrapper — so the Delta-3
   triple never transports and the completion tails (session
   invalidation, peer push, applied stamp) never run for that leg.
   (Resolution: a daemon-side completion listener / cursor drain
   must own those tails.) SMR r23 SMR23-3 confirmed.
4. **[MAJOR] `syncSnapshotLocked` publishes cancelled/OVERLAP
   snapshots — no token-liveness check** (process_status.go:10-140;
   plan Delta 4): the catch-up checks only
   `m.publishedSnapshot < m.lastSnapshot.Generation` and XSK
   liveness — never whether the registration was OVERLAP-cancelled;
   a superseded staged object still referenced by `m.lastSnapshot`
   publishes anyway. (Resolution: the publish path must verify
   `token.state != CANCELLED`.) SMR r23 SMR23-4 confirmed (raised
   to BLOCKER — the plan pins the check on the OnXSKBound leg while
   the actual publisher stays blind).
5. **[MAJOR] Unspecified package locus & closure wiring for the
   `QueueConfig` exposure check** (pkg/cluster
   sync_conn_config.go:230-243; daemon_ha_sync.go:474-497): the
   exposure check needs `DurableRevision()` (configstore), which
   `pkg/cluster` does not import; the plan does not specify the
   closure-injection pattern or the held-push re-wake owner.
   SMR r23 SMR23-7 confirmed (also the marker-claim ordering:
   today the daemon claims the marker BEFORE `QueueConfig`).
6. **[MINOR] §9 lacks coverage for the restart-only GO-LOCAL loop
   and the boot executor sequence** (plan §9 (a)-(j)): test (d)
   covers only standard exposable builds; test (a)/(b) do not pin
   the executor's arming sequence. Folds with SMR23-1/SMR23-2's
   test requirements.

Evidence wishes (informational): daemon_apply.go
(`applyConfigLocked` entry/guard evaluation), daemon_run_servers.go,
pkg/cluster sync_conn_config.go (`QueueConfig` internals) — the
first and third were partially covered by the inline excerpts.

DEMAND-REVISION
