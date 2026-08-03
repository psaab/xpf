# Reviewer ID ledger — #6749 armed-state research

## Round 1 (plan v1 @ 8c76670d6)

- **Codex** — background bash task `bpeskwtds` (codex-companion `task`,
  fresh thread; resume-candidate check returned a stale cross-issue
  thread, correctly NOT resumed). Output: `/tmp/codex-6749-r1.out`;
  verdict doc: `codex-plan-r1.md`. Verdict: DEMAND-REVISION (2 BLOCKER
  — deferred-activation armed-from-global hazard + identity-not-physical;
  5 MAJOR — E2 concurrence, volatile-vs-control carry, queue-override
  lifetime, B-rejection overstated, unsafe-green test; 1 MINOR —
  trigger/outage overstatement + helper-restart release note).
- **AGY** — five documented attempts; infra-limited for the first four:
  1. `bdococru5` / agy job `rescue-msd58qxp-8wtalr` — DENIED: jetski
     headless auto-denied the `command` tool permission; no output.
  2. `bchno4y52` / agy job `rescue-msd5faa6-0a2mlw` — retry with explicit
     no-shell steering — DENIED identically.
  3. `bnzrb1qet` / agy job `rescue-msd5gvjg-fcse4z` — inline-evidence
     prompt via companion argv — garbage/unrelated response
     (`--print-timeout` hallucination; argv-mangling suspected).
  4. `b34jcg019` — direct `agy --print` with stdin pipe — transport
     error (`flag needs an argument: -print`; agy takes the prompt as a
     flag argument, not stdin).
  5. `bqnwvd6rc` — direct `agy --print-timeout 9m --print "$(cat
     /tmp/agy-6749-r1c-prompt.txt)"` with the inline-evidence prompt —
     SUCCESS. Verdict doc: `agy-plan-r1.md`. Verdict: DEMAND-REVISION
     (1 MAJOR — E2 invalid→valid stranding; 1 MINOR — zero volatile on
     carry [v3 ADOPTS it via R3, superseding v2's rejection]; 1 NIT —
     Go gate test).
- **Claude SMR** — `claude-smr-plan-r1.md`. Verdict: DEMAND-REVISION
  (SMR-1 B-rejection honesty, SMR-2 observability-only Go leg [option
  D], SMR-3 close Q2/Q5 from source, SMR-4 identity semantics
  documentation).

## Round 2 (plan v3 @ bce10126c)

- **Codex** — background bash task `bd01h9f99`; prompt
  `/tmp/codex-6749-r2-prompt.txt`; output `/tmp/codex-6749-r2.out`;
  verdict doc `codex-plan-r2.md`. Verdict: DEMAND-REVISION (6 BLOCKER
  — fold claims partly false; R1 arm-before-reconcile →
  armed-but-unbound/partial forwarding on failed bring-up; **R2 misses
  the rebind completion path** (process_linkcycle.go:219);
  defer-completion via full-apply leg + #5134 debt discard; deferred
  CONTRACTION leaves everything armed (no new identity); full fan-out
  reverses operator maintenance disarms — scoped provenance REQUIRED;
  E2/operator-unregister flap; tests green unsafe impls; + 2 MAJOR).
- **AGY** — background bash task `b7b4f8pf7` (direct `agy
  --print-timeout 9m --print`, inline-evidence prompt
  `/tmp/agy-6749-r2-prompt.txt`); output `/tmp/agy-6749-r2.out`;
  verdict doc `agy-plan-r2.md`. Verdict: DEMAND-REVISION (1 BLOCKER —
  full-leg defer-completion stranding; 2 MAJOR — R1 pre-arm on failed
  reconcile, E2/operator-unregister flap; 1 MINOR — test gaps; 1 NIT —
  fan-out override loss).
- **Claude SMR** — `claude-smr-plan-r2.md`. Verdict: DEMAND-REVISION
  (SMR2-1: R2 same-plan-only placement misses full-leg completions —
  independently confirmed by AGY r2 f1 + generalized by Codex r2
  BLOCKER 4; SMR2-2: commitment cleanups).

## Round 3 (plan v4 @ f679a791a)

- **Codex** — background bash task `b3nxp5nhd`; prompt
  `/tmp/codex-6749-r3-prompt.txt`; output `/tmp/codex-6749-r3.out`;
  verdict doc `codex-plan-r3.md`. Verdict: DEMAND-REVISION (6 BLOCKER
  — hybrid-plan activation via unversioned marker + auto-rebind; S3
  marks operator-disarmed slots; one-bool conflates registration and
  activation provenance (C3 must scope to registered; S2 was-armed
  gate); S4's identity scope never guaranteed enabled=false (contraction
  shape); registration-toggle reconcile converges mid-defer-window
  (defer gate, rebind-authorized); C3 clears marks before the fallible
  arm reconcile; tests green unsafe impls; + 2 MAJOR + 2 MINOR).
- **AGY** — background bash task `bvv1uiufg` (direct `agy --print`,
  inline-evidence prompt `/tmp/agy-6749-r3-prompt.txt`); output
  `/tmp/agy-6749-r3.out`; verdict doc `agy-plan-r3.md`. Verdict:
  DEMAND-REVISION (2 MAJOR — S5 must never arm at replan
  [convergence-only arming deletes S4]; S2 marks operator-disarmed
  slots on flap; 1 MINOR — test 7(c) split; 1 NIT — S3 release note).
- **Claude SMR** — `claude-smr-plan-r3.md`. Verdict: DEMAND-REVISION
  (SMR3-1 S4-E2 side door [subsumed by AGY f1 + S4']; SMR3-2/3/4
  commitments on Q3/Q5/Q7).

## Round 4 (plan v5 @ 0c0b9b677)

- **Codex** — background bash task `b6kq41wsw`; prompt
  `/tmp/codex-6749-r4-prompt.txt`; output `/tmp/codex-6749-r4.out`;
  verdict doc `codex-plan-r4.md`. Verdict: DEMAND-REVISION (6 BLOCKER
  — name-only plan gate authorizes wrong-physical and incomplete
  retained plans; bool conflates global-disarm with operator
  ownership; S4' full-apply-only + retained-records retry deficit;
  arm-then-fail strands with no production retry; compile-time
  arm-sync bypasses the defer gate (verified manager_ha.go:601-607);
  rebind verb-identity is not completion provenance; + 3 MAJOR —
  sysfs-race authorization, more test holes).
- **AGY** — background bash task `b30wsddwd` (direct `agy --print`,
  inline-evidence prompt `/tmp/agy-6749-r4-prompt.txt`); output
  `/tmp/agy-6749-r4.out`; verdict doc `agy-plan-r4.md`. Verdict:
  PLAN-READY-WITH-NITS (all r3 dispositions confirmed; nits: arm-verb
  global-bit rollback on reconcile Err; rebind log pending count).
- **Claude SMR** — `claude-smr-plan-r4.md`. Verdict:
  PLAN-READY-WITH-NITS (N1 plan-gate drift semantics; N2 C2
  claim-before-reconcile code order; N3 cosmetic).

## Round 5 (plan v6 @ 6969b6167)

- **Codex** — background bash task `btb0wkhig`; prompt
  `/tmp/codex-6749-r5-prompt.txt`; output `/tmp/codex-6749-r5.out`;
  verdict doc `codex-plan-r5.md`. Verdict: DEMAND-REVISION (8 BLOCKER
  — tri-state cannot distinguish disarmed-then-force-cleared from
  unregistered; failure-path replan destroys accepted-A operator
  claims AND reintroduces the live-sysfs race (permanent empty
  vector); update_fabrics falsifies the coherent-vector invariant;
  daemon clears m.deferWorkers before MAC programming (pre-MAC arm
  race moved, not closed); S4' creates unscheduled pending sinks
  (first-Compile loop ordering, rollback-to-true no-op, failed tagged
  rebind warns-only, watchdog suppressed); completion + #5134
  provenance neither durable nor generation-safe, and live-change
  completion fires on FAILED MAC programs; + 2 MAJOR — tests, #6165
  Warn flood).
- **AGY** — background bash task `bkrhr0gc1` (direct `agy --print`,
  inline-evidence prompt `/tmp/agy-6749-r5-prompt.txt`); output
  `/tmp/agy-6749-r5.out`; verdict doc `agy-plan-r5.md`. Verdict:
  PLAN-READY-WITH-NITS (1 MINOR — un-ratelimited Warn on #6165
  refusal [= SMR r5 N1 = Codex r5 M10]; 1 NIT — README must state
  defer-clearing alone does not activate).
- **Claude SMR** — `claude-smr-plan-r5.md`. Verdict:
  PLAN-READY-WITH-NITS (N1 Warn-rate edge-trigger [= same]; N2
  no-link-cycle completion corner doc; N3 idempotent re-arm test pin).

## Round 6 (plan v7 @ 3e388fde8; v7.1 @ d61e76ec3 folded AGY r6 + SMR r6 mid-round)

- **Codex** — background bash task `b8qo89ua3`; prompt
  `/tmp/codex-6749-r6-prompt.txt`; output `/tmp/codex-6749-r6.out`;
  IN FLIGHT at v7.1 fold time.
- **AGY** — background bash task `buksg7v0r` (direct `agy --print`,
  inline-evidence prompt `/tmp/agy-6749-r6-prompt.txt`); output
  `/tmp/agy-6749-r6.out`; verdict doc `agy-plan-r6.md`. Verdict:
  DEMAND-REVISION (1 BLOCKER — convergence signature/latch atomicity;
  2 MAJOR — transient-MAC stranding, fixed-5s retry thrash; 1 MINOR —
  clear-to-dispatch race).
- **Claude SMR** — `claude-smr-plan-r6.md`. Verdict:
  PLAN-READY-WITH-NITS (N1 retry backoff/cap/debt-suppression
  [= AGY f3/f4], N2 MAC-failure corner doc [= AGY f2], N3 latch write
  ordering [= AGY f1]).

## Round 7 (plan v8 @ pending)

- **Codex r6** — background bash task `b8qo89ua3`; output
  `/tmp/codex-6749-r6.out`; verdict doc `codex-plan-r6.md`. Verdict:
  DEMAND-REVISION (6 BLOCKER — C2 discriminator + candidate-deletion
  claim loss; partial-B/restored-A volatile alias; replan-only
  update_fabrics publishes wrong-physical with enabled=true;
  sysfs race relocated into update_fabrics + netlink-driven cadence;
  quiescence race from the v7.1 flag clear; pending-retry incomplete
  (untagged latch, unregistered pendings, desired-vs-actual, churn,
  first-Compile orphans); Go re-latches Rust via wholesale snapshot
  clones + wrong debt scope (FIB bumps) + MAC-set/link-up-failed
  phase loss; + 2 MAJOR tests + 1 NIT retry observability).
- Codex r7 — pending dispatch.
- AGY r7 — pending dispatch.
- Claude SMR r7 — pending.
