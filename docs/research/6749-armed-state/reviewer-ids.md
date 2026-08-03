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

## Round 3 (plan v4 @ commit pending)

- Codex — pending dispatch.
- AGY — pending dispatch (direct `agy --print` transport).
- Claude SMR — pending.
