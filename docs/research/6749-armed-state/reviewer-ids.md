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

## Round 2 (plan v3 @ commit pending)

- Codex — pending dispatch.
- AGY — pending dispatch (direct `agy --print` transport per attempt 5).
- Claude SMR — pending.
