# #6751 plan-review reviewer ledger

3-way hostile plan review (Codex + AGY + Claude SMR). Copilot is NOT a research
reviewer (it joins the quad at `/engineer` on the code PR).

| Round | Reviewer | ID / location | Verdict |
|---|---|---|---|
| r1 | Claude SMR | `claude-smr-plan-r1.md` | PLAN-NEEDS-REVISION (B1 tuple_unknown probe leak, B2 carry-over aliasing, B3 holder boundary, B4 pool/iface occupancy seam, M5-M8, N9-N10) |
| r1 | Codex | codex session `019fc774-03cb-74d0-b590-c17cd31a3803` (companion task `task-msd60x19-a1vhsp` + `codex exec resume` foreground) → `codex-plan-r1.md` | PLAN-NEEDS-REVISION (4 BLOCKERs: cross-domain overlap, generation-global registry, holder lifecycle, sync reserve not fail-closed; 5 MAJORs; 3 MINORs) |
| r1 | AGY | companion jobs `rescue-msd5qexy-q9isgm` + `rescue-msd732ow-sp1cw8` both infra-misfired (returned `--print-timeout` CLI docs, not a review); direct `agy --print` foreground run succeeded → `agy-plan-r1.md` | PLAN-NEEDS-REVISION (2 BLOCKERs: reserve/insert race, cross-commit leak; 2 MAJORs incl. "adopt option (b)"; 2 MINORs; 1 NIT) |
| r2 | Claude SMR | `claude-smr-plan-r2.md` | PLAN-NEEDS-REVISION (all Codex/AGY r2 blockers independently verified; M9 install+reserve wrapper, M10 pre-reserve is_reverse+bulk note, M11 delete-sync tail, M12 brute-force squat variant) |
| r2 | Codex | codex session `019fc7a1-64a7-7db0-b3ee-2f2e1ccfab2d` (companion task `task-msd7snrk-35edf1`) → `codex-plan-r2.md` | PLAN-NEEDS-REVISION (3 BLOCKERs: runtime overlap seam, non-transactional sync reserve, shared-map holder gap; 3 MAJORs: lazy-create/reclamation, probe math wrong, validator owner granularity; 1 MINOR, 1 NIT). Option (a) endorsed. |
| r2 | AGY | direct `agy --print --dangerously-skip-permissions` foreground (companion headless auto-denied the command tool) → `agy-plan-r2.md` | PLAN-NEEDS-REVISION (2 BLOCKERs: materialize bypass, replace-time leak; 2 MAJORs: probe-mutex contention, helper-restart reserve gap; 2 MINORs, 1 NIT). Option (a) endorsed; r1 mis-parse claim withdrawn. |
| r3 | Claude SMR | `claude-smr-plan-r3.md` | PLAN-NEEDS-REVISION (AGY r3 majors adjudicated: displacement refined to canonical-map pin, wholesale clear confirmed; M13 delta-relay inventory, M14 per-holder-owner decrement, M15 conflict-drop counter) |
| r3 | Codex | codex session `019fc7b7-81b3-7123-a9ab-9966860dfc01` (companion task `task-msd8npxz-0qs5md`) → `codex-plan-r3.md` | PLAN-NEEDS-REVISION (4 BLOCKERs: live-pool-session drain gap, pool_failure-blind reserve scan + NAT64 channel, install-before-reserve wrapper race, wholesale clear at stop/rebind; 3 MAJORs: exhaustion claims, HA-fidelity DoS acceptance, observability scope; 1 MINOR) |
| r3 | AGY | direct `agy --print --dangerously-skip-permissions` foreground → `agy-plan-r3.md` | PLAN-NEEDS-REVISION (2 MAJORs: publish-displacement {Shared} leak, wholesale-clear {Shared} leak; 1 NIT: churn-cap accumulation; every other r2 fold verified complete) |
| r4 | Claude SMR | (fold-only round — SMR r4 findings were pre-empted by Codex/AGY r4 and folded directly; see plan v5 header) | — |
| r4 | Codex | codex session `019fc7cd-f792-7cc1-a6de-106358ca4ebe` (companion task `task-msd9j9yk-f6n9wd`) → `codex-plan-r4.md` | PLAN-NEEDS-REVISION (6 BLOCKERs: tri-state reserve, drain-marker ordering + atomic lift, addr_index authoritative, worker-teardown markers, publish-acquires-{Shared}, tuple-change overlap; 2 MAJORs: materialize failure semantics, egress derivation matrix; 1 MINOR, 1 NIT) |
| r4 | AGY | direct `agy --print --dangerously-skip-permissions` foreground → `agy-plan-r4.md` | PLAN-NEEDS-REVISION (2 MAJORs: {Worker} leak across stop/rebind, drain release-scan omission on pool edit; 1 MINOR: {Shared} asymmetry on worker reserve refusal — documented) |
| r5 | Claude SMR | `claude-smr-plan-r5.md` | PLAN-READY-WITH-NITS (no BLOCKER/MAJOR survives; self-found N16 reverse-companion relay-lag window documented as inherited pool-shape discipline) |
| r5 | Codex | codex session `019fc7e7-9d1d-72f1-9ccc-e64dbeeb62ed` (companion task `task-msdajap7-xs09zy`) → `codex-plan-r5.md` | PLAN-NEEDS-REVISION (3 BLOCKERs: live_by_flow single-record cardinality vs staged overlap, canonical-row/alias staleness on tuple replace, re-enabled pool minting past an older draining generation; 1 MAJOR: materialize None is a cold-miss not a drop) |
| r5 | AGY | direct `agy --print --dangerously-skip-permissions` foreground → `agy-plan-r5.md` | PLAN-READY-WITH-NITS (every r4 fold verified; 2 NITs: Prometheus reason label, staged pre-read helper signature) |

Round-1 infra notes: the Codex companion background job tracker lost the first
job (`task-msd5pjfq-yfwbeg` — state dir is workspace-hash-keyed and the poll
cwd must be the worktree); the review completed via foreground
`codex exec resume`. The AGY companion `rescue` wrapper mangled the prompt
twice (model answered a meta question about its own `--print-timeout` flag);
the review completed via direct `agy --print` invocation. Per
`feedback_codex_infra_must_retry` both were retried to real completions —
neither counts as a blocked/absent review.

## Round-1 convergence state

All three reviewers independently confirmed the bug analysis (real, High,
nothing existing disambiguates). All three demanded revision; the findings
converged on: probe purity (SMR B1 = Codex 5), registry lifetime (SMR B2 =
Codex 2 = AGY 2), holder model (SMR B3 = Codex 3), cross-domain occupancy seam
(SMR B4 = Codex 1), over-PATing semantics (Codex 6 → v2 identity-set redesign,
which also moots AGY 1 + SMR M5), Junos wording (SMR N9 = Codex 7 = AGY 5),
pinned-test disposition (SMR M7 = AGY 7), release-site inventory (Codex 10),
RST-claim wording (Codex 12), (a)-vs-(b) fork dispute (AGY 4 — answered in v2
with the identity-squatting-DoS counter-argument + the (a)≈(b)+probe redesign).
v2 folds every finding; round 2 re-reviews v2.
