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
| r6 | Claude SMR | `claude-smr-plan-r6.md` | PLAN-READY-WITH-NITS (v6 mechanisms verified independently; nits: alias-sweep same-tuple guard, sticky-pool quarantine exhaustion — folded in v6.1) |
| r6 | Codex | codex session `019fc800-2646-70d1-a7d2-a28e76dd9a1d` (companion task `task-msdbhrfh-dslfvv`) → `codex-plan-r6.md` | PLAN-NEEDS-REVISION (1 BLOCKER: fabric forward-wire alias separately-synced canonical row false-conflicts + sole-marker hazard + sweep gap; 1 MAJOR: idempotence secondary index + reserve auto-drop; 2 MINORs; 1 NIT) |
| r6 | AGY | direct `agy --print --dangerously-skip-permissions` foreground → `agy-plan-r6.md` | PLAN-READY-WITH-NITS (all v6 folds verified incl. staged replacement walkthrough, alias-sweep parity, quarantine placement; 2 carried NITs) |
| r7 | Claude SMR | `claude-smr-plan-r7.md` | PLAN-READY-WITH-NITS (self-found E1 out-of-order alias-first merge rule, folded v7.1; AGY's 2 nits adopted) |
| r7 | Codex | codex session `019fc822-a935-71e3-addc-8573934988ef` (companion task `task-msdcu8lh-9omzxx`) → `codex-plan-r7.md` | PLAN-NEEDS-REVISION (3 BLOCKERs: telemetry predicate unsafe as ownership equivalence — needs session-identity clause; holder set cannot encode base+alias multiplicity — needs per-row counts; NAT64 alias export class uncovered; 1 MAJOR: sweep needs compare-and-remove; 1 MINOR; 1 NIT) |
| r7 | AGY | direct `agy --print --dangerously-skip-permissions` foreground → `agy-plan-r7.md` | PLAN-READY-WITH-NITS (fabric-alias lifecycle verified end-to-end; 2 NITs: out-of-order arrival test, predicate doc comment) |
| r8 | Claude SMR | `claude-smr-plan-r8.md` | PLAN-READY-WITH-NITS (four-part predicate re-derived sound; fallback discriminates via per-session node-local id; counting HolderSet order-safe; folded v8.1 RTFlowSessionID precision) |
| r8 | Codex | codex session `019fc83b-6d00-7790-9542-2eb2ab337ffc` (companion task `task-msddt06o-dlnhjt`) → `codex-plan-r8.md` | PLAN-NEEDS-REVISION (1 BLOCKER: zero/legacy id fallback unsafe — per-call generation stamps break value equality, legacy all-zero values false-match; fix = fail closed; 1 MAJOR: compare-and-remove identity chain + per-map atomicity; 1 MINOR: §9 must enumerate five fixed-path quarantine tests) |
| r8 | AGY | direct `agy --print --dangerously-skip-permissions` foreground → `agy-plan-r8.md` | PLAN-READY-WITH-NITS (all v8 folds verified incl. id-0 fallback adequacy; 2 implementation nits) |
| r9 | Claude SMR | `claude-smr-plan-r9.md` | PLAN-READY-WITH-NITS (fail-closed consequence verified near-free via the derived forward-wire index; N17 counter-semantics doc, folded v9.1) |
| r9 | Codex | codex session `019fc851-bc9c-7df0-94bc-40a9954e4a95` (companion task `task-msdeod3l-mvzavu`) → `codex-plan-r9.md` | PLAN-NEEDS-REVISION (1 BLOCKER: zero-id alias-first arrival lets the alias reserve and the real base drop — needs wire-form-yield/deferral; 1 MAJOR: identity chain not representable on SyncedSessionEntry (no node-local id; local publications are session_id 0) — needs a helper-local publication token) |
| r9 | AGY | direct `agy --print --dangerously-skip-permissions` foreground → `agy-plan-r9.md` | PLAN-READY-WITH-NITS (all v9 folds verified incl. the standby forward-wire walk resolving to base; 1 NIT: v4+v6 alias test parity) |
| r10 | Claude SMR | `claude-smr-plan-r10.md` | PLAN-READY-WITH-NITS (N18 retain merged alias row, folded v10.1; mooted by v11) |
| r10 | Codex | codex session `019fc86a-a176-7f60-ae06-a38c38bf45d2` (companion task `task-msdfnbxz-7navdm`) → `codex-plan-r10.md` | PLAN-NEEDS-REVISION (1 BLOCKER: wire-form-yield unsafe — alias's published artifacts (canonical row + broken synthesized companion with rewrite_dst=E) not retracted by holder merging; 1 NIT) |
| r10 | AGY | direct `agy --print --dangerously-skip-permissions` foreground → `agy-plan-r10.md` | PLAN-READY-WITH-NITS (wire-form-yield walks verified; 1 carried NIT) |
| r11 | Claude SMR | `claude-smr-plan-r11.md` | PLAN-READY-WITH-NITS (retreat verified: alias row redundant with derived index; broken companion independently confirmed as live shipped hazard) |
| r11 | Codex | codex session `019fc88d-926d-7510-b7b5-b5069e7bbacd` (companion task `task-msdh0f0a-lsp1j5`) → `codex-plan-r11.md` | PLAN-NEEDS-REVISION (2 BLOCKERs: flag has no end-to-end carrier across the cluster wire + unmarked deletes; old-Go+new-helper cell regresses under the new reserve machinery; 1 MAJOR: pub_token chain text lost in the section replacement; 1 NIT: stale fold artifacts) |
| r11 | AGY | direct `agy --print --dangerously-skip-permissions` foreground → `agy-plan-r11.md` | PLAN-READY-WITH-NITS (redundancy + broken-companion + matrix all verified; 2 carried NITs) |
| r12 | Claude SMR | `claude-smr-plan-r12.md` | PLAN-READY-WITH-NITS (v12 carrier/gate/drop-point verified; §9 counter typo folded v12.1) |
| r12 | Codex | codex session `019fc8ac-0d94-7772-adc4-46db74a88c5b` (companion task `task-msdi787b-0wwwlx`) → `codex-plan-r12.md` | PLAN-NEEDS-REVISION (2 BLOCKERs: cluster codec serializes only byte(Flags) — high bits lost, sync_protocol.go:116/122/231/237/396/525, low byte fully assigned; unmarked alias delete can delete a genuine canonical occupant via DeleteWithCompanions + unconditional helper delete; 1 MAJOR: sticky gate has an unavoidable bootstrap false-positive window; 1 MINOR: drop hook must be in pkg/cluster pre-bulk, sync_conn_read.go:109; 1 NIT: counter inventory) |
| r12 | AGY | direct `agy --print --dangerously-skip-permissions` foreground → `agy-plan-r12.md` | PLAN-READY-WITH-NITS (carrier/drop/sticky-gate/pub_token/artifacts verified; 1 NIT: §9 said four counters) |

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

## Rounds 13-26 (compact ledger; full review docs in this directory)

Codex ran via `codex exec` foreground sessions (IDs below); AGY ran via
direct `agy --print --dangerously-skip-permissions` foreground; Claude SMR
docs are `claude-smr-plan-r<N>.md` in this directory. From round 13 the
review docs were archived to /tmp only; they are backfilled here as
`codex-plan-r<N>.md` / `agy-plan-r<N>.md` (round 26 backfill + ledger
catch-up in the v15.14 commit).

| Round | Codex session / verdict | AGY verdict | Claude SMR verdict |
|---|---|---|---|
| r13 | `019fc8c2-c4d8-7933-ba77-c4bd47f1cb10` / PLAN-NEEDS-REVISION | PLAN-READY-WITH-NITS | PLAN-READY-WITH-NITS (r13 file) |
| r14 | `019fc8ec-95b8-73e2-9c6c-67c332ed1f7a` / PLAN-NEEDS-REVISION | PLAN-READY-WITH-NITS | PLAN-READY-WITH-NITS (r14 file) |
| r15 | `019fc8fe-d80b-77c2-bee8-f91fd6c6288c` / PLAN-NEEDS-REVISION | PLAN-NEEDS-REVISION (bulk-bookkeeping blocker) | PLAN-READY-WITH-NITS (r15 file) |
| r16 | `019fc91d-f77c-7c73-a301-d885ec99f21e` / PLAN-NEEDS-REVISION | PLAN-READY-WITH-NITS | PLAN-READY-WITH-NITS (r16 file) |
| r17 | `019fc930-ed4e-7b43-aeee-cf7f9d6462e3` / PLAN-NEEDS-REVISION | PLAN-READY-WITH-NITS | PLAN-READY-WITH-NITS (r17 file) |
| r18 | `019fc93f-b633-7191-acb6-bd398f400de5` / PLAN-NEEDS-REVISION | PLAN-READY-WITH-NITS | PLAN-READY-WITH-NITS (r18 file) |
| r19 | `019fc95f-4a54-75c0-96f4-e71265b70fd8` / PLAN-NEEDS-REVISION | PLAN-READY-WITH-NITS | PLAN-READY-WITH-NITS (r19 file) |
| r20 | `019fc96d-dec6-7870-9c69-3ed87e33cf03` / PLAN-NEEDS-REVISION | PLAN-READY-WITH-NITS | PLAN-READY-WITH-NITS (r20 file) |
| r21 | `019fc983-5b3a-72e0-adf1-3b666963566c` / PLAN-NEEDS-REVISION | PLAN-READY-WITH-NITS | PLAN-READY-WITH-NITS (r21 file) |
| r22 | `019fc993-44db-7290-8e5a-f626b15d6b45` / PLAN-NEEDS-REVISION | PLAN-READY-WITH-NITS | PLAN-READY-WITH-NITS (r22 file) |
| r23 | `019fc9a4-2f5e-7d83-b4dc-fb1493447a58` / PLAN-NEEDS-REVISION | PLAN-READY-WITH-NITS | PLAN-READY-WITH-NITS (r23 file) |
| r24 | `019fc9b5-1d7f-71c1-a480-08a202b56598` / PLAN-NEEDS-REVISION | PLAN-READY-WITH-NITS | PLAN-READY-WITH-NITS (r24 file) |
| r25 | `019fc9c0-9b1c-7d71-9d30-6d199428946f` / PLAN-NEEDS-REVISION | PLAN-NEEDS-REVISION (equal-generation CAS blocker) | PLAN-READY-WITH-NITS (r25 + r26 files) |
| r26 | `019fc9d5-922d-7ef3-86e0-d5d2eaf46679` / PLAN-NEEDS-REVISION (2 BLOCKERs: readiness-timeout bypass, lossless-bulk order; 1 MINOR: §9 test enumeration; 1 NIT) | PLAN-READY-WITH-NITS (2 nits, folded v15.13.1) | PLAN-READY-WITH-NITS (r26b fold-check of v15.13) |

Round-26 disposition: Codex's 4 findings fold in v15.14 (readiness-timeout
joins the lifecycle event inventory; prime order via epoch barrier with the
bulk keeping its lossless direct-write discipline; §9 enumerates the six
lifecycle/delta regression tests explicitly; stale binding-point sentence
corrected). Round 27 re-reviews v15.14.

| r27 | `codex exec` foreground (detached-poll), session in /tmp/codex-6751-r27.log / PLAN-NEEDS-REVISION (2 BLOCKERs: content-order cut, authoritative recovery; 1 MINOR: ss==nil teardown skip; 2 NITs) | PLAN-READY-WITH-NITS (1 nit: drain bound in parameter summary — folded) | PLAN-READY-WITH-NITS (r28 fold-check of v15.15) |

Round-27 disposition: all five Codex findings + the AGY nit fold in
v15.15 (content-version binding V1-V4, epoch-at-stamp envelopes with
the journal-replay exception, authoritative-only recovery,
unconditional timer invalidation, stall-seam precision, flag-name
corrections, drain-bound parameter). AGY note: agy 1.1.10 requires
`--prompt`; positional args are silently ignored (two misfires
answered flag documentation — retried per infra-must-retry, real
review obtained). Round 28 re-reviews v15.15.

| r28 | `codex exec` (detached-poll), session in /tmp/codex-6751-r28.log / PLAN-NEEDS-REVISION (4 BLOCKERs: mirror not a consistent cut, debt ownership/discharge, pre-DNAT dst_port occupancy, RTFlowSessionID not retrievable; 2 MAJORs: double-mint, V4 trigger; 1 MINOR: equality projection) | PLAN-READY-WITH-NITS (1 nit: receive-deadline default — folded) | PLAN-READY-WITH-NITS (r29 fold-check of v15.16) |

Round-28 disposition: all seven Codex findings + the AGY nit fold in
v15.16 (producer-ordering invariant for Close; daemon-lifetime
monotonic-generation debt with exact-generation ACK discharge;
effective-destination IP+port canonicalization; decode-time
base-identity index; universal producer atomicity; sender-side
known-stale omission; telemetry-excluded equality projection;
receive-deadline default). Round 29 re-reviews v15.16.

| r29 | `codex exec` (detached-poll), session in /tmp/codex-6751-r29.log / PLAN-NEEDS-REVISION (5 BLOCKERs: incarnation/producer-completeness, pre-BulkStart Open gap, owner/occupancy conflation, static cross-domain, index lifecycle+stale-row; 3 MAJORs: debt attribution, worker-id threading, fallible allocator; 3 MINORs: producer enumeration, sweep bound, projection) | PLAN-READY (no nits) | PLAN-READY-WITH-NITS (r30 fold-check of v15.17) |

Round-29 disposition: all eleven Codex findings fold in v15.17
(incarnation-conditional error-accounted delete + three-producer
funnel; received-set carry-forward; owner/occupancy tuple split with
effective-port plumbing; static whole-address occupancy arm;
received-set-bounded index + confirm-purge; debt epoch→debtGen
attribution + terminal clear; worker-id threading; fallible
allocator_for; sweep-wake; producer enumeration precision;
projection exclude-list). AGY wrote its PLAN-READY verdict with zero
findings. Round 30 re-reviews v15.17.

| r30 | `codex exec` (detached-poll), session in /tmp/codex-6751-r30.log / PLAN-NEEDS-REVISION (6 BLOCKERs: close ordering producer-incomplete/non-convergent, carry-forward poisoned aliases + unbounded, split not API-representable, worker-holder/standby lifecycle, static mapped-port + test inversion + provenance, alias index/purge three failures; 1 NIT: pre-dispatch assertion) | PLAN-NEEDS-REVISION (1 BLOCKER: tunnel_purge 4th producer; 3 MAJORs: zombie resurrection, worker-shard locality, carry-forward abort invalidation; 4 MINORs: index overflow misdelivery, carry-forward cardinality, static counter, mapped-port static) | PLAN-READY-WITH-NITS (r31 fold-check of v15.18) |

Round-30 disposition: AGY's 8 + Codex's 7 findings fold together in
v15.18 (compare-and-delete on the #5213 session_id; four-producer
funnel + tracked purge generations; sender delete tombstones;
clear-on-completion carry-forward with forceResync overflow;
provisional admitted aliases with exact-publication purge;
API-representable owner/occupancy split with InterfaceOwnerKey;
import-driven standby allocator creation; static provenance + mapped
ports + own counter; id preservation across HA hops; pre-dispatch
no-pair assertion; SMR r31 legacy-id pin). Round 31 re-reviews v15.18.

| r31 | `codex exec` (detached-poll), session in /tmp/codex-6751-r31.log / PLAN-NEEDS-REVISION (7 BLOCKERs: close not incarnation-linearizable + fatal inverse, zombie at gen-map capacity, carry-forward overflow wrong direction, owner/occupancy API contradictory, static emitted-port/inbound/drain, P2 no atomic seam, old-sender lost-base cell; 2 MAJORs: deferral liveness, FOUR-producers false tree-wide; 1 MINOR: standby edge tests) | PLAN-READY-WITH-NITS (2 nits, both already satisfied by v15.18 pins) | PLAN-READY-WITH-NITS (r32 fold-check of v15.19) |

Round-31 disposition: Codex's 10 findings fold in v15.19
(incarnation-gated close suppression end-to-end with striped-mutex
atomicity; omission index + table-truth overflow; fenced inbound
re-prime + reconciliation hold; honest signature inventory; static
emitted-port/inbound/drain; serialized-loop purge; honest
mixed-version cell; scoped producer claim; standby edge tests).
Round 32 re-reviews v15.19.

| r32 | `codex exec` (detached-poll), session in /tmp/codex-6751-r32.log / PLAN-NEEDS-REVISION (7 BLOCKERs: cross-process gate not atomic + refresh-restore inverse, purge id source absent + legacy zero undefined, omission-index seam + non-authoritative overflow, receiver-local fencing can't force inbound prime, carried-hold overflow identity, inbound static lifecycle, P2 no atomic seam; 2 MAJORs: deferral liveness, contradictory old-sender promises; 1 MINOR: probe signature; 1 NIT: 257th qualifier) | PLAN-READY-WITH-NITS (2 nits: stripe count, reverse-companion test — both folded) | **PLAN-NEEDS-REVISION on the v15.19 substrate + PATH B (table-truth) RECOMMENDED** (r33 doc — the fold attempt surfaced the six-round breed-a-race pattern; the substrate fork is now §4.0) |

Round-32 disposition: the round is the inflection point. Rather than
fold a seventh mirror-defense layer, v15.20 puts the substrate fork
to the reviewers in §4.0: PATH A (cross-process arbiter, rerouted
HA import — rejected on the control-socket contention foreclose) vs
PATH B (table-truth snapshot channel; the mirror exits the sync
path; every mirror-defense mechanism retires). Round 33 adjudicates
the fork.

| r33 | `codex exec` (detached-poll), session in /tmp/codex-6751-r33.log / fork adjudication: **PATH A** (control-socket foreclose DISPROVED — dedicated session socket exists; PATH B-as-written killed on 4 factual errors; PATH A needs bounded admission + ImportBarrier + sole-writer transaction + exact Close publication) | fork adjudication: **PATH B** (PATH A rejected on unbounded WorkerCommand queue + socket budget — the same factual error SMR made) | **Concedes to PATH A** after independent verification (r34 doc — both factual errors owned; §4.0.1 attacked rule-by-rule) |

Round-33 disposition: the fork CLOSED on corrected facts — PATH A
(sole-writer helper) is the adjudicated substrate. v15.21 rewrites
§4.0 with the evidence (dedicated session socket verified;
PATH B's four factual errors enumerated; "B2" table-truth noted as
possible future work) and §4.0.1 as the seven-rule sole-writer
specification with §4.0.2's consequence map (V1-V4 shrink, exact
omission results, in-helper P2, retained carry-forward/hold/
re-prime + prime-REQUEST field, debt pair recorded before End).
Round 34 re-reviews v15.21 for convergence.

| r34 | `codex exec` (detached-poll), session in /tmp/codex-6751-r34.log / PLAN-NEEDS-REVISION (10 BLOCKERs: writer inventory incomplete ×3 classes + ABI bug, Rule 2 deadline/admission/refusal-recovery, Rule 3 two-ledger, Rule 4 absent-predicate/one-producer/identity-domains, Rule 5 RMW, Rule 6 one-arbiter + both-lane fields + incarnation namespace, Rule 7 sticky lineage, known-stale copy binding, omission-overflow authoritative source, old-peer re-prime proof; 1 MAJOR: P2 ownership) — explicitly "fixable within PATH A, not PLAN-KILL" | PLAN-NEEDS-REVISION (1 MAJOR: Rule 3 vs §5.6 bookkeeping; 2 MINORs: dedup reconnect reset, 11th writer restoreBPFSession; 2 NITs: clear latency, metric scope) — PATH A ACCEPTED on the corrected evidence | PLAN-READY-WITH-NITS (r35 fold-check of v15.23; self-audit for the fifth factual error passed) |

Round-34 disposition: AGY's 5 + Codex's 11 findings fold in
v15.23 (two-ledger applied transaction with five terminal outcomes;
complete writer inventory with the negative bound; one deadline +
reserve-before-mutate + fence-on-unknown; table-authoritative
delete predicate + one close producer + identity domains; RMW
refresh; one-arbiter dual-lane dedup with additive both-lane
fields; sticky alias lineage; copy-time identity binding; framed
helper-snapshot recovery source; quiet-interval re-prime; P2
in-helper). Codex r34 also surfaced a shipped ABI bug
(maps_sync.go:609 reads SessionID bytes as Created) — flagged for
a separate fix issue, NOT absorbed into this plan. Round 35
re-reviews v15.23.

| r35 | `codex exec` (detached-poll), session in /tmp/codex-6751-r35.log / PLAN-NEEDS-REVISION (1 BLOCKER: quiet interval controls outbound dialing not inbound admission — the non-initiator redial race; 1 MAJOR: worker outcomes not recorded before barrier ACK / §5.6 "not fed back" contradiction; 3 MINORs: incarnation namespace reuse, ConfirmedAliasNoop terminalizes before P2 result, replica refresh owner predicate; 1 NIT: NACK naming — several attacks CLOSED: F1 inventory, quarantine recording, F4, F8, F9 precedent, M11) | PLAN-READY-WITH-NITS (2 MINORs: arbiter Go-side scoping, NACK = connection teardown; 1 NIT: replica last_seen only) | PLAN-READY-WITH-NITS (r36 fold-check of v15.24) |

Round-35 disposition: all six findings fold in v15.24 (Go-side
arbiter scoped; teardown named as the single fence mechanism; the
quiet interval becomes a BOTH-directions admission fence; worker
outcomes mandatory before barrier ACK with the §5.6 asymmetry
superseded; daemon-issued incarnation namespace; ConfirmedAliasNoop
terminalizes only after P2's report; origin-predicate replica
refresh with monotonic last_seen). Round 36 is the convergence
check.

| r36 | `codex exec` (detached-poll), session in /tmp/codex-6751-r36.log / PLAN-NEEDS-REVISION (1 BLOCKER: post-auth refusal installs locally first — transport-level refusal required; 1 MAJOR: the missed second r35 MAJOR — alias-suspect lineage (marking only confirmed aliases permits alias→promote→export; marking every suspect permanently over-suppresses genuine rows); 2 MINORs: §5.6 paragraph replacement, §9 failure-semantics pins; 2 NITs: normative incarnation in Rule 6, replica iterator origin projection) | PLAN-READY-WITH-NITS (2 nits: RST refusal feedback, quiet_interval = 2.5× keepalive_timeout — both folded) | PLAN-READY-WITH-NITS (r37 fold-check of v15.25) |

Round-36 disposition: all findings fold in v15.25 (transport-level
refusal with re-fence cycles; two-stage alias-suspect/alias-lineage
marks with definitive-pass clearing; §5.6 paragraph replaced; §9
failure-semantics pins; normative daemon-issued incarnation;
iterator origin projection). Round 37 is the convergence check.

| r37 | `codex exec` (detached-poll), session in /tmp/codex-6751-r37.log / PLAN-NEEDS-REVISION (1 BLOCKER: listener closure does not fence already-accepted pre-install children — generation-bind Accept through install, kill pre-fence children, reject stale stamps; 1 MAJOR: the 5s window's clear semantics contradictory — only complete-prime or row-close clears, suspect owes a prime; 2 MINORs: §9 pins absent, stage carrier inventory; 2 NITs: Rule 6 incarnation fold only in summary, stale-replica regression absent) | PLAN-READY-WITH-NITS (2 nits: export-skip counter for both marks, incarnation-advancement log marker — both folded; BUT its §9-pins verification was a hallucination pattern-matched on the header — the pins were absent, caught by the audit) | PLAN-READY-WITH-NITS (r38 fold-check + the fold-landing audit — 3 silent fold failures found and repaired, grep-verified) |

Round-37 disposition: the round exposed a process failure — three
earlier folds had silently no-opped (python replace wrap mismatch)
and AGY's §9 "verification" was hallucinated. All repaired and
grep-verified in v15.26, plus the substance folds: generation-bound
admission with pre-fence child kill + stale-stamp rejection; the
5s window never clears alias-suspect (complete-prime or row-close
only; the suspect owes a prime via prime-REQUEST with the fence
bound); the lineage stage carrier inventory; four consolidated §9
suites. Round 38 is the convergence check.

| r38 | `codex exec` (detached-poll), session in /tmp/codex-6751-r38.log / PLAN-NEEDS-REVISION (2 BLOCKERs: accept-after-advance escapes through the fence (accept-refuse-while-engaged + release-side generation advance); legacy no-heartbeat-ACK peer retains C0 (two-mode both-empty proof: interval-derived vs OBSERVED PRIME + re-fence); 2 MAJORs: 5s "definitive" wording contradicts no-window-clear; stage carrier lacks Go→helper ingress + §6 reconciliation (second additive field, import request rides it, promotion Open gated, all exporters gated); 1 MINOR: prime-request/re-fence liveness suite; 1 NIT: export-skip counter not in §5.8) | PLAN-READY-WITH-NITS (2 nits: export-skip counter in the §5.8 table, incarnation log marker carries G_old → G_new — both folded; its line-cites are now grep-verified per the process fix) | PLAN-READY-WITH-NITS (r39 fold-check of v15.27; accept-refusal atomicity, legacy-both-detectors-absent residual, stage wire-enum degradation analyzed) |

Round-38 disposition: all findings fold in v15.27 (accept-proof
fenced window with release-side advance; two-mode both-empty proof
with the no-ACK C0 pin; disposition-vs-lineage wording fixed with a
fail-on-timeout-clear regression; the stage carrier reconciled
end-to-end as a second additive SyncedSessionEntry field with all
exporters gated; the liveness suite; the §5.8 counter (6+3=9) and
log marker). Round 39 is the convergence check.

| r39 | `codex exec` (detached-poll), session in /tmp/codex-6751-r39.log / PLAN-NEEDS-REVISION (2 BLOCKERs: observed BulkStart proves neither both-empty nor authoritativeness — the no-ACK cohort predates #5085's lossless bulk (capability-gate: legacy windows are FRAMING-ONLY); nothing plan-bounded kills retained legacy C0 (the cited deadline was a WRITE deadline — my factual error, owned — honesty statement + readiness-timeout terminal + interval cap); 1 MAJOR: §6 two-field contradiction (folded as the AGY nit); 1 MINOR: exact accept trace absent from §9; 2 NITs: named admission mutex, literal 'CURRENT store as definitive' tail) | PLAN-READY-WITH-NITS (1 nit: §6 line 2690 still said ONE additive field — folded) | PLAN-READY-WITH-NITS (r40 fold-check of v15.28; the honesty folds verified; the write-deadline factual error owned) |

Round-39 disposition: all findings fold in v15.28 (capability-gated
authoritative uses of a bulk window; retained-C0 honesty with the
readiness-timeout terminal and interval cap; §6 two-field
reconciliation; named admission mutex with advance-before-disengage;
the exact accept trace + wording cleanup pinned). Round 40 is the
convergence check.

| r40 | `codex exec` (detached-poll), session in /tmp/codex-6751-r40.log / PLAN-NEEDS-REVISION (2 BLOCKERs: framing-only rule contradicts the retained r15-era resolution rules + bootstrap (capability ticker at 5-10s vs immediate cold-prime — per-window authority binding, disposition-only non-capable resolution, ordered pre-data send, fresh capable prime on first-learn); the retained-C0 degraded terminal is not code-real (the detector is ≈20s not 5s, the 5s readiness timer is connected-only with a no-release-without-reconnect regression, classic RETH VRRP has a 30s hold — derived interval + fence-owned disconnected-eligible terminal); 1 MAJOR: alias-proof debt can never discharge for a legacy peer (two separate debts: delivery vs alias-proof); 1 MINOR: retained-C0 regression absent from §9) | **PLAN-READY (zero findings)** — first clean verdict of the research | PLAN-READY-WITH-NITS (r41 fold-check of v15.29; ordered-send robustness, disposition-only vs never-ACK, first-learn storm bound, 20s-delay failover pricing analyzed) |

Round-40 disposition: all findings fold in v15.29 (per-window
authority binding; disposition-only non-capable resolution with
genuine rows never regressing; ordered pre-data capability send
with UNKNOWN = non-capable and a forced fresh capable prime on
first-learn; derived quiet interval from the actual ≈20s detector;
fence-owned disconnected-eligible degraded terminal with the
connected-only 5s timer preserved and the 30s classic-VRRP hold +
private-RG gate as outer bounds; two separate debt terminals; the
§9 regression). AGY's PLAN-READY is the first clean verdict.
Round 41 is the convergence check.

| r41 | `codex exec` (detached-poll), session in /tmp/codex-6751-r41.log / PLAN-NEEDS-REVISION (4 BLOCKERs: capability/framing contradiction remains in retained texts + ordered send not bound to a lossless pre-publication path (the EMISSION GATE — checked direct write before publication, failed write fails the connection + cold-prime); degraded interval vs connected-only terminal conflict (the stale 2.5×keepalive text replaced with the derived 2×syncReadDeadline+5s everywhere); fence-cycle expiry missing from the lifecycle inventory + no precedence over the 5s timer + bulk-received effect reuse (seventh generation-bound lifecycle event, atomic engagement gating, DISTINCT release effect with no false bulk-completion and no debt discharge); private-RG outer gate not code-real (INTRODUCED by this plan — daemon_ha_vip.go:40-55 takes over on VIP readiness with IsSyncReady() false; §9 refusal pin)) | PLAN-READY-WITH-NITS (2 nits: named jitter constant 2×syncReadDeadline+5s; §6 struct inventory notes syncCapabilityTicker — both folded) | PLAN-READY-WITH-NITS (r42 fold-check of v15.30; emission-gate failure posture, seventh-event composition, private-RG proportionality analyzed) |

Round-41 disposition: all findings fold in v15.30 (lossless
emission gate for the capability frame; retained resolution rules
scoped by the capability gate; derived interval everywhere; the
seventh lifecycle event with atomic precedence and a distinct
degraded-release effect; the private-RG gate introduced by this
plan). Round 42 is the convergence check.

| r42 | `codex exec` (detached-poll), session in /tmp/codex-6751-r42.log / PLAN-NEEDS-REVISION (4 BLOCKERs: last retained-text contradictions (scoped); seventh event + fence precedence absent from the detailed contract (readiness commit re-validates fence state now); fence engagement never arms the hold its expiry releases — a REAL logic hole (engagement's commit unit sets readiness false + re-arms the classic hold); private-RG gate lacks the sync-configured predicate (conditioned on fabric endpoints — no-op otherwise); 2 MAJORs: behavior change unpriced/unpinned (§8 pricing vs the deliberate-policy history + §9 refusal + no-op cases); alias confirmation names the impossible "current store" (decode-time base-identity index named as the predicate's source); 1 NIT: interval formula joins the parameter summary) | PLAN-READY-WITH-NITS (2 nits: capability qualifier on the §9 recaps; seven-event parenthetical — both folded) | PLAN-READY-WITH-NITS (r43 fold-check of v15.31; engagement-arming disjointness from #466, the re-armed hold's 30s bound ordering, and the stranded-cluster class analyzed) |

Round-42 disposition: all findings fold in v15.31 (retained-text
scoping sweep complete; fence-state revalidation in the readiness
commit unit; engagement arms the hold — the real logic hole closed;
the conditioned private-RG gate with §8 pricing and §9 refusal +
no-op pins; the index-named predicate source; the parameter summary
interval). Round 43 is the convergence check.

| r43 | `codex exec` (detached-poll), session in /tmp/codex-6751-r43.log / PLAN-NEEDS-REVISION (4 BLOCKERs: capability-gated alias resolution still contradictory (evidence-based insertion confirmation vs window-authority decisions — the split); the readiness gate uses neither production predicate (whole direct/no-VRRP domain; control-link OR fabric endpoints; peer-dead bypass survives); configured never-connected cold startup has no bounded terminal (cold-start degraded release with heartbeat-alive priority precondition, no-release-without-reconnect preserved for its own case); re-arming through SetSyncHold imports an untagged stale-timer release (re-arm via the lifecycle queue / generation-bound hold); 1 MINOR: §9 lacks the explicit stale-fence-expiry-after-rearm pin) | PLAN-READY-WITH-NITS (1 nit: the §9 callback recap lists 5 events, update to 7 — folded) | PLAN-READY-WITH-NITS (r44 fold-check of v15.32; the pre-learn mixed deployment, forged-id trust model, endpoint-pair completeness, cold-start priority precondition, and the shared-pointer race death analyzed) |

Round-43 disposition: all findings fold in v15.32 (evidence-vs-
authority confirmation split; whole-domain conditioned gate with
peer-dead bypass intact; cold-start bounded release; generation-
bound hold re-arm; the explicit §9 pin; the seven-event recap).
Round 44 is the convergence check.
