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
