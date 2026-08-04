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

## Round 6 (plan v7 @ 3e388fde8)

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

## Round 7 (plan v8 @ ee2f548d8)

- **Codex r7** — background bash task `bl3eothhw`; output
  `/tmp/codex-6749-r7.out`; verdict doc `codex-plan-r7.md`. Verdict:
  DEMAND-REVISION (6 BLOCKER — update_fabrics not a fail-closed
  Go→Rust transaction + pending-only mark doesn't close the enabled
  gate; guard authority split Rust/Go; leaking defer epoch (needs
  rollover); terminal retry cap recreates the sink; debt/config-epoch
  contracts not implementable as stated; socket-tuple identity check
  tears on relaxed stores; + 3 MAJOR — claim boundary contradiction,
  Q2 sound + overlap test, tests/split-line).
- **AGY r7** — background bash task `b9tm0qwts` (trimmed prompt
  `/tmp/agy-6749-r7b-prompt.txt` after the 2505-line r7 prompt hit
  E2BIG; first attempt `bblk9uveu` failed "Argument list too long");
  output `/tmp/agy-6749-r7b.out`; verdict doc `agy-plan-r7.md`.
  Verdict: PLAN-READY-WITH-NITS (MAJOR f1: tag must gate on
  !hasActiveMACDebt; MINOR f2: test for it; NIT f3: arm-sync gate as
  explicit arm-direction skip).
- **Claude SMR r7** — `claude-smr-plan-r7.md`. Verdict:
  PLAN-READY-WITH-NITS (N1 exact empty-guard discriminator; N2 MAC
  debt member-removal cancellation; N3 plan-scoped convergence note).

## Round 8 (plan v8.2 @ f84e0827a)

- **Codex r8** — background bash task `bt8sgfmyh`; output
  `/tmp/codex-6749-r8.out`; verdict doc `codex-plan-r8.md`. Verdict:
  DEMAND-REVISION (3 BLOCKER — MAC contract not restart-safe or
  positively provenance-gated, applySem missing; update_fabrics
  unknown-outcome handling + understated budget; rollover belongs
  at acceptance + operator arm must clear the helper latch; + 3
  MAJOR — mixed-version Q1 producer, reset clock, tests/split-gate).
- **AGY r8** — background bash task `b0toie254` (prompt trimmed to
  122,201 bytes after two E2BIG failures at ~132-144KB:
  `byq130nbg` at 144,022 and `bubm0r8yi` at 132,025; the working
  ceiling is ~127KB); output `/tmp/agy-6749-r8c.out`; verdict doc
  `agy-plan-r8.md`. Verdict: PLAN-READY (clean pass, zero findings).
- **Claude SMR r8** — `claude-smr-plan-r8.md`. Verdict:
  PLAN-READY-WITH-NITS (N1 rollover ordering, N2 mixed-update
  whole-defer, N3 claimed-slot rebind assurance).

## Round 9 (plan v8.3 @ e7b835f73)

- **Codex r9** — background bash task `bo6f1zwek`; IN FLIGHT on v8.3
  at v8.4 fold time; output `/tmp/codex-6749-r9.out`.
- **AGY r9** — background bash task `bh7r5snyo` (prompt trimmed to
  122,243 bytes — the agy argv ceiling is ~127KB); output
  `/tmp/agy-6749-r9.out`; verdict doc `agy-plan-r9.md`. Verdict:
  DEMAND-REVISION (2 BLOCKER — two-phase precheck disables the whole
  dataplane on any down member; epoch-open debt deadlocks the first
  tagged rebind (applySem held during the flow); + 1 MAJOR —
  pre-disable resets neighborsPrewarmed on guard-hits; + 1 MINOR —
  operator arm must reset the retry clock; + 1 NIT — CLI display
  scope).
- **Claude SMR r9** — `claude-smr-plan-r9.md`. Verdict:
  PLAN-READY-WITH-NITS (N1 out-of-band admin-down as drift; N2
  first-validation-is-synchronous; N3 pre-disable must not reset
  liveness [= AGY f3]; N4 timeout-landed convergence path; N5
  dropped-queue errors + reverse-sync notes).

## Round 9, Codex verdict (v8.3 @ e7b835f73)

- **Codex r9** — background bash task `bo6f1zwek`; output
  `/tmp/codex-6749-r9.out`; verdict doc `codex-plan-r9.md`. Verdict:
  DEMAND-REVISION (2 BLOCKER — pre-disable insufficient without
  failure semantics + UNKNOWN cache divergence; reset clock event
  storm; + 4 MAJOR — invariant/error contradictions, test holes, HA
  authority, lost-ACK latch + nil-config teardown).

## Round 10 (plan v8.5 @ fe899556f)

- **Codex r10** — background bash task `bnbl68qo1`; output
  `/tmp/codex-6749-r10.out`; verdict doc `codex-plan-r10.md`.
  Verdict: DEMAND-REVISION (3 BLOCKER — three-bucket mixed-case
  outage + bucket semantics + handoff; unconditional fabric
  adoption hybrids; stored-generation guard contamination +
  three-authority latch; + 4 MAJOR — contradiction sweep, test
  folds, budget, handoff spec).
- **AGY r10** — background bash task `bawfiel1f` (prompt trimmed to
  126,173 bytes); output `/tmp/agy-6749-r10.out`; verdict doc
  `agy-plan-r10.md`. Verdict: PLAN-READY-WITH-NITS (1 MINOR —
  stored-generation guard must compare a config-only generation,
  not the fib-contaminated scalar; 2 NITs — rebind handler
  plumbing, evidence wish).
- **Claude SMR r10** — `claude-smr-plan-r10.md`. Verdict:
  PLAN-READY-WITH-NITS (N1 fib-invariance sentence [superseded by
  configEpoch]; N2 flap classes; N3 posture sentence).

## Round 11 (plan v8.6 @ dc0e618f8)

- **Claude SMR r11** — `claude-smr-plan-r11.md` (written by the
  prior session, committed here at f42b500ce2). Verdict:
  PLAN-READY-WITH-NITS (SMR11-1 MINOR — the pair-gated adoption
  wedges on a fib-bump failure; refine the gate to config
  lineage: adopt UNLESS staged-uncommitted OR
  helper-strictly-ahead-of-publishedSnapshot; + N2 bucket-i
  link-flap sentence + N3 configured-disabled posture
  sentence).
- **AGY r11** — background bash `bxaoyldjz`; direct `agy
  --print-timeout 9m --print "$(cat
  /tmp/agy-6749-r11-prompt.txt)"` (prompt assembled at 125,992
  bytes: boilerplate + transport-trimmed plan [rounds 1-9
  verdict rows, r8/r9 tables, Round-10 narrative, round-1
  detail, §2-§4, §7-§8, §10 elided] + evidence excerpts ev0/
  ev1/ev2/ev5/ev6 + manager_generation.go:55-73); output
  `/tmp/agy-6749-r11.out`; verdict doc `agy-plan-r11.md`.
  Verdict: PLAN-READY (clean pass, zero findings; evidence
  wishes informational).
- **Codex r11** — TWO dispatches on the same v8.6 blob:
  `task-msdotvm6-vc98k3` (orphan from the interrupted prior
  session, discovered in `status --all`) and
  `task-msdpdhr4-xmh4du` (this session, prompt
  `/tmp/codex-6749-r11-prompt.txt`, --fresh). The orphan stalled
  70+ minutes with no output and was CANCELLED; the completed
  task is the round-11 Codex verdict of record. Output:
  `/tmp/codex-6749-r11.out`; verdict doc `codex-plan-r11.md`.
  Verdict: DEMAND-REVISION (9 BLOCKER + 3 MAJOR — pair authority
  not a lineage pair; request-side hybrids unfenced; completion
  token false-refusal + ordering; ownership protocol + exits
  incomplete; configEpoch advance inconsistent; bucket cohort
  contradictory; LinkController not a contract; edge-trigger
  unsafe + error swallowed; test greens; 19s not worst-case.
  Q1 remains CLOSED).

## Round 12 (plan v8.7 @ d63d98f75e3d)

- **Claude SMR r12** — `claude-smr-plan-r12.md`. Verdict:
  DEMAND-REVISION (SMR12-1 BLOCKER — my own v8.7
  `ConfigGeneration` token false-refuses after ordinary overlay
  republishes (manager_overlay.go:188/:239 sends full applies
  with fresh generations; the helper's stored generation
  advances, the compile-stamped token does not) → fix is
  `config_epoch` ON THE WIRE; + SMR12-2 MAJOR — AttemptMACDebt's
  call direction contradicts the daemon→manager LinkController
  reality; + SMR12-3 staged-ahead scalar disjunct false-fires
  after fib bumps (upgraded to BLOCKER per AGY f3); + SMR12-4
  guard-env locus pin; + SMR12-5 bucket-iii pass-1 reread).
- **AGY r12** — background bash `bo613nc74`; direct `agy
  --print-timeout 9m --print` (prompt assembled at 125,322
  bytes); output `/tmp/agy-6749-r12.out`; verdict doc
  `agy-plan-r12.md`. Verdict: DEMAND-REVISION (3 BLOCKER —
  f1 re-sync cannot read B's ConfigGeneration (Go discards the
  staged snap on publish timeout, manager_compile.go:350-365);
  f2 = SMR12-1; f3 = SMR12-3; + 3 MAJOR — f4 AB-BA
  m.mu↔applySem inversion; f5 bucket-iii flap leaves member
  unmonitored; f6 telemetry-locus suppression deadlock).
  Convergence: AGY f2/f3/f4/f6 == SMR12-1/3/2/4; AGY f1/f5 new.
- **Codex r12** — background task `task-msdremqy-s0poqq`
  (prompt `/tmp/codex-6749-r12-prompt.txt`, --fresh); output
  `/tmp/codex-6749-r12.out`; verdict doc `codex-plan-r12.md`.
  Verdict: DEMAND-REVISION (11 BLOCKER + 3 MAJOR —
  ConfigGeneration vs wrong helper authority (all full-apply
  producers false-refuse); appliedSnapshot asymmetric capture;
  staged-ahead disjuncts false-block; B unrecoverable; echo
  erases staged intent + verb provenance + restart; reclassify
  discards MAC obligation; AttemptMACDebt incoherent;
  TRY-acquire starvation; env token causal/watch/incarnation/
  dispatch; error corrupts map-commit; :618 citation +
  pending-XSK handoff; test greens; budget omissions. Q1
  remains CLOSED).

## Round 13 (plan v8.8 @ c2147e57329e)

- **Claude SMR r13** — `claude-smr-plan-r13.md`. Verdict:
  DEMAND-REVISION (SMR13-1 BLOCKER — the content-dedup collapse
  advances the WRONG counter: the helper's stored epoch is set
  only on full applies, so collapsing accepted=pending on a
  no-publish skip wedges the adoption gate AND the fence;
  correct rule: retire the staged mint, pending=accepted;
  + SMR13-2 re-sync debt identity; SMR13-3 debt keying
  uniform sentence; SMR13-4 recovery drop-window + oscillation
  posture sentences).
- **AGY r13** — background bash `bkl6u4zsp`; direct `agy
  --print-timeout 9m --print` (prompt assembled at 126,383
  bytes); output `/tmp/agy-6749-r13.out`; verdict doc
  `agy-plan-r13.md`. Verdict: DEMAND-REVISION (4 BLOCKER —
  f1 = SMR13-1 (dedup desync); f2 mint-vs-stamp contradiction
  (text ambiguity — the mint point must be pinned:
  post-build/pre-dispatch staging, failed builds never mint,
  failed publishes leave a staged mint BY DESIGN); f3
  defer-intent deletion reopens the mid-compile arm-sync
  window (VERIFIED — the pre-Compile call covered the long
  build; fix: daemon sets intent+compileInFlight atomically
  before Compile); f4 applySem↔m.mu inversion (NOT VERIFIED —
  applySem is daemon-private, no manager→daemon path exists;
  answered by the hierarchy proof sentence); + 2 MAJOR — f5
  1Hz oscillation bound; f6 post-recovery binding
  reconciliation naming).
- **Codex r13** — background task `task-msdu5oma-68z6tz`
  (prompt `/tmp/codex-6749-r13-prompt.txt`, --fresh); output
  `/tmp/codex-6749-r13.out`; verdict doc `codex-plan-r13.md`.
  Verdict: DEMAND-REVISION (12 BLOCKER + 3 MAJOR — epoch
  allocator/ambiguous failure; overlay B-under-A lineage +
  census; dedup lineage; re-sync owner + A-clone overwrite;
  mixed-version epoch-0; defer-intent API + provenance wire;
  recovery XSK transaction; work-pull + linearization +
  pendingWorkerArm; lock rule + fairness; env
  loss/oscillation; fabric debt state machine; test greens;
  pass-1 cost; budget).

## Round 14 (plan v8.9 @ 6e2da70b98e1)

- **Claude SMR r14** — `claude-smr-plan-r14.md`. Verdict:
  DEMAND-REVISION (SMR14-1 BLOCKER — `note_config_epoch` needs
  compare-and-set semantics (= AGY f5); SMR14-2 BLOCKER — the
  latch echo must be ASYMMETRIC clear-only (credit AGY f2);
  + 4 MINOR/NIT — drain-time re-read pin, recovery clear
  predicate for operator slots (= AGY f3), suppression TTL
  (= AGY f4), three pins (= AGY f6/f7 + exit pairing)).
- **AGY r14** — background bash `bbw71e22g`; direct `agy
  --print-timeout 9m --print` (prompt assembled at 126,095
  bytes); output `/tmp/agy-6749-r14.out`; verdict doc
  `agy-plan-r14.md`. Verdict: DEMAND-REVISION (4 BLOCKER —
  f1 factory reset bricks via archiveSeq reseed vs surviving
  helper state (state.json at os.TempDir(),
  capabilities.go:21); f2 non-deferred compile defer
  corruption via the (v) echo (VERIFIED — asymmetric
  clear-only echo is the fix); f3 operator-disarmed slots →
  infinite recovery retry; f4 ack-set eviction strands
  suppression; + 2 MAJOR — f5 note monotonicity/CAS; f6
  debt-state RPC; + 1 MINOR — f7 Deadline semantics).
- **Codex r14** — background task `task-msdwofas-rgffdh`
  (prompt `/tmp/codex-6749-r14-prompt.txt`, --fresh); output
  `/tmp/codex-6749-r14.out`; verdict doc `codex-plan-r14.md`.
  Verdict: DEMAND-REVISION (12 BLOCKER + 3 MAJOR — archiveSeq
  is not a commit sequence (per-process retention counter;
  CommitConfirmed/SyncApply/PromoteRollback don't bump it;
  manual archive bumps it without a commit; crash-reseed
  reuse; no revision on config.Config or ActiveConfig);
  rollback refusal rejects legitimate auto-revert; same-config
  divergence needs a separate publication revision; auxiliary
  first-publishers lack acceptance handoff (#5134 arms staged
  B); note monotonicity backdoor + no failed-transfer owner;
  re-sync debt prohibited by its own firing rule + not
  latest-wins; StartDeferredCompile one-sided; claimToken
  fences bookkeeping not physical work; recovery can't prove
  quiescence (PrepareLinkCycle void, ignores failures);
  fairness proof source-false (120s owner holds); env
  eviction ownership + aggregate bound; fabric debt payload
  aliasing + readiness conduit doesn't exist; tests green;
  pass-1 estimate unsupported; budget unbounded).


## Round 15 (plan v8.10 @ pending)

- Codex, AGY, Claude SMR — pending dispatch.
## Round 15 (plan v8.10 @ 12ced136fe30)

- **Claude SMR r15** — `claude-smr-plan-r15.md`. Verdict:
  DEMAND-REVISION (2 BLOCKER — SMR15-1 StartCompile reservation
  clobbers itself in one apply (= AGY f1); SMR15-2
  publication_rev seed has no acquisition ordering (= AGY f4);
  + 3 MAJOR — 150s bound not the honest guarantee (= AGY f5);
  per-mutation re-read must be try-lock (= AGY f6); re-sync
  must fire on NONZERO helper-behind (= AGY f2, missed);
  restore-rebind on every quiesced attempt (= AGY f3, missed);
  + 3 MINOR — identity-keyed fabric debt (= AGY f7); note
  clear ≥ sent (= AGY f8); batch-arrival + fsatomic pins).
- **AGY r15** — background bash `bhsjhsjth`; direct `agy
  --print-timeout 9m --print` (prompt assembled at 123,397
  bytes); output `/tmp/agy-6749-r15.out`; verdict doc
  `agy-plan-r15.md`. Verdict: DEMAND-REVISION (4 BLOCKER —
  f1 StartCompile(false) clobbers precheck StartCompile(true);
  f2 re-sync ignores nonzero helper-behind; f3 post-quiescence
  failure leaves workers stopped; f4 unseeded publication_rev
  at startup; + 3 MAJOR — f5 150s bound vs multi-RPC
  pipelines; f6 blocking claimToken re-read under applySem;
  f7 FabricSyncDebtOutstanding misses telemetry-updated debts;
  + 1 MINOR — f8 note clear vs supersession).
- **Codex r15** — background task `task-msdyv5wo-1gs8c2`
  (prompt `/tmp/codex-6749-r15-prompt.txt`, --fresh); output
  `/tmp/codex-6749-r15.out`; verdict doc `codex-plan-r15.md`.
  Verdict: DEMAND-REVISION (12 BLOCKER + 2 MAJOR + 1 MINOR —
  f11 environment token the ONE clean closure. R1 durability
  (Option-B reuse) + rollout migration + atomic transport;
  publication high-water conflation + ping seed + legacy
  guard; R2 fence not freshness + legacy-zero contradiction +
  unverified rebase; note CAS self-contradiction + refusal
  plumbing; re-sync owner incomplete + precheck-bypassing
  execution; StartCompile self-clobber + ownerless Clear;
  claim fence has no validator + no nextWake; recovery
  abandonment leaves workers stopped + wrong-MAC rebind;
  fairness FIFO position loss; readiness hash incoherent;
  tests carry v8.9 identifiers; pass-1 unspecified).


## Round 16 (plan v8.11 @ c381b621a44f)

- **Claude SMR r16** — `claude-smr-plan-r16.md`. Verdict:
  DEMAND-REVISION (1 MAJOR — SMR16-1 the batch-arrival "REVALIDATES
  before enabling" rule is either a no-op or takes the whole dataplane
  down via the all-or-nothing enabled gate; the correct form is
  ABSORPTION at the re-Claim + immediate event-fired attempts with a
  read-only MAC-match routing check; + 5 MINOR/NIT — dedicated
  revision high-water counter (not archiveSeq), migration-write-failure
  posture, note-echo loop ordering, UNKNOWN vs PRE-PUBLISH
  classification, unwind failure routes to #5134, fairness pins,
  FabricSyncStateOK fresh-boot polarity).
- **AGY r16** — background bash (direct `agy --print-timeout 9m
  --print`, prompt assembled at 123,277 bytes); output
  `/tmp/agy-6749-r16.out`; verdict doc `agy-plan-r16.md`. Verdict:
  DEMAND-REVISION (4 BLOCKER — f1 Option-B (B,A) duplicate-revision
  aliasing; f2 DUAL refusal permanent deadlock when a restarted
  manager's active lags the helper's stored revision; f3 direct
  Compile invocations (HA sync, background recompiles, tests) canary-
  panic under the single-site StartCompile model; f4 mid-quiesce link
  return → wrong-MAC rebind for deferred recovery members; + 3 MAJOR —
  f5 pre-first-poll not-seeded-yet abort drops the boot apply with no
  re-trigger; f6 claimToken re-read contention spurious unwinds;
  f7 FabricSyncStateOK true immediately at startup before helper
  alignment; + 1 MINOR — f8 applySem FIFO starvation of urgent MAC
  recovery; + 1 NIT — f9 evidence requests).
- **Codex r16** — companion session 019fcaa9-fa07-7ce3-b114-47683c8fcf59
  (prompt `/tmp/codex-6749-r16-prompt.txt`, --fresh); output
  `/tmp/codex-6749-r16.out` (arrived after the prior session ended;
  verdict doc `codex-plan-r16.md` transcribed this session). Verdict:
  DEMAND-REVISION (14 BLOCKER + 2 MAJOR + 1 MINOR — disposition table
  false; Option B destroys config identity ((B,A) pair); migration no
  failure policy/allocator ordering; SetActiveRevision+ApplyConfig not
  atomic; ping seed too late for Compile stamping; socket ownership no
  rebase proof + downward-rebase rollback window; fresh-minted stale
  content escapes both fences; note has no typed refusal / note-first
  ordering; re-sync test permits the precheck bypass; reservation ABA
  + incomplete outcomes; claim validation not atomic with quiescence +
  no restore owner; batch MAC revalidation no safe rebind; fabric
  readiness not a coherence protocol + wrong identity; fairness model
  inconsistent; tests green; pass-1 fixture-scoped; severity-High
  residuals unbounded).

## Round 17 (plan v8.12 @ 08c78677f)

- **Claude SMR r17** — `claude-smr-plan-r17.md`. Verdict:
  DEMAND-REVISION (3 BLOCKER — SMR17-1 exposure gate has no mechanical
  locus and no re-exposure trigger (persistRetryLoop observer-free,
  source-verified); SMR17-2 freshness-token validation compares only
  the (config, revision) pair — same-commit stale content escapes;
  SMR17-3 live-MAC re-apply ActivePair() re-read admits an
  interposed-commit wrong-MAC publish; + 3 MAJOR — SMR17-4
  map_generation no seed/first-proof rule; SMR17-5 PENDING-XSK STAGED
  leaks compileInFlight forever; SMR17-6 §9 lacks half the claimed
  chain tests (disposition accuracy); + 5 MINOR — late-arrival
  exposure text, Warn episode keying, PrepareLinkCycleChecked hold
  span, ping deadline class, edit-hygiene splice artifacts).
- **AGY r17** — background bash `bi99ym7sf` (direct `agy
  --print-timeout 9m --print`, prompt assembled at 119,259 bytes);
  output `/tmp/agy-6749-r17.out`; verdict doc `agy-plan-r17.md`.
  Verdict: DEMAND-REVISION (4 BLOCKER — f1 exposure-gate re-exposure
  trigger; f2 snapshot_token post-build mint re-ordering; f3
  fresh-boot FabricSyncStateOK false forever; f4 live-MAC re-apply
  interposed commit; + 3 MAJOR — f5 PENDING-XSK compileInFlight leak;
  f6 ping-under-m.mu monopoly; f7 late-arrival exposure understates
  FIFO delay; + 1 MINOR — f8 RetryLater resets Warn; + 1 NIT — f9
  evidence wishes).
- **Codex r17** — background bash `bpji20ck2` (`codex exec -C
  <worktree> -s read-only`; prompt `/tmp/codex-6749-r17-prompt.txt`);
  output `/tmp/codex-6749-r17.out`; verdict doc `codex-plan-r17.md`.
  Verdict: DEMAND-REVISION (13 BLOCKER + 1 MAJOR + 1 MINOR —
  disposition false; exposure gate no state/owner (+ HA applied-marker
  depth: standby marked converged while running A); paired transport
  three competing authorities + stale SetActiveRevision reference +
  boot not under the hold; zero-event boot retry has no owner;
  freshness token no build linearization (+ locked/unlocked entry
  points, §6 omission, semantic-hash exclusion); error_code
  producer/consumer contract (+ not_seeded manager-local); predecessor
  chain still reproduces the ABA (non-head outcomes unrecorded) + API
  impossible as written; PrepareLinkCycleChecked split-API
  contradiction + RetryLater phase boundary; restore debt not
  executable (#5134 self-clears; respawn needs a paired full replay);
  late arrival has NO event source; FIFO proof false (stopLocked
  unbounded `<-done`); map_generation no atomic mutation identity or
  semantic coherence (+ fresh-boot trigger ANSWERED via
  startClusterComms); tests green; residuals unbounded; Warn lifecycle
  inconsistent). Convergence: Codex f2=AGY f1=SMR17-1; f5=AGY
  f2=SMR17-2; f3=AGY f4=SMR17-3; f12=AGY f3=SMR17-4; f7-tail=AGY
  f5=SMR17-5; f8=SMR17-9; f10=AGY f7=SMR17-7; f15=AGY f8=SMR17-8;
  f13=SMR17-6.

## Round 18 (plan v8.13 @ 92fb722e1)

- **Claude SMR r18** — `claude-smr-plan-r18.md`. Verdict:
  DEMAND-REVISION (2 BLOCKER — SMR18-1 auxiliary-producer gate-window
  A-config/B-FIB hybrid (SMR-only); SMR18-2 input-capture refs
  unimplementable → content-hash validation; + 3 MAJOR — SMR18-3
  replay order; SMR18-4 post-quiescence try-lock contradiction;
  SMR18-5 m.mu-resident netlink resolution; + 5 MINOR — exposure debt
  wake, error_code consumer contract + warning surface, 60s-floor
  bound, respawn replay composition, gate locus/peer visibility).
- **AGY r18** — background bash `b4wkeltmj`; output
  `/tmp/agy-6749-r18.out`; verdict doc `agy-plan-r18.md`. Verdict:
  DEMAND-REVISION (4 BLOCKER — f1 post-quiescence try-lock
  contradiction; f2 error_code Go survival contract; f3 m.mu-resident
  netlink resolution; f4 input-capture mutable refs; + 4 MAJOR — f5
  unspecified fold matrix; f6 missing commit-warning delivery; f7
  60s-floor blackhole; f8 polling cannot accelerate; + 1 NIT — f9
  requestDetailedLocked spec).
- **Codex r18** — background bash `bknj3ap8h`; output
  `/tmp/codex-6749-r18.out`; verdict doc `codex-plan-r18.md`.
  Verdict: DEMAND-REVISION (11 BLOCKER + 3 MAJOR — exposed marker
  inherits same-text; no typed outcome + wrapper tails leak; global
  gate suppresses durable A's second leg (pair-specific
  durableRevision); premature buildSeq invalidation + pre-send side
  effects; capture-order + token incarnation; note verb census; fold
  algebra (v8.13 head-first); read-to-syscall race + RetryLater
  starvation; restore debt not executable; map_generation false
  coherence (idempotent advance); late-arrival cutoff (CLOSED);
  tests green; hazard budget + false systemd bound). Convergence:
  f6=AGY f4=SMR18-2; f8=AGY f5=SMR18-3; f9=AGY f1=SMR18-4; f12=AGY
  f3=SMR18-5; f12-late=AGY f7=SMR18-8; f7=AGY f2/f9=SMR18-7;
  f15-Warn=CLOSED.

## Round 19 (plan v8.14 @ ef735f529)

- **Claude SMR r19** — `claude-smr-plan-r19.md`. Verdict:
  DEMAND-REVISION (2 MAJOR — SMR19-1 hash leg incoherent with the
  canonical fabrics replacement AND unnecessary (two legs suffice);
  SMR19-2 revision-keyed marker conflates node-local vs inter-node
  identity; + 5 MINOR — suppression-flag fail-stale + ordering, CLI
  pair-current exemption, deferred-tail set enumeration, lease
  latency + restore semaphore, durableRevision derivation).
- **AGY r19** — background bash `b4u6mmwvz`; output
  `/tmp/agy-6749-r19.out`; verdict doc `agy-plan-r19.md`. Verdict:
  DEMAND-REVISION (3 BLOCKER — f1 both-abandoned hash deadlock (=
  SMR19-1); f2 suppression flag stuck after superseding non-gated
  commit; f3 fold algebra NOT-VERIFIED on re-derivation (trace
  misreads the capture semantics); + 4 MAJOR — f4 MarkActiveApplied
  TOCTOU (VERIFIED: store.go:787-794 parameterless); f5 fabric
  replacement invalidates the hash (= SMR19-1); f6 lease latency
  (link cycles 50-500ms); f7 typed error via errors.As (adopted);
  + 1 NIT — requestDetailedLocked spec).
- **Codex r19** — background bash `b9uiq5t7f`; output
  `/tmp/codex-6749-r19.out`; verdict doc `codex-plan-r19.md`.
  Verdict: DEMAND-REVISION (11 BLOCKER + 4 MAJOR — gate/FRR
  contradiction (full gating subsumes the suppression flag);
  suppression fail-open (scheduler closes); HA settlement transport
  (ordered-loop item); deferred tails lose history + omit rollback +
  need phased ownership + warning aliases store state; marker
  pair-safety (all four call sites); hash contradicts invalidation
  both directions + ownerless pair-current (GO-LOCAL re-sync rule);
  no implementable build graph (named phase split); fold replays
  speculative priors (both-fail resurrection); lease cross-layer
  impossible + per-syscall insufficient (member-boundary model);
  restore intent + applySem; canonical pair uniform (P,g) +
  map-authoritative MACs; old-helper note narrative; tests green;
  hazard budget). f7 note verb CLOSED core; f12 late cutoff CLOSED;
  prior f15 CLOSED.

## Round 20 (plan v8.15 @ 132309631)

- Codex, AGY, Claude SMR — pending dispatch.