# #9522-DesignB — Chunked learned-route transfer with joint commit, retention, LPM FIB (cap unreachable, #7480 strict throughout)

## 1. Status

DRAFT v3 (Design B) — pending adversarial plan review (round 3 of 3, final). Same branch, base
`7ef226474`. Supersedes v2 (`3e1da97`).

Round-2 record (raws: `docs/pr/9522-designB/reviews/round2-*.md`): Astra PLAN-KILL (scoped
Phase 1 + dependent Phase 3; Phase 0 viable, Phase 2 deferral clean) + GLM NEEDS-MINOR (2
required: R2-1 pre-bump serialization + NAK re-pair; R2-2 version-identity fork). Convergent
and closable; v3 closes all of it:

- Generation exclusivity: ONE sequencer (`fibGenMu`) across mint+send for ALL publishers;
  strict freshness (carried > current; equal ⇒ receipt-only duplicate); boot nonce epochs;
  status-pair update in the commit critical section; NAK re-pair rule; Q1 consumer audit
  answered (snapshot stampers benign, BPF self-healing, RMW race fixed by the sequencer).
- Retention completeness: coverage-REMOVAL path (Go detects newly-uncovered keys → immediate
  re-transfer, fail-closed interim, M2 cell) alongside ADDITION suppression at apply; three
  rebuild paths enumerated (reconcile apply, armed same-plan, disarmed twin); ban scoping
  recorded (transfer gap-fill Go vs apply exact-key suppression); config identity stored as
  `route_config_binding`, separate from `content_digest`.
- Recovery as an in-plan state machine (§5-1.5 table): staging/commit/abort states, duplicate
  commit (same id, different content) refused, staging expiry, restart identity, supersede
  races, lost-ACK-then-unavailable-status disambiguation.
- Version fork resolved per GLM R2-2(a): NO snapshot version bump (stays v16); route-transfer
  protocol version advertised via omitempty status field (positive detection); per-verb
  refusal handles old helpers; matrix rewritten truthfully; sticky latch demoted to backstop.
- Numeric gates completed: behavioral M0 thresholds (NoRoute pps at 1M ≥ 65k-master, build ≤
  2×, memory ≤ 2×); per-chunk hold p99 ≤ 500 ms; staging ≤ 1× steady FIB; route-vs-config
  churn progress rules; K=3 scoped to Go-side restarts + config-abort leg in M1.
Round-1 → v2 record (kept for archaeology): v2 closed publication ordering (pre-authorized
joint commit), committed identity, config binding, Phase-2 kill, retention, sender
serialization, matrix reconciliation, LPM sharpening, numeric gates. Round-2 put the same
shape under the microscope and found the joints: v3 is joints, not reshaping.

## 2. Issue framing

Unchanged from v1: the #8355 count cap withholds the whole learned import above 64,956 routes;
the helper delegates every `NoRoute` frame unadjudicated. STEP-0 stands. Fail-closed-above-cap
rejected. Fix = move the table in budget-fitting pieces so the capped state is unreachable on
paired deployments, #7480 strict throughout, no oracle/attestation/doctrine-exception.

Acceptance (measurable): full-table box — learned miss ≡ uncapped miss (deny drops both,
permit delegates both with verdicts); uncapped-deny control untouched; NO window (transfer,
config-commit, overlay, restart) drops/delegates anything the pre-window table would not have
(availability parity pinned, M2 no-wipe + removal-path cells); coverage REMOVALS converge by
re-transfer with a fail-closed interim (drops-more, bounded by transfer convergence — stated,
not smuggled); permit throughput within the measured LPM envelope;
`LearnedRouteCapHits()==0` on route-transfer pairings (necessary, not sufficient — sufficiency
is the installed-transfer-identity echo, §5-1.5).

## 3. Honest scope / value framing

Unchanged costs (new verb + transfer protocol + LPM migration), minus Phase 2 (killed).
*Reviewers may still kill whole or phased (Q6 stands). Phases 0/1 are independently shippable;
Phase 3 is removal + rollout.*

## 4. What's already shipped / partially batched

V1 §4 stands in full, plus round-1-verified mechanics v2 is built on (all re-read at head):

- Pair publication: `publish_runtime_view` clones forwarding + CURRENT validation and rotates
  the worker `Arc` (`coordinator/mod.rs:1590-1598`); `republish_runtime_validation` reuses the
  published `Arc` for validation-only changes (no worker rotation, #1188 preserved,
  `:1600-1619`); there is exactly ONE `ha.runtime.store(` site (canary-pinned) reached via
  `store_runtime_view`; `bump_fib_generation` sets `self.validation` then republishes
  (`:1690-1701`) with a `<`-fence (equal admitted — the confirm path, §5-1.5).
- `choose_v4_route` composition: connected wins iff
  `conn.prefix_len() >= route.prefix_len()`, else static, else connected-or-none
  (`forwarding/fib.rs:863-881`, v6 twin) — the LPM corpus pins the composition, not just trie
  behavior.
- Neighbor sender full pattern (`manager_neighbor.go:81+`): diff → replace+gen → ACK check →
  retry debt → writeback → epoch resolve; resolver bounds (4096 queue, 1 s/3 s);
  `manager_neighbor_generation` ACK precedent for status echo.
- Digest gate (`snapshot.rs:135-161`), clear-on-mutation (`neighbors.rs:54-59`), empty digest
  vouches nothing; Go digest = SHA-256 over its own JSON struct (`builder.go:187-205`) —
  hence unrestampable helper-side (GLM R1-F2).
- Same-package spawn bounds mixed pairings (GLM R1-F5 citation:
  `process_identity_restart_8899_test.go:30`, `/usr/sbin/xpf-userspace-dp`).

## 5. Concrete design

### Phase 0 (prerequisite, shippable alone): binary-trie LPM maps with parity corpus + numeric gates

Structure CHOSEN (Astra-9): per-table binary prefix trie (not ART — build/insertion complexity
unjustified; prefix splits are exact for IP LPM), nodes holding same-prefix entry lists in
today's exact order. `lookup_*_inner` walks most-specific→least; `choose_v4/v6_route`
composition byte-identical; all six `lookup_*` signatures kept; build/sort write side
(`forwarding_build/fib.rs:82,168`) constructs tries (sort-then-insert preserves stability).

Corpus (parity, all fail-on-revert): longer-wins-despite-better-shorter-preference;
same-prefix preference-ASC; equal-preference insertion stability ACROSS chunk reassembly order;
selected-discard/next-table never falls back to an ancestor; connected tiebreak
(`conn >= route`); table-scoped connected (#2388); discard/next-table/cycle arms; ECMP
whole-slice identity + member order + hash-to-member stability; canonicalization parity;
unparseable-destination fail-closed (#6568) preserved at ingest (tries never see bad routes).

Gates M0 (numeric, pre-cutover): lookup ns + NoRoute pps at 65k/250k/500k/1M pre/post; build
p95 at 1M (budget: ≤ 2× today's vec build — stipulated, confirmed by measurement); memory at
1M (budget: ≤ 2× vecs); warmer-sweep + log/test readers migrated or explicitly exempted.
No-go kills Phase 0 and everything behind it.

### Phase 1 (core fix): `update_routes` transfer with joint commit

Wire (NO snapshot version change — stays v16; route-transfer protocol versioned separately,
GLM R2-2(a)): `route_transfer_nonce: u64` (Manager boot nonce; fence resets on nonce change —
restart identity) + `route_transfer_seq: u64` (monotone per nonce), `route_chunks`,
`route_chunk_index/total`, `route_replace`, `route_complete` (carrying `route_learned_hash`:
Go-stamped SHA-256 over the canonical learned-set encoding — transfer-internal identity, NOT
`content_digest`), `route_commit_fib: u32` (PRE-AUTHORIZED fib generation minted under the
sequencer), bound `route_config_gen: u64` + `route_config_hash` (stored as
`route_config_binding`). Helper advertises `route_transfer_protocol: u32` (omitempty) in
`ProcessStatus`; Go sends the verb ONLY on positive detection (unknown-type refusal arm is
the backstop latch, not the mechanism).

Handler + commit sequence (round-2 closures built in):

1. **Fence per (nonce, seq)**: unknown nonce ⇒ adopt as new epoch (fence reset — restart
   identity); same nonce: `seq < last_seen` refuse, `==` idempotent chunk store (conflicting
   duplicate chunk contents refused loudly), `>` abort prior staging. One live transfer;
   staging caps (chunks/routes/decoded bytes/aggregate memory, immutable envelope, index
   bounds, 90 s wall-clock expiry — all refused loudly, never repaired in place).
2. **Config-bound ingest**: staging records `(nonce, seq, config_gen, config_hash)`; EVERY
   chunk checked against CURRENT config identity; mismatch ⇒ abort. Gap-fill computed ONCE
   per Go build from the bound config and carried in-chunk (helper invents no coverage —
   transfer-time gap-fill stays Go-computed per `routes.go:789-792`; ban scoping recorded:
   the round-1 helper-coverage ban is about transfer-time kernel-table policy, while
   apply-time suppression below is exact-key equality over Go-authored content — GLM R2-4).
3. **Validate through `populate_routes` path per chunk into STAGING** (same fail-closed
   checks; `iface_ctx`: persist last-apply `iface_ctx` in `ServerState`, refreshed on every
   apply, transfer aborts if refreshed mid-flight).
4. **Commit (joint, sequenced, receipted)**: ALL fib-generation minting Go-side goes through
   ONE sequencer (`fibGenMu`) held across {mint shim value + send the verb} for bumps AND
   transfer commits (R2-1: pre-`m.mu` RMW race fixed by construction; serial socket orders
   verbs as minted). Commit verb carries `route_commit_fib` (= freshly minted, hence >
   every previously minted value). Helper rule: `route_commit_fib` > current validation fib
   REQUIRED (strict freshness; equal-value CANNOT precede committed identity); full bitmap +
   staged hash == carried hash + config binding current. Then ONE critical section, in order:
   swap forwarding, set `self.validation.fib_generation`, set
   `guard.status.last_fib_generation` (GLM R2-5 — the pair never disagrees),
   `store_runtime_view` (existing site only), record `last_committed (nonce, seq, fib,
   learned_hash)`, CLEAR `content_digest`, `persist_state`. ACK returns the receipt.
   Duplicate commit (same nonce+seq, equal fib) ⇒ receipt ONLY, no re-publish. Same id with
   DIFFERENT hash/fib ⇒ refuse loudly (corrupt sender, fail-closed). Crash between pre-bump
   and commit ⇒ shim ahead: NAK re-pair rule — Go sends `bump_fib_generation` with the
   CURRENT map value (equality admitted) to re-pair, never waiting for the next window.
   Gap consumers audited: snapshot stampers benign (monotone-≥ gates), BPF stamps self-heal
   by re-lookup (one extra lookup, never blackhole).
5. **Recovery machine** (states/events/guards/mutations/responses — Astra 3, in-plan):
   STAGING → COMMITTING → COMMITTED, ABORTED as sink (stale fence, config mismatch,
   validation failure [staging DISCARDED], envelope violation, 90 s expiry). Events: chunk /
   complete / duplicate-complete / invalid-commit / ACK-lost (commit-only retry ≤3, receipt
   dedups) / status-unavailable-after-ACK-loss (commit-retry FIRST, THEN re-transfer —
   ordered disambiguation) / supersede (newer nonce or same-nonce higher seq ⇒ abort +
   fence-advance) / config-change (abort staging; COMMITTED table keeps serving — abort never
   unpublishes) / helper-restart-during-retry (echo check → re-transfer). Completion proven
   ONLY by status echo (`manager_route_transfer` nonce+seq AND `manager_route_hash`) matching
   intent, OR a commit receipt for the same triple. `route_config_binding = (config_gen,
   config_hash)` retained separately, set at commit AND every apply, checked at ingest +
   pre-publish; `content_digest` participates NOWHERE (binding ≠ digest).
6. **Digest**: CLEAR installed `content_digest` at swap (neighbors precedent, zero CPU at 1M).
   Transfer-internal hash never touches the snapshot digest gate.
7. **Retention across applies, both coverage directions** (GLM R1-F1 + Astra 2 closed):
   genuine learned partition, rebuilt by NO apply path. All THREE rebuild sites replay it:
   reconcile apply, armed same-plan refresh, disarmed twin (GLM R2-3) — replay = retained
   `RouteSnapshot`s through `populate_routes` with the NEW `iface_ctx` (re-resolution #4446),
   filtered by Rust gap-key suppression (exact-key equality over Go-authored content,
   canonicalization corpus vs Go's `canonicalRoutePrefix`). ADDITIONS covered synchronously at
   apply (no permit-side transient). REMOVALS: Go detects newly-uncovered keys at build
   (compares covered set vs previous) ⇒ marks routes-dirty ⇒ immediate re-transfer; interim
   keeps old suppression (fail-closed: drops-more, bounded by transfer convergence — stated,
   M2-pinned). Helper restart empties the partition ⇒ echo-based Go re-arm. M2 cells:
   no-wipe-on-config-commit (all three paths), new-covering suppression synchrony,
   removal-path convergence bound.
8. **Single carrier + echo-primary anti-entropy**: route-transfer-capable Go excludes learned
   from `snapshot.Routes`; actuator/overlay/dedup drive the transfer sender (full republish =
   new transfer; unchanged = hash-skip). PRIMARY drift detector is the echo-compare on every
   status tick (GLM R2-8); M=30min hash-skip full transfer is the backstop bound, not the
   detection bound (Q5 dissolves).
9. **Socket discipline + serialization, churn-separated** (GLM R1-F3, Astra 5/7): ONE
   in-flight transfer; ROUTE churn (kernel marks) sets DIRTY (never pre-empts); pre-empt ONLY
   on epoch/config change; `m.mu` released between chunks; chunks ≤1–2 MiB measured pre-send.
   K=3 supersession bound scoped to Go-side restarts ONLY; helper-side config aborts are
   unbounded-by-construction AND correct-by-binding (GLM R2-6) — convergence bound stated
   honestly: one quiet window (no config change) ≥ one transfer duration, plus the measured
   argument that route churn does not move config identity. M1 adds the config-abort leg +
   lock/socket percentiles + status/HA max wait + staging peak (budget ≤ 1× steady FIB) +
   per-chunk hold p99 ≤ 500 ms ceilings (Astra 5 — no "stated in PR" deferrals).

### Phase 2: KILLED (both reviewers + v1 Q2)

Deltas deferred to a future issue gated on measured diff-size distribution. Anti-entropy lives
in Phase 1 (item 8). No delta verb, no live-partition mutation, no batch-atomicity surface.
### Phase 3 (removal + rollout — version fork resolved per GLM R2-2(a), no snapshot bump)

- Snapshot protocol stays v16. Route-transfer capability advertised by the helper via omitempty
  `route_transfer_protocol: u32` in `ProcessStatus` (positive detection — the mixed-version
  precedent pattern); Go sends `update_routes` ONLY on positive detection. Old helpers are
  detected by ABSENCE (no refusal storm); the unknown-type refusal arm is the backstop latch,
  stated as Go-side behavior (GLM R2-7).
- Pairings (all reachable, none refused at commit level — the gate still guards commits
  version-exactly as today): new+new ⇒ transfers, cap never fires, gate never triggers (stays
  in code for legacy pairings); old helper + new Go ⇒ legacy cap path LOUDLY (cap +
  delegation + log + metric, byte-identical to today); new helper + old Go ⇒ v16 snapshots
  accepted, gate honored byte-identically (NO blackhole — the row GLM R2-2 proved false under
  a bump reading is TRUE under no-bump). Rollback either side ⇒ legacy behavior automatically
  (helper restart loses RAM-only staging/partition ⇒ echo-based re-arm).
- Same-package spawn bounds long-lived mixed pairings (citation §4); first-full-transfer
  readiness = installed-identity echo (cap-hits-zero necessary-only); operator-visible
  refusal/recovery status required deliverables. No compat window (GLM Q7: would reintroduce
  the hole by design).

## 6. Public API preservation

Preserved: `noroute_policy_denial[_gated]` (gate legacy-only); all six `lookup_*` signatures;
`populate_routes` validation (reused); 64 MiB lockstep; `LearnedRouteCapHits()`; #9654;
#1913/single-recycle; flow-cache pair contract; `update_neighbors`; the ONE `ha.runtime.store(`
site (reused, canary unchanged). Added: `update_routes` verb (`route_transfer_protocol`
capability, NO snapshot bump — stays v16) + fields + (`manager_route_transfer/hash`) echo +
Go sender/sequencer (`fibGenMu`) + `partialRoutes` section + digest-clear +
retention/suppression + sequenced joint commit.

## 7. Hidden invariants the change must preserve

V1's twelve stand, amended: (3) invalidation exactly-once-per-commit via pre-authorized joint
publish (never per chunk, never zero, never publish-then-bump); (4) transfer bound to
(config_gen, config_hash) at ingest + pre-publish, digest CLEARED at swap (never restamped),
transfer hash internal-only; (6) gap-fill Go-computed per build AND Rust-suppressed at apply
(parity corpus); new: (13) **retention safety** — apply/overlay NEVER drops the learned
partition silently (replay + suppress + re-resolve, M2-pinned); (14) **commit atomicity** —
one store site, both halves, no return/?/panic between assignment and publish (the #6592
property extended); (15) **sender serializability** — one in-flight, dirty-not-preempt,
epoch-preempt-only, bounded supersession.

## 8. Risk assessment

| Class | Rating | Reason |
|---|---|---|
| Behavioral regression | HIGH | FIB core + publish ordering + retention interplay; the #9054-class mistake now has three named sites (commit order, retention suppression, fence) each M2-pinned. |
| Lifetime / borrow-checker | MED | Staging + partition + trie node ownership; signatures kept; one store site reused. |
| Performance regression | HIGH until M0/M1 | LPM build/lookup/memory at 1M; swap-clone at 1M; chunk-stream occupancy; worker-rotation cost; neighbor-push clone impact (LPM changes shared clone cost — measured). |
| Architectural mismatch | MED | Explicit-state cold-path machinery (GLM: not the #946 pattern); transfer + migration + choreography is still heavy — Q6 invites phased or whole kill. |

## 9. Test plan

- M0 (LPM, behavioral thresholds — Astra 5): NoRoute pps at 1M ≥ NoRoute pps at 65k on master
  (no scale regression vs today's cap-scale behavior); build p95 ≤ 2× vec; memory ≤ 2× vec;
  parity corpus green (tiebreaks, stability incl. cross-chunk reassembly order, discard/
  next-table no-ancestor-fallback, connected composition both families + shorter/equal/longer,
  ECMP slice+bitmask+hash-member stability, canonicalization, #6568 fail-closed). No-go kills
  Phase 0+.
- M1 (transfer, ceilings — no deferrals): per-chunk service percentiles with the ≤1–2 MiB rule
  confirmed by data; per-chunk hold p99 ≤ 500 ms; convergence vs 30 s actuate; status/HA max
  wait (stated numerically in PR); swap-clone + rotation cost at 1M; staging peak ≤ 1× steady
  FIB; unchanged-skip under churn; convergence-under-churn (route churn: dirty-queue bound;
  config-abort leg: one quiet window ≥ one transfer; K=3 Go-side restarts only);
  neighbor-push clone delta.
- M2 (acceptance, ≥cap synthetic): determinist equivalence (deny drops both / permit delegates
  both); uncapped-deny control; no-wipe-on-config-commit across ALL THREE rebuild paths
  (reconcile apply, armed same-plan, disarmed twin); new-covering-config suppression synchrony;
  removal-path convergence bound (fail-closed interim); restart re-arm (both processes);
  fail-on-revert (no staging / no fence / partial-commit / legacy gate refire / retention drop).
- Recovery state table (Astra 8): every terminal/replay path (lost commit ACK, double ACK,
  shim-ahead crash, supersede races, validation-fail disposition, empty transfer encoding,
  index/envelope bounds, staging lifetime/memory caps) with failure-injection cells.
- Suites: build-per-commit; full cargo + 5/5 flake; go affected pkgs (chunk math, envelope,
  writeback, partialRoutes, digest-clear, sender serialization).
- Smoke (REQUIRED): v4+v6 × push+reverse; `-P 12 -R`; full-table run with counters +
  installed-identity echo + cap-hits==0; per-class CoS. Captured, never asserted.

## 10. Out of scope (explicitly)

Design A (killed); Phase 2 deltas (killed — future issue); fail-closed-above-cap;
budget/ceiling changes; FRR filtering; #9172 (beyond needed counters); leak/next-table
features; chunked-delta stacking (refused); snapshot-version compat window (not needed — no
bump; positive status detection + per-verb refusal instead).

## 11. Open questions for adversarial review

1. **Sequencer coverage:** does `fibGenMu` (or m.mu-reordered equivalent) cover ALL shim
   minters — ipmon `pendingFIBBump`, CompileConfig tail, transfer pre-bump — with mint+send
   atomicity in each? A missed minter reopens the RMW race. Enumerate all three call sites or
   kill.
2. **Retention staleness bound:** "≤ next transfer" recorded (GLM Q2). A synchronous re-issue
   on every apply would couple commit latency to a 1M rebuild. Is the bound acceptable given
   the removal path is fail-closed and the addition path synchronous?
3. **Rust suppression vs Go-carried list:** kept Rust-side (GLM R2-4: Go-side unbuildable
   post-restart, 1M-string payload). Is cross-language canonical parity reviewable enough, or
   does the corpus need byte-vector fixtures generated from Go?
4. **iface_ctx abort rate under link churn:** abort ⇒ re-arm, bounded storms. Keep the M1
   measurement, or does link-flap realistically livelock transfers (abort on EVERY refresh)?
   Consider generation-scoped (abort only if interfaces affecting learned next-hops changed).
5. **Anti-entropy cadence:** echo-compare per tick is the detector (GLM R2-8); M=30min backstop
   bound. Too slow for code-bug drift that echo itself can't see (echo compares hashes the
   same code computed)? What independent check closes that loop, if any is needed?
6. **#946-Phase-2 pattern, final call (GLM Q6: proceed; Astra: re-entry bar):** proceed,
   phased kill, or whole kill?
7. **Rollout without snapshot bump:** same-package coupling + positive status detection +
   per-verb refusal + echo-readiness — sufficient for pinned-old-helper fleets, or must the
   plan specify a forced-upgrade path? (No compat window either way — GLM Q7.)
