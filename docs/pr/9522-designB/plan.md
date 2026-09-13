# #9522-DesignB — Chunked + delta learned-route transport with shadow-staged atomic publish and LPM FIB (cap unreachable, #7480 strict throughout)

## 1. Status

DRAFT v1 (Design B) — pending adversarial plan review. Same branch
`fix/9522-learned-route-cap`, base `origin/master 7ef226474`. New dir `docs/pr/9522-designB/`;
Design A artifacts frozen under `docs/pr/9522/` with the kill recorded in
`docs/pr/9522/KILLED-DesignA.md` (parent ruling: 4 rounds, 4 scoped Astra KILLs; remainder
needed ungrantable weakened guarantees + doctrine exceptions).

Round-1 (Design A v1, chunked-verb attempt) record — this plan is written against it, point by
point: Astra PLAN-KILL required "stage an immutable replacement off the live forwarding view,
validate completeness and content identity, bind it to the config context, then publish the
finished FIB and fresh validation pair together; abort leaves the previous complete view
intact", plus single-carrier, Go-owned fib bump, digest-at-divergence, transaction protocol,
version negotiation, and GLM F2 (linear scan at 1M routes unshippable — LPM in scope or lower
the target). Every item below names its round-1 finding ID. Raw round-1 reviews:
`docs/pr/9522/reviews/round1-*.md`.

## 2. Issue framing

Same issue, primary direction: above the #8355 derived cap (64,956 routes) the daemon
withholds the ENTIRE learned import and the helper delegates every `NoRoute` frame
unadjudicated (`noroute_policy_denial_gated` early-`None` → `xpf-usp0` reinject). STEP-0 stands
on base. Fail-closed-above-cap stays rejected (#9054). The fix removes the cap's *cause* — one
publish cannot carry a full table within `learnedRoutePublishBudget` (~56 s socket hold vs a
socket shared with the 1/s status poll, HA sync, session installs) — by moving the table in
budget-fitting pieces through a new route verb modeled on `update_neighbors`, so the capped
state becomes unreachable and #7480 strict adjudication applies uniformly. No kernel oracle,
no attestation, no version-doctrine exception, no weakened invariant: every new mechanism is
helper-local FIB content + control transport, both already-precedented shapes.

Acceptance (issue's, restated measurably): on a full-table box, a learned-destination miss and
an uncapped miss produce the SAME policy result (deny box drops both; permit box delegates
both with explicit verdicts); the uncapped-deny positive control
(`noroute_is_denied_on_a_default_deny_box_7480`) keeps passing untouched; no transfer window
drops or delegates anything the pre-transfer table would not have (availability parity pinned);
permit throughput within the measured scan/LPM envelope (§9).

## 3. Honest scope / value framing

Large change, binary security payoff. Cost, stated up front: a new control verb + transfer
protocol (generation envelope, chunk bitmap, retry debt), a shadow-staged FIB publish path,
and an LPM migration of the route maps (the current per-table `Vec` + linear `find` cannot
hold 10⁶ routes — GLM F2, accepted as prerequisite rather than follow-up). Benefit: the
`LearnedRouteImportCapped` state becomes unreachable for size reasons on paired (new,new)
deployments; #7480 adjudication becomes uniform; the #9054 gate stays only as the legacy-path
fallback and never fires on a current pairing.

*If reviewers conclude the LPM migration alone exceeds the value (e.g. capped boxes are few
and static, and a smaller operational fix suffices), or that the transfer protocol replays the
#946-Phase-2 over-mechanization pattern, PLAN-KILL is an acceptable verdict — including
KILL of individual phases (§5f). Phases are ordered so a kill lands on scope, not on the
whole direction.*

## 4. What's already shipped / partially batched

- #7480 adjudication + cells; #8355 derived cap + `LearnedRouteCapHits()`; #9054
  `LearnedRouteImportCapped` wire bit (protocol **v16** at `protocol/control.rs:131` — v4's
  "v11" was stale; Design B targets **v17**, verified current), gated delegation, overlay
  recompute, pre-v-old-helper refusal; #7409 gap-fill (`learnedRouteGapKey`,
  config-wins-always, order-independent emission); #7437 coalesced republish (1 s/3 s/30 s);
  #9654 absence-is-unknown; #7480/#9054 cells pinned.
- `update_neighbors` full envelope: replace/clear (#5864), generation fence + ACK (#6034),
  digest clear (#9520), epoch/outcome tracking (#9684, `partialNeighbors`), writeback guards
  (#6986, #1197/#5306), sender retry-debt (`RegenerateNeighborSnapshot`,
  `manager_neighbor.go:81+`), unknown-verb loud refusal (`handlers/mod.rs:360-363`).
- Publish path: full rebuild per apply (`ForwardingState::default()` → `populate_routes` →
  `sort_routes`, `forwarding_build/mod.rs:555-594`); single-choke-point publish
  (`publish_runtime_view` clones + rotates the worker `Arc`, `coordinator/mod.rs:1590-1598`);
  neighbor pushes already pay one clone per push; bulk-replace atomicity for neighbors
  (#949: readers see pre- or post-, never half).
- Route-only overlay (`PublishRouteOverlaySnapshot`, `manager_overlay.go:102+`): clone
  lastSnapshot, rebuild routes, bump generation, hash-dedup skip, hybrid-ACK refusal (#5680),
  must-call-`BumpFIBGeneration`-after ordering (AGY r2-1), dirty-retry (#3757), cap recompute
  per build (#9054 comment at :201-207).
- Validation: #3771 fail-closed build checks (preference range, family match, unparseable
  destination), #2390 sort (longest-first, lowest-preference, stable insertion), #2388
  connected table scoping, #4446 per-table next-hop inference (needs `iface_ctx` at build),
  #6568 no-silent-skips, flow-cache pair-equality invalidation (#3767/#5169), generation
  monotonicity + content-identity gates (#3767 H5, #9520: sha256 `ContentDigest`,
  `builder.go`/`apply_snapshot_identity_9520.go`), FIB generation Go-owned via shim map
  (`manager_generation.go:10-23`; helper `<`-fence), #1844 retry contract.
- Per-route wire cost ~113 B, 64 MiB lockstep caps, `controlRoundtripDeadline` as timeout
  allowance (never service-time evidence).

## 5. Concrete design

### Phase 0 (prerequisite, shippable alone): LPM route maps with parity proof

Replace `FastMap<String, Vec<RouteEntryV4/V6>>` lookup with a longest-prefix structure **without
changing what it stores or decides**: each table maps to a binary/ART trie whose nodes hold
the same-prefix entry list in today's exact order (preference-ascending, insertion-stable).
`lookup_*_inner` walks most-specific → least instead of `iter().find`; everything downstream
(connected interplay #2388, discard/next-table, ECMP whole-slice selection, NoRoute construction)
is untouched. Readers (30 refs, all funneling through the ~6 `lookup_*` fns in
`forwarding/fib.rs`) keep their signatures — the map type changes, the call sites do not.

- Parity gate (before cutover): dual-serve in test builds (trie + vec, mismatch counter, corpus
  of same-prefix tiebreaks, insertion-stability, discard/next-table, ECMP identity, connected
  interplay, canonicalization) + `forwarding_build` equivalence cells; production cutover only
  when the corpus is green. Build cost gated #923-style (trie build p95 budget at 1M scale).
- Perf gates (§9 M0): miss-path ns + NoRoute pps at 65k/250k/500k/1M pre/post; commit-time
  build latency; memory (trie overhead vs vecs at 1M).
- If LPM fails its gates, Phase 1+2 STOP (GLM F2 honored structurally, not rhetorically).

### Phase 1 (core fix): `update_routes` chunked transfer, shadow-staged, atomically published

Wire (additive, v17): `route_transfer: u64` (new monotone `routeTransferGen`, seeded from
status like `neighborReplaceGen`), `route_chunks: Vec<RouteSnapshot>` (budget-sized),
`route_chunk_index/total: u32`, `route_replace: bool` (first chunk of a transfer),
`route_complete: bool` (last chunk; commit iff full bitmap received), plus a later Phase-2
`route_add/route_withdraw` delta shape (§5-Phase-2) carried by the same verb with
`route_delta_seq: u64`.

Handler (`server/handlers/routes.rs`, dispatched as `"update_routes"`):

1. **Fence at transfer granularity** (round-1 finding 7): `transfer < last_seen` ⇒ refuse;
   `transfer == last_seen` ⇒ idempotent chunk store by `(transfer, index)` (duplicate/replay
   safe); `transfer > last_seen` ⇒ ABORT prior staging (bounded staging lifetime: one live
   transfer; supersede is the only abort verb — no separate cancel message to lose).
2. **Validate each chunk through the SAME per-route path `populate_routes` uses**
   (#3771/#6568 fail-closed, family match, canonical table, next-hop resolution) into a
   STAGING table set — never the live FIB (round-1 blockers 1–3 closed by construction: no
   clear-at-chunk-0, no mixed-table window, no per-chunk invalidation question).
   `iface_ctx` availability at verb time is the first implementation decision (persist the
   last-apply `iface_ctx` in `ServerState` vs re-derive; nailed pre-code, Q1).
3. **Commit only on complete + full bitmap + content identity** (round-1 finding 8): premature
   `complete`, missing indices, total mismatch, or validation failure ⇒ refuse/retain-old-table
   (abort leaves the previous COMPLETE view intact — the required reset, verbatim). Empty
   learned set is a valid complete table (distinct from absent, #5864-analogous).
4. **Atomic publish**: swap staging into `self.forwarding` + ONE `publish_runtime_view`
   (round-1 finding 4: no per-chunk clone/rotation; worker visibility exactly once per
   transfer) + fold the staged set into the stored snapshot's routes + recompute/refresh
   `content_digest` over the FULL new content at swap (round-1 finding 6/8: digest never vouches
   for unswapped content; enforced content never diverges from the installed digest).
   `refresh_status` on every arm; `persist_state` on swap.
5. **Go-owned invalidation** (round-1 finding 5): commit-ACK ⇒ Go bumps shim ⇒ existing
   `bump_fib_generation` — the helper NEVER self-advances fib. Exactly one invalidation per
   completed transfer (never per chunk, never zero).
6. **Single carrier** (round-1 finding 3): v17-aware Go EXCLUDES learned routes from
   `snapshot.Routes` (they ride the verb); the #7437 actuator, overlay publish, hash-dedup
   skip, and `apply_snapshot` interplay are rewired to the transfer sender (full republish =
   new transfer; unchanged table = skip by content hash as today). `buildRouteSnapshots`
   gains the split (config+overlay routes vs learned set) with gap-fill computed ONCE per
   build and carried into chunks (round-1 finding 5: coverage from the build's config context;
   mid-transfer config change aborts the transfer via generation/epoch check — Q2).
7. **Socket discipline** (round-1 finding 6): chunks sized ≤1–2 MiB serialized (measured per
   chunk pre-send; shrink-and-retry); stop-and-wait with in-band ACK (generation,index) in
   `ProcessStatus` (new `manager_route_generation/index` pair mirroring #6034); `m.mu`
   released between chunks (no multi-chunk hold — explicit scheduling change from the overlay
   path, not a yield comment); transfer must converge inside the 30 s actuate budget or the
   actuator retry starts a NEW transfer (old staging superseded, old table still serving).
   Service times MEASURED (§9 M1), never derived from the deadline formula.

### Phase 2 (churn efficiency; merges separately): delta mode on the same verb

Kernel route events already arrive coalesced (#7437). Small diffs ride as deltas instead of
full transfers: Go diffs (old,new) learned sets → `route_add: [...]` (full `RouteSnapshot`s,
same validation) + `route_withdraw: [...]` (destination keys: table|family|canonical-dest —
the `learnedRouteGapKey` identity; config routes are NEVER withdrawn by this verb, gap-fill
precedence structurally preserved). Deltas apply DIRECTLY to the live learned partition
(each delta is self-consistent — add/withdraw named prefixes, no clear-and-refill, so the
atomicity objection does not attach), then the same single-publish + digest-refresh + Go-owned
bump as Phase 1. Diff-exceeds-budget ⇒ full transfer instead (no chunked-delta mode — two
mechanisms, never stacked). Anti-entropy: periodic full-transfer re-sync at a stated cadence
(default: every Nth actuator sweep or M minutes, Q3) bounds async-divergence accumulation.

### Phase 3 (removal, same PR series): cap retirement

- New-helper + new-Go: chunks carry the whole table ⇒ `learnedRouteCapExceeded` never fires;
  `LearnedRouteImportCapped` stays decoded + status-visible but unfireable (telemetry preserved
  for #9172-adjacent consumers; the gate remains in code for legacy pairings only).
- Old helper (refuses `update_routes` loudly per unknown-verb arm): Go keeps the OLD cap path
  with the OLD delegation semantics + loud log (no silent fallback — first-refusal sticky).
- New helper + old Go (withholds above cap, stamps capped): gate HONORED (no blackhole —
  the v10 lesson, applied without exception).
- Protocol v17 (current verified 16, `control.rs:131`): new verb + `route_*` fields +
  `manager_route_*` ACK + learned-exclusion-from-snapshot rule. Mixed pairings refuse loudly
  per the existing version gate — no doctrine exception requested (the v9 lesson, applied).

## 6. Public API preservation

Preserved verbatim: `noroute_policy_denial[_gated]` semantics (gate fires only on legacy
pairings; current pairings never set the condition); `apply_snapshot`, `bump_fib_generation`,
`update_neighbors`; all six `lookup_*` signatures (LPM is behind them); `populate_routes`
per-route validation (reused by chunk/delta ingest); 64 MiB lockstep; `LearnedRouteCapHits()`;
#9654 absence; #1913 chokepoint + single-recycle; flow-cache pair contract. Added: v17 verb +
fields + ACK pair + Go sender/sequencer + `partialRoutes` section type + digest restamp path.
`update_neighbors` pattern copied, not modified.

## 7. Hidden invariants the change must preserve

1. Single-recycle/slow-path ownership (#6432/#1327): the NoRoute arm is UNTOUCHED — disposition
   plumbing changes nowhere; only table *content* completeness changes.
2. ONE kernel-reach authority (#6664/#1913): untouched.
3. Flow-cache pair-equality: exactly one Go-owned bump per completed transfer/delta-batch;
   staging never visible under the published pair (round-1 blocker 2 structural fix).
4. Monotonicity/content-identity (#3767/#9520): transfer fence + digest restamp at swap only;
   staged content never attested; full-snapshot publishers rebase/abort staged transfers via
   epoch check (#9684 extended, not bypassed).
5. Allocation: hot path zero-alloc preserved AND improved (LPM walk allocates nothing; fewer
   prefix-contains scans); chunk decode/staging is cold control work; per-chunk and per-swap
   clone budgets stated (§9 M0/M1).
6. Gap-fill: computed once per Go build, carried into chunks/deltas; helper never invents
   coverage; config routes unwritable by the route verb (key-space separation, not discipline).
7. Socket sharing (corrected per round-1): per-chunk holds bounded by size + measured service
   time; `m.mu` released between chunks; `sync_session`'s dedicated socket unaffected; status
   poll/HА/bumps unaffected by design (measured in M1).
8. Deterministic emission: canonical order end-to-end (split the SORTED set; reassembled ≡
   sorted); unchanged tables skip by hash (no FIB flap).
9. Serde skew: all v17 fields defaulted/omitempty; unknown-verb refusal is the old-helper
   signal (loud, sticky); v17 gate refuses mixed pairings loudly.
10. HA/sync portability: no new per-session wire; route content + envelope only; rolling
    upgrade matrix in §5-Phase-3.
11. LPM semantic identity: longest-first, lowest-preference, insertion-stable, connected
    scoping, discard/next-table, ECMP slice identity — pinned by the Phase-0 corpus, not by
    prose.
12. #9521/#3292/#4024/#3110 arms: untouched (content-only change).

## 8. Risk assessment

| Class | Rating | Reason |
|---|---|---|
| Behavioral regression | HIGH | Touches the FIB build/publish core + the #7480-adjacent completeness premise; wrong swap/fence/invalidation = blackhole or bypass. Same class as the #9054 composition mistake — hence phased, gated, parity-proven. |
| Lifetime / borrow-checker | MED | Staging table + swap changes `Coordinator` borrow shape; LPM replaces map types behind 30 refs (signatures kept). Trie node ownership/lifetimes are the new surface. |
| Performance regression | HIGH until M0/M1 pass | LPM build + lookup at 1M, per-transfer clone at 1M, chunk-stream socket occupancy — all measured pre-commit-gates, none reasoned. The plan's core bet (LPM recovers the scan) is itself gated. |
| Architectural mismatch | MED | Stateful transfer protocol + FIB-structure migration is exactly the machinery class killed at plan time before (#946-Phase-2). Counter: the issue NAMES this direction; round-1's reset prescribed this shape; phases let each half die separately. Q6 invites the kill. |

## 9. Test plan

- M0 (LPM gates, BEFORE cutover): miss-path ns + NoRoute pps at 65k/250k/500k/1M pre/post;
  build latency p95 at 1M (bench, #923-style); memory at 1M; parity corpus green. No-go kills
  Phase 0 (and everything behind it).
- M1 (transfer gates): per-chunk service times (sizes the ≤1–2 MiB rule with data);
  transfer convergence vs 30 s actuate; socket-hold per chunk vs 1 s status poll;
  swap-clone cost at 1M; unchanged-table skip verified (no republish storm under BGP churn).
- M2 (acceptance, full-table synthetic ≥ cap): capped-history miss ≡ uncapped miss (deny
  drops both; permit delegates both with verdicts); uncapped-deny control green (untouched);
  availability parity across transfer (old table serves until swap — drop/delta counters flat
  except churn itself); fail-on-revert cells (delete staging ⇒ RED; delete fence ⇒ RED;
  partial-table commit attempt ⇒ RED; gate-refire on legacy path ⇒ RED).
- Suites: `cargo build` per commit; full `cargo test --release`; 5/5 flake on affected cells;
  `go test` affected pkgs (chunking math, envelope, digest restamp, writeback, #9684-routes).
- Guards updated in place: #9054 composition cells (gate now legacy-only + never-fires-on-v17
  cell), #7480 cells untouched, `slow_path_admit_single_site_6664.rs` untouched (arm unchanged
  — stated as evidence of blast-radius containment).
- Smoke (REQUIRED — FIB content changes): deploy; v4+v6 × push+reverse; `-P 12 -R`;
  full-table run (deny learned-only dst DROPS, permit FORWARDS); counters +
  `LearnedRouteCapHits()` (= 0 on v17 pairing) captured; per-class CoS 5201-5206. All figures
  captured.

## 10. Out of scope (explicitly)

Design A revival (killed, see record); fail-closed-above-cap (#9054, rejected); raising
`learnedRoutePublishBudget`/`MaxControlRequestBytes` (moves the accident, #7675 stays);
FRR-side filtering (operator remedy); #9172 observability (beyond the counters this plan needs);
general FIB feature work (leak rules, next-table depth); chunked-delta stacking (refused by
design — diff-overflow uses full transfer).

## 11. Open questions for adversarial review

1. **LPM-before-transfer or transfer-before-LPM?** The plan orders LPM first (F2 blocks growth).
   Is that right, or should chunked transfer land first behind a retained count ceiling with
   LPM following — i.e. is the phase order itself the risk (big-bang FIB swap before any
   transport value ships)? KILL-or-reorder invited.
2. **Is delta mode (Phase 2) worth it?** With 3 s-throttled full transfers, does BGP-churn
   traffic justify a second mechanism, or should Phase 2 die and churn pay full transfers?
   Diff-size distribution evidence invited; KILL-Phase-2 acceptable.
3. **Staging memory at 1M routes:** two full FIBs during staging (tens of MB) + one clone at
   swap. Acceptable on the helper's footprint, or must staging be delta-applied then
   checksummed (reintroducing live-mutation review)? Numbers invited.
4. **Transfer envelope shape:** transfer-generation + chunk bitmap + stop-and-wait ACK vs a
   lighter cumulative-ACK/windowed stream. Is stop-and-wait's N×RTT convergence (tens of
   seconds at 1M routes) an availability problem in itself (stale table serves long), and does
   that force deltas to be Phase 1, not Phase 2?
5. **Digest over staged content:** Go restamps over config + FULL route set; helper verifies
   content identity at commit against what? Full rehash per commit (CPU at 1M) vs incremental
   hash vs trust-with-bitmap-completeness? Each has a failure mode — pick or kill.
6. **#946-Phase-2 pattern match:** stateful generation-fenced ACKed transfer + FIB-structure
   migration + publish choreography — is this the over-mechanization shape this tree kills at
   plan time, with `update_neighbors` as a false friend (10² entries, single message) for a
   10⁶-entry consistency problem? KILL (whole or phased) is the expected answer if so.
7. **v17 refusal blast radius:** mixed pairings refuse loudly — at fleet rollout that means
   old helpers shed load/reject until upgraded. Is the rollout story (upgrade order, refusal
   observability, rollback) specified tightly enough, or does v17 need a compat window (verb
   ignored + cap retained) that reintroduces the hole temporarily? Draw the line.
