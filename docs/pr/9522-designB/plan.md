# #9522-DesignB — Chunked learned-route transfer with shadow staging, joint FIB+validation commit, LPM FIB (cap unreachable, #7480 strict throughout)

## 1. Status

DRAFT v2 (Design B) — pending adversarial plan review (round 2 of 3). Same branch, base
`7ef226474`. Supersedes Design B v1 (`4720981f`).

Round-1 record (raws: `docs/pr/9522-designB/reviews/` — to be saved with v2's dispatch):
Astra PLAN-KILL (scoped: Phase-1 publication protocol, Phase-2 live mutation, dependent Phase-3
retirement; Phase 0 direction sound) + GLM NEEDS-MAJOR (5 closable items). The reviews converge;
v2 accepts ALL of it:

- Publication ordering wrong (swap→publish→ACK→bump exposes new FIB under old validation) →
  pre-authorized commit identity + ONE joint store (§5-1.4 rewritten).
- Exactly-once asserted, not specified → commit receipt + idempotent committed-state +
  crash reconciliation via status echo (§5-1.5 rewritten).
- Config binding + digest identity open → bound transfer identity, pre-publish checks,
  clear-at-swap (neighbors precedent), transfer-internal hash distinct from `content_digest`
  (§5-1.3/1.4).
- Phase 2 exempts itself from atomicity → **Phase 2 KILLED** (both reviewers + v1 Q2);
  anti-entropy folded into Phase 1 (hash-skip periodic transfer + installed-identity echo).
- Apply/overlay path wipes the learned table (GLM R1-F1, the biggest hole) → helper-side
  learned retention with Rust-side gap-key suppression + next-hop re-resolution (§5-1.6
  rewritten).
- Sender serialization/livelock → single in-flight, dirty-flag queueing, pre-empt only on
  epoch change, convergence-under-churn bound (§5-1.7 rewritten).
- Phase-3 matrix vs version gate → over-refusal stated correctly + same-package coupling
  (§5-Phase-3 rewritten).
- LPM sharpening: structure chosen (binary trie), corpus additions, numeric gates (§5-Phase-0).
- Plus Astra 6/8: numeric resource/scheduling gates, transaction state table + failure
  injection, rollout contract.

## 2. Issue framing

Unchanged from v1: the #8355 count cap withholds the whole learned import above 64,956 routes;
the helper delegates every `NoRoute` frame unadjudicated. STEP-0 stands. Fail-closed-above-cap
rejected. Fix = move the table in budget-fitting pieces so the capped state is unreachable on
paired deployments, #7480 strict throughout, no oracle/attestation/doctrine-exception.

Acceptance (measurable): full-table box — learned miss ≡ uncapped miss (deny drops both,
permit delegates both with verdicts); uncapped-deny control untouched; NO window (transfer,
config-commit, overlay, restart) drops/delegates anything the pre-window table would not have
(availability parity pinned, including the new M2 no-wipe-on-config-commit cell); permit
throughput within the measured LPM envelope; `LearnedRouteCapHits()==0` on v17 pairings
(necessary, not sufficient — sufficiency is the installed-transfer-identity echo, §5-1.5).

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

Wire v17 (additive): `route_transfer: u64` (new `routeTransferGen`, seeded from status),
`route_chunks`, `route_chunk_index/total`, `route_replace` (first chunk),
`route_complete` (commit request carrying `route_learned_hash`: Go-stamped SHA-256 over the
canonical learned-set encoding — transfer-internal identity, NOT `content_digest`),
`route_commit_fib: u32` (PRE-AUTHORIZED fib generation — see commit order), bound
`route_config_gen: u64` + `route_config_hash` (config identity — see binding).

Handler + commit sequence (Astra blockers 1–3 closed by construction):

1. **Fence per transfer**: `transfer < last_seen` refuse; `==` idempotent chunk store;
   `>` abort prior staging (one live transfer, bounded staging: caps on chunks/routes/decoded
   bytes/aggregate memory, immutable envelope fields, index bounds — refused loudly).
2. **Config-bound ingest**: staging records `(transfer, config_gen, config_hash)`; EVERY chunk
   checked against the CURRENT config identity; mismatch ⇒ abort (stale transfer never
   commits against new config). Gap-fill coverage computed ONCE per Go build from the bound
   config and carried in-chunk (helper invents no coverage).
3. **Validate through `populate_routes` path per chunk into STAGING** (same fail-closed
   checks; `iface_ctx`: persist last-apply `iface_ctx` in `ServerState` — chosen, Q1 closed
   by decision: persisted, refreshed on every apply, transfer aborts if refreshed mid-flight).
4. **Commit (joint, pre-authorized)**: Go PRE-BUMPS the shim counter BEFORE sending
   `route_complete` (shim stays the sole authority; skipped values harmless under
   equality-match — unpublished pairs never stamp entries). The commit verb carries
   `route_commit_fib` (= pre-bumped value) + `route_learned_hash`. Helper verifies full chunk
   bitmap + staged-set hash == carried hash + config binding still current, then sets
   `self.forwarding` (swap) AND `self.validation.fib_generation` (= carried value) and
   publishes through the ONE existing choke point (`store_runtime_view` — NO new store site,
   canary count unchanged). Workers observe complete FIB + fresh pair together, atomically.
   ACK returns the commit receipt `(transfer, fib)`. A later `bump_fib_generation` with the
   EQUAL value is admitted by the `<`-fence as the confirm path (or Go skips it when the
   commit ACK landed — specified both, idempotent either way).
5. **Exactly-once as committed identity** (Astra 2): helper records
   `last_committed_transfer` + learned-set hash, echoed in `ProcessStatus`
   (`manager_route_transfer`, `manager_route_hash` — the neighbor-ACK precedent). Lost ACK ⇒
   Go retries the COMMIT verb only (never the transfer); helper answers committed-state
   idempotently (already-committed ⇒ receipt, no re-publish). Crash between shim pre-bump and
   commit ⇒ shim ahead, helper behind: next transfer pre-bumps further, commits forward —
   reconciliation rule: Go compares status echo vs intended id on every tick; mismatch ⇒
   re-transfer (never assume). Daemon/helper restart ⇒ RAM-only staging/partition lost ⇒ echo
   absent/stale ⇒ Go re-arms a full transfer (restart matrix, §9 cell).
6. **Digest**: CLEAR installed `content_digest` at swap (neighbors precedent, one line, zero
   CPU at 1M — GLM R1-F2). The transfer-internal hash is a different object and never touches
   the snapshot digest gate.
7. **Retention across applies** (GLM R1-F1 — the v1 hole, closed): `ForwardingState` gains a
   genuine learned partition the apply path does NOT rebuild: `apply_snapshot` rebuilds
   config tables from the incoming snapshot, then REPLAYS retained learned `RouteSnapshot`s
   through `populate_routes` with the NEW `iface_ctx` (re-resolution per #4446), filtered by a
   Rust-side gap-key suppression (`table|family|canonical-destination`, canonicalization
   parity-pinned against Go's `canonicalRoutePrefix` by shared corpus cells) so config-added
   coverage re-suppresses immediately at apply time (no permit-side transient). Overlay path:
   same replay (it rebuilds `next.Routes` config-only). Restart: helper restart empties the
   partition ⇒ Go re-arm trigger (echo check). Retention + suppression + re-resolution are
   M2-gated cells (config commit on full-table deny box: learned traffic uninterrupted;
   new-covering-config cell: suppressed synchronously at apply).
8. **Single carrier**: v17 Go excludes learned from `snapshot.Routes`; actuator/overlay/dedup
   all drive the transfer sender (full republish = new transfer; unchanged = hash-skip).
   Anti-entropy folded in (Phase 2 killed): periodic hash-skip full transfer at stated cadence
   (every Nth sweep / M minutes — Q3 narrowed: default M=30min, N/A, confirmed by churn data)
   + installed-identity echo (drift detector, not just skip).
9. **Socket discipline + serialization** (GLM R1-F3, Astra 7): ONE in-flight transfer
   (sender mutex/flag under `m.mu`); new demand sets DIRTY (never pre-empts); pre-empt ONLY on
   epoch/config change (which aborts + restarts); `m.mu` released between chunks; chunks
   ≤1–2 MiB measured pre-send; transfer converges inside 30 s actuate or the actuator starts a
   NEW transfer while the old table serves (progress rule: pre-emption requires NEWER
   epoch — churn marks alone cannot livelock; convergence-under-churn measured in M1 with a
   stated bound: at most K supersessions per actuation window, K=3 stipulated, then the
   actuator holds the newest dirty set for one full transfer — anti-livelock by construction).
   M1 measures lock/socket percentiles + status/HA max wait (Astra 6).

### Phase 2: KILLED (both reviewers + v1 Q2)

Deltas deferred to a future issue gated on measured diff-size distribution. Anti-entropy lives
in Phase 1 (item 8). No delta verb, no live-partition mutation, no batch-atomicity surface.

### Phase 3 (removal + rollout, reconciled with the version gate)

- New+new: transfers carry the table; cap never fires; gate never triggers (stays in code for
  legacy pairings).
- Old helper: refuses `update_routes` per-verb (unknown type, loud, sticky first-refusal) ⇒
  Go keeps the LEGACY cap path (cap + delegation + loud log + metric) — reachable and
  specified (NOT via the commit version gate, which governs `apply_snapshot`; per-verb refusal
  is the operative signal here — GLM R1-F5 reconciled: over-refusal at commit level is safe
  but unreachable in this pairing because Go never sends v17 snapshots to a v16 helper — Go
  learns the helper version from status BEFORE choosing the path).
- New helper + old Go: capped snapshots honored by the gate (byte-identical, no blackhole).
- Rollout: same-package spawn makes pairings atomic per node (citation §4); upgrade order
  (helper-first safe: honors gate; Go-first safe: verb refused → legacy path loudly);
  rollback either side ⇒ legacy behavior automatically; first-full-transfer readiness signaled
  by the installed-identity echo (cap-hits-zero is necessary-only); operator-visible
  refusal/recovery status required deliverables. v17 (current verified 16).

## 6. Public API preservation

Preserved: `noroute_policy_denial[_gated]` (gate legacy-only); all six `lookup_*` signatures;
`populate_routes` validation (reused); 64 MiB lockstep; `LearnedRouteCapHits()`; #9654;
#1913/single-recycle; flow-cache pair contract; `update_neighbors`; the ONE `ha.runtime.store(`
site (reused, canary unchanged). Added: v17 verb + fields + (`manager_route_transfer/hash`)
echo + Go sender/sequencer + `partialRoutes` section + digest-clear + retention/suppression +
pre-bump commit order.

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

- M0 (LPM): lookup ns + NoRoute pps 65k→1M pre/post; build p95 ≤ 2× vec; memory ≤ 2× vec;
  parity corpus green (tiebreaks, stability incl. cross-chunk reassembly order, discard/
  next-table no-ancestor-fallback, connected composition, ECMP slice+bitmask, canonicalization,
  #6568 fail-closed). No-go kills Phase 0+.
- M1 (transfer): per-chunk service percentiles (size rule from data); convergence vs 30 s;
  socket-hold vs 1 s poll; status/HA max wait; swap-clone + rotation cost at 1M; staging peak
  (coordinator + worker views + retained + staging + clone + scratch, budget stated in PR);
  unchanged-skip under churn; convergence-under-churn with K=3 supersession bound; neighbor-push
  clone delta.
- M2 (acceptance, ≥cap synthetic): determinist equivalence (deny drops both / permit delegates
  both); uncapped-deny control; no-wipe-on-config-commit; new-covering-config suppression
  synchrony; restart re-arm (both processes); fail-on-revert (no staging / no fence /
  partial-commit / legacy gate refire / retention drop).
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
features; chunked-delta stacking (refused); compat window for v17 (over-refusal chosen,
rollout-safe per same-package coupling).

## 11. Open questions for adversarial review

1. **Pre-bump ordering:** Go pre-bumps the shim before the commit verb; helper applies the
   carried value jointly. Does shim-ahead-of-helper break any consumer of `readFIBGeneration`
   (BPF programs? session stamps `protocol/binding.rs:1213`?) during the pre-bump→commit gap?
   Enumerate or kill.
2. **Retention vs re-transfer:** apply-time replay keeps old learned routes across config
   commits — but a withdrawn-in-kernel route then lingers until the next transfer. Is the
   staleness bound (≤ next transfer/anti-entropy cadence) acceptable, or must every config
   apply force a synchronous learned re-issue (cost: commit latency)? Name the bound.
3. **Rust gap-key parity:** canonicalization parity with Go's `canonicalRoutePrefix` pinned by
   shared corpus — is cross-language canonical parity reviewable, or should suppression stay
   Go-side (apply carries a suppression list)? Which is less mechanism?
4. **iface_ctx persistence:** persist-last-apply vs re-derive at verb time — stale-interface
   hazard either way; transfer-abort-on-refresh chosen. Is the abort rate under link churn
   acceptable, or does it recreate the livelock R1-F3 closed?
5. **Anti-entropy cadence:** M=30min/hash-skip default — too slow to catch helper-side drift
   that matters (drift can't happen without a publish path touching tables — enumerate them or
   lengthen M)?
6. **#946-Phase-2 pattern, final call:** explicit-state cold-path fenced machinery at
   neighbor-scale precedent vs million-route transaction unsuitability — kill whole, phased,
   or proceed?
7. **v17 rollout:** is same-package coupling + loud refusal + echo-readiness sufficient for a
   fleet with pinned old helpers, or is a compat window (verb-ignored + cap retained)
   REQUIRED — knowing it reintroduces the hole temporarily by design?
