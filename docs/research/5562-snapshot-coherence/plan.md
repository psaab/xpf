# Plan of Action — #5562: snapshot refresh publishes validation and forwarding through two independent ArcSwaps (persistent policy fail-open)

- **Revision:** r2 (folds Claude SMR r1 findings F1–F6; AGY pending; Codex infra-blocked)
- **Issue:** #5562 (bug, security — High)
- **Research branch:** `research/5562-snapshot-coherence`
- **Base:** origin/master `4e0c7f74c` (issue verified vs `0ab8a90a8`; mechanism unchanged at base)
- **Mode:** `/research` — stops at PLAN-READY or PLAN-KILL. No PR, no production source touched.

---

## 1. Status

`PLAN-REVIEW r2` — Claude SMR r1 = **PLAN-NEEDS-MINOR** (findings F1–F6 folded into this
revision). Codex = **INFRA-BLOCKED** (CLI 1.0.6 / ChatGPT account offers only `gpt-5.6-sol`
which needs a newer CLI; all other models rejected — 5 retries; proceeding 2-of-3 per the
codex-infra-blocked exception). AGY = pending. Recommendation: ship **Path D (split-source
stamp: `config_generation` embedded in `ForwardingState`, `fib_generation` stays in
`ValidationState`)**. Paths A/B/C documented with tradeoffs (§5). PLAN-KILL is an acceptable
outcome if reviewers judge the churn unjustified — see §3.

---

## 2. Issue framing (what breaks, verified against the tree)

`Coordinator` publishes two pieces of worker-visible runtime state through **two
independent `ArcSwap`s**:

- `shared_validation: Arc<ArcSwap<ValidationState>>` (coordinator/mod.rs) — carries
  `{ snapshot_installed: bool, config_generation: u64, fib_generation: u32 }`
  (`types/runtime.rs`).
- `ha.forwarding: Arc<ArcSwap<ForwardingState>>` (coordinator/ha_state.rs) — carries the
  actual policy / NAT / filter / route / CoS tables that produce a permit/deny decision.
  **`ForwardingState` carries NO generation field** (verified: no `config_generation` /
  `fib_generation` member).

### 2.1 The two stores are ordered validation-first in BOTH apply paths

- **Same-plan refresh** — `coordinator/snapshot_refresh.rs`:
  - L303 `self.shared_validation.store(Arc::new(self.validation));`  ← store A (validation)
  - L304 `self.ha.forwarding.store(Arc::new(self.forwarding.clone()));`  ← store B (forwarding)
- **Full reconcile** — `coordinator/reconcile/snapshot.rs`:
  - L476 `coord.shared_validation.store(Arc::new(coord.validation));`  ← store A
  - L480 `…forwarding.store(Arc::new(coord.forwarding.clone()));`  ← store B
- **Fib-only bump** — `coordinator/mod.rs` `bump_fib_generation` (L907–914): stores
  **only** `shared_validation` (validation.fib_generation = new); it does **NOT** rebuild
  or re-store `forwarding`. This is a deliberate optimization — route churn must not deep-
  clone the entire `ForwardingState`. **This fact is load-bearing for the design (§3).**

Between store A and store B the coordinator computes `Arc::new(self.forwarding.clone())`
— a deep clone of the whole `ForwardingState`. For a large config that clone is order
microseconds-to-tens-of-µs; that is the publication window.

### 2.2 The worker read path loads validation-first, forwarding-second

- Initial worker bring-up — `worker/loop_body/setup.rs`:
  - L111 `let validation = **shared_validation.load();`
  - L112 `let forwarding = shared_forwarding.load_full();`
- Per-iteration refresh — `worker/loop_body/mod.rs`:
  - L364 `let live_validation = shared_validation.load();` → L366 `validation = **live_validation;`
  - L372 `if let Some(new_forwarding) = load_arc_if_changed(&forwarding, &shared_forwarding)` → L454 `forwarding = new_forwarding;`

Both are ordinary `Acquire` loads of two **independent** atomics. There is no fence,
seqlock, or common commit tag that couples them. `load_arc_if_changed` only short-circuits
the clone via `Arc::ptr_eq`; it does not compare a generation.

### 2.3 The decision is evaluated against `forwarding`; the stamp is captured from `validation`

- RX processing calls `poll_binding(... validation, ... &forwarding, ...)`
  (`worker/loop_body/mod.rs` L790 = the `validation` local, L794 = the `forwarding`
  local). The permit/deny + resolution **decision** is computed against `forwarding`
  (the policy tables). `ValidationState` holds no policy — only counters.
- The flow-cache seed is stamped from **validation**:
  `flow_cache.rs` L535–537 `FlowCacheStamp::capture(validation.config_generation,
  validation.fib_generation, …)`.
- The flow-cache lookup keys off **validation** too: `FlowCacheLookup::for_packet(meta,
  validation)` → L172–173 `config_generation: validation.config_generation`,
  `fib_generation: validation.fib_generation`.
- Invalidation contract — `flow_cache.rs` L873–874:
  `if entry.stamp.config_generation != lookup.config_generation
   || entry.stamp.fib_generation != lookup.fib_generation { evict; return MISS }`.

So the stamp records **the generation of the validation the worker held**, while the
decision it stamps was made against **the forwarding the worker held** — two independently-
loaded siblings. When they disagree, the stamp is a lie about which policy generation
actually produced the cached decision.

### 2.4 The race window — persistent fail-open (forward schedule)

1. Coordinator does store A: `shared_validation = gen N`.
2. A worker executes L364 and loads `validation = N`. Store B has **not** landed yet
   (coordinator is mid deep-clone), so at L372 the worker loads `forwarding = gen N-1`
   (old policy tables).
3. During RX, a packet matches an **old permit** under `forwarding N-1` and the worker
   inserts a flow-cache seed **stamped `config_generation = N`** (from `validation`).
4. Coordinator does store B: `shared_forwarding = gen N` (new policy says **DENY**).
5. From here every lookup uses `validation = N`, so
   `stamp.config_generation (N) == lookup.config_generation (N)` → the invalidation gate
   at L873 does **not** fire → the stale permit **hits**.

The stale permit survives past the transient publication window. It persists until the
cached flow ages out **or** the next `config_generation` bump (a later, unrelated config
apply). The generation-invalidation mechanism — the exact thing that is supposed to cut
already-cached flows when policy changes — is defeated for the raced 5-tuple. This is a
**persistent firewall fail-open on the packet path**: an operator adds a DENY, and a
raced-in cached flow keeps being permitted.

Status honestly reports only generation N (the coordinator's own `self.validation`), so
the incoherence is invisible to `show`/metrics.

### 2.5 The inverse schedule — transient, self-healing

Worker loads OLD `validation` (before store A), then both stores land, worker loads NEW
`forwarding`: decision made under NEW forwarding, stamped OLD generation. Once the worker's
`validation` catches up to N, that entry's `stamp.config_generation (N-1) !=
lookup.config_generation (N)` → it is evicted and re-evaluated. **Transient** — it self-
heals on the next validation load; it can briefly deny/re-evaluate a flow that new policy
would permit, but it does not leave a persistent fail-open. The forward schedule (§2.4) is
the load-bearing severity.

### 2.6 Why it is real, and not already mitigated

- **#5169 (CLOSED)** added a generation-**monotonicity** gate at the control plane
  (`server/handlers/snapshot.rs` L86–89: reject `generation < cur`, or `== cur` with
  `fib_generation <`). That rejects a *rolled-back / reused* generation *before* apply. It
  does **not** make the two stores of a legitimate forward-progress apply atomic — #5562's
  window is inside a single monotone apply. Orthogonal.
- **#5171 (CLOSED)** moved the mandatory-map + forwarding integrity build ahead of ack in
  the defer path. Orthogonal to the store-atomicity gap.
- **`rg_epochs`** (`flow_cache.rs` L882–894) is an HA **RG-ownership** epoch gate, not a
  config-generation fence. Orthogonal.
- No seqlock / commit-tag couples validation↔forwarding (grep: none).

Confirmed **real** on origin/master `4e0c7f74c`.

### 2.7 Enumeration of ALL readers (any fix that reorders/couples the pair touches these)

- **`shared_validation` (`ArcSwap<ValidationState>`)** — the **only runtime readers are
  the workers**: `worker/loop_body/mod.rs` L364 (per-tick) and `worker/loop_body/setup.rs`
  L111 (bring-up). Writers: snapshot_refresh L303, reconcile/snapshot L476,
  bump_fib_generation L912; bringup passes a clone to each spawned worker. Status/metrics
  read `fib_generation` via a coordinator accessor on `self.validation` (the coordinator's
  own copy — **not** the ArcSwap); `config_generation` has **no** accessor. HA session-sync
  does **not** read `shared_validation`.
- **`ha.forwarding` (`ArcSwap<ForwardingState>`)** — readers: workers
  (`loop_body/mod.rs` L372 + `setup.rs` L112) **and** the GRE local-origin tunnel aux
  thread (`afxdp/tunnel.rs`, its own `load_full` + `load_arc_if_changed` loop). The tunnel
  thread reads **only** forwarding, never validation, and never stamps the flow cache
  (`FlowCacheStamp::capture` has exactly one production call site, flow_cache.rs L535).
  `refresh_fabric_links` stores directly to it (L60/L66); `tunnel_supervision.rs` /
  `reconcile/bringup.rs` clone the `Arc<ArcSwap>` into aux threads.

Blast-radius takeaway: **only workers read `shared_validation`**; forwarding has one extra
reader (the tunnel thread) that ignores validation. Any option that bundles the two forces
the tunnel thread and bring-up to carry validation they do not use.

---

## 3. Honest value framing

The window is small (a single deep-clone of `ForwardingState`, order µs) and only opens on
a config apply or reconcile (rare, operator-driven). But the consequence when it is hit is
a **persistent** policy fail-open for the raced flow that outlives the window and is
invisible to status — precisely the class of defect the flow-cache generation gate exists
to prevent. A firewall's core contract is that a committed DENY takes effect; a stale
permit that a new DENY fails to invalidate is a genuine security regression, not a cosmetic
one. So there is real value in closing it.

Against that: the code paths are load-bearing and heavily annotated (#3766, #1873, #2440,
#5169, #5171). Any change that reorders or restructures the publish/read touches the hottest
loop in the dataplane and every reader in §2.7. The design must therefore be the **minimum**
that makes the stamp coherent — not a speculative bundle-everything rewrite.

**If reviewers conclude a mechanism is unsafe or the churn unjustified, PLAN-KILL is
acceptable.**

---

## 4. Already-shipped related work

- #5169 — apply_snapshot generation-monotonicity guard (rejects rolled-back/reused
  generations). CLOSED. Complements but does not fix #5562. **Load-bearing predecessor of
  Path D** (SMR F3): the flow-cache invalidation is an *equality* compare, so it only
  guarantees eviction if `config_generation` never rolls back to a value a live entry still
  carries; #5169's monotonicity is the precondition that makes equality safe.
- #5171 — defer_workers integrity build before ack. CLOSED.
- #5166 — forwarding published before CoS owner/lease maps (forwarding↔CoS pair). **OPEN.**
  Same *family* (non-atomic multi-store publish), different store pair; a bundle-style fix
  (Path A) could in principle share a mechanism with #5166, but the two pairs are distinct
  and #5166 is out of scope here (§10).
- #3048 — neighbor MAC epoch eviction (`neighbor_mac_epoch`) — an independent staleness
  axis on the same cache entry; a useful precedent for "stamp the entry with the epoch of
  the state it was resolved against, compare live on hit."

---

## 5. Concrete design — Multiple Path Options

All four options share one root-cause statement: **the flow-cache entry is stamped with a
generation sourced from a different atomic than the state its decision was evaluated
against.** They differ in how they restore coherence.

### Path A — single atomic rotation (issue's suggested "WorkerRuntimeSnapshot" bundle)

Combine `(ValidationState, ForwardingState, …)` into one `CoherentSnapshot` published
through **one** `ArcSwap<Arc<CoherentSnapshot>>`. A worker loads BOTH atomically in one
`.load()` → one coherent boundary; the stamp and the decision come from the same bundle.

- **Closes the fail-open fully?** Yes — one load, one generation, no torn pair.
- **Per-packet hot-path cost?** None extra on the hit path; one `.load()` instead of two
  per tick.
- **Blast radius:** **Large.** Every reader in §2.7 migrates: bring-up, the GRE tunnel aux
  thread (now must hold validation it never uses), status. **Critical hidden cost:**
  `bump_fib_generation` currently bumps a `u32` with a single validation store and **no**
  forwarding clone. If `fib_generation` lives in the bundle *with* forwarding, every route
  churn event must deep-clone the entire `ForwardingState` to publish a new bundle — a real
  throughput regression on route-heavy boxes. Avoiding that means keeping fib_generation
  *outside* the bundle, which re-introduces a second atomic and partially defeats the point.
- **Testability:** Moderate — a bundle-identity change is easy to assert; the fib-bump-
  without-forwarding-rebuild interaction is the hard case to test.

### Path B — generation-gate at stamp time

Embed `config_generation` in `ForwardingState`, then at insert only stamp/cache a permit if
the worker's loaded `forwarding.config_generation == validation.config_generation`; else
skip the cache (cold-path re-evaluate next packet) or force a reload.

- **Closes the fail-open fully?** Partially / fragile. It prevents caching *during* a torn
  window, but it has its own TOCTOU (the two values can still be read at different program
  points) and it does nothing for the inverse schedule. It leans on the gate firing rather
  than on the stamp being correct.
- **Per-packet hot-path cost?** A compare on every cacheable insert (cheap) + transient
  cache-bypass during the window (a burst of cold-path evaluations at apply time).
- **Blast radius:** Small-ish, but it *also* requires embedding a generation in forwarding —
  the same prerequisite as Path D — while delivering a weaker guarantee. **Strictly
  dominated by Path D:** once forwarding carries the generation, using it as the stamp
  source (D) is both simpler and complete; using it merely as a gate (B) is more complex and
  incomplete.

### Path C — seqlock / epoch fence around the paired publish

Wrap the two stores in a writer seqcount; readers retry if they observe an odd/ torn
sequence between loading validation and forwarding.

- **Closes the fail-open fully?** Yes if implemented correctly.
- **Per-packet hot-path cost?** A seqcount read + retry branch on **every worker tick**
  (the read happens per iteration, not just at apply). Adds two atomic loads + a compare to
  the hottest loop for a condition that is true a few µs per config apply. Poor cost/benefit.
- **Blast radius:** Every reader must adopt the retry protocol, including the tunnel aux
  thread. Seqlock-with-Arc is subtle (a reader can capture two Arc clones across a torn
  window and the retry must discard both). Higher bug risk than A or D.
- **Testability:** Hard — racing the writer seqcount deterministically is the exact kind of
  timing test that flakes.

### Path D — split-source stamp (RECOMMENDED)

Root cause restated precisely: `config_generation` bumps **only** on a config apply, and a
config apply **always rebuilds `ForwardingState`** — so `config_generation` and the
forwarding tables are *already produced together*; keying the cache stamp off `validation`
instead of `forwarding` is the only reason they can tear. `fib_generation`, by contrast,
bumps **without** rebuilding forwarding (`bump_fib_generation`), so it must stay sourced
from the single atomic that carries it.

Therefore:

1. Add `config_generation: u64` to `ForwardingState`, populated at build time in
   `build_forwarding_state_*` from `snapshot.generation` (the same value the coordinator
   writes into `validation.config_generation`). Zero cost — it rides the existing forwarding
   rotation; no new store, no extra clone (`bump_fib_generation` never touches forwarding,
   so route churn is unaffected).
2. Change the flow-cache **stamp** to read `config_generation` from **forwarding** and
   `fib_generation` from **validation**:
   `FlowCacheStamp::capture(forwarding.config_generation, validation.fib_generation, …)`.
3. Change the flow-cache **lookup** identically: `config_generation` from the worker's
   current `forwarding` local, `fib_generation` from `validation`.

Why it closes the fail-open completely and atomically:

- The decision, the stamp's `config_generation`, and the lookup's `config_generation` now
  **all read the same worker-local `forwarding` Arc** (a single `.load()` result). They can
  never disagree — coherence is by construction, no fence, no retry.
- Forward schedule (§2.4): the raced permit is decided under forwarding N-1 and now stamped
  `config_generation = N-1` (from that same forwarding). After forwarding rotates to N, the
  lookup reads `forwarding.config_generation = N`, so `stamp N-1 != lookup N` → **evicted →
  re-evaluated under new policy → DENY**. Fail-open closed.
- Inverse schedule (§2.5): decided under forwarding N, stamped N, invalidated correctly when
  forwarding rotates again. Coherent.
- `fib_generation` remains sourced from `validation` (a single atomic, read once per tick) —
  no tearing is possible for a value that lives in exactly one ArcSwap. Route-churn
  invalidation is unchanged.

Both-axes coherence proof (SMR F2) — a full apply bumps BOTH `config_generation` (→
forwarding, store B) AND `fib_generation` (→ validation, store A); Path D must be coherent
on every interleaving, not just the config axis:

- **Forward torn read** (validation NEW `fib=F_N`, forwarding OLD `config=C_{N-1}`): decision
  under `C_{N-1}`; stamp `= (C_{N-1}, F_N)`. After forwarding→`C_N`, lookup `= (C_N, F_N)`.
  `C_{N-1} != C_N` → **evict**. Closed by the config axis.
- **Inverse torn read** (validation OLD `fib=F_{N-1}`, forwarding NEW `config=C_N`): decision
  under `C_N`; stamp `= (C_N, F_{N-1})`. After validation→`F_N`, lookup `= (C_N, F_N)`.
  `F_{N-1} != F_N` → **evict** (transient, re-evaluated under live policy).
- **fib-only bump** (forwarding unchanged, `F→F+1` via validation): one atomic; stamp and
  lookup both read the single `validation.fib_generation`; advance → evict.

Each axis is sourced from exactly one atomic, and the stamp/lookup read the *same* worker-
local of that atomic — so neither axis can tear against itself. Coherence is structural.

Why NOT just reorder the two stores (SMR F4): reordering to forwarding-first (stores AND
reads) does not create atomicity. A worker can still load forwarding=OLD, then both stores
land, then load validation=NEW → NEW-validation + OLD-forwarding persists. Reordering only
shuffles which schedule is the persistent one; it never removes the torn pair. A real
coherence mechanism (D) is required.

Symmetry (SMR F6): the generation-mismatch eviction is direction-agnostic. If deny decisions
are also cacheable, the inverse of the reported bug is a persistent fail-*closed* (a raced
new PERMIT stays denied); Path D closes both directions with the same compare.

- **Blast radius:** **Smallest.** No ArcSwap restructuring. The tunnel aux thread, bring-up,
  status, and HA sync are untouched (forwarding merely gains a `u64` field they ignore;
  validation is unchanged). The insert site (`flow_cache.rs` ~L430–542) ALREADY receives both
  `forwarding` (used at L437/L466/L472) and `validation` (L536) as parameters, so the stamp
  change is a one-token source swap (`forwarding.config_generation` for
  `validation.config_generation`); the only real signature churn is
  `FlowCacheLookup::for_packet` (L169), and `forwarding` is already in scope at its call site
  (`poll_descriptor/flow_cache_hit.rs`, under `poll_binding`). Change is confined to:
  `ForwardingState` struct + its builders (`forwarding_build/`), `FlowCacheStamp::capture` /
  `FlowCacheLookup::for_packet` signatures and their call sites in `flow_cache.rs` /
  `poll_descriptor/` / `worker/loop_body/`, and the flow-cache tests.
- **Per-packet hot-path cost:** None — same number of atomic loads; the stamp/lookup read a
  struct field instead of a sibling struct field.
- **Testability:** High — a pure unit test drives the exact schedule: build forwarding N-1
  (config_generation N-1), stamp an entry, rotate forwarding to N (config_generation N),
  assert the lookup MISSes. No timing race required because the coherence is structural.

**Residual to validate in review (see §7):** `config_generation` still lives in
`ValidationState` for the coordinator's control-plane rollback/monotonicity guard
(`self.validation`, #5169) and any status accessor. Path D *adds* a coherent copy into
forwarding for the worker stamp; it does not remove the control-plane copy. The worker
simply stops reading `validation.config_generation` (it keeps reading
`validation.fib_generation` + `snapshot_installed`). Whether to then drop
`config_generation` from the *worker-visible* validation Arc is optional cleanup, out of
scope for the fix.

### Path comparison

| | A bundle | B gen-gate | C seqlock | **D split-source** |
|---|---|---|---|---|
| Closes forward fail-open | Yes | Partial/fragile | Yes | **Yes** |
| Closes inverse schedule | Yes | No | Yes | **Yes** |
| Hot-path per-packet cost | none | insert compare + bypass burst | **per-tick seqcount read** | **none** |
| Route-churn (fib bump) cost | **risk: forwarding clone** | none | none | **none** |
| Blast radius (readers) | **all** | forwarding+insert | **all + retry proto** | **flow-cache + builders only** |
| Race test determinism | moderate | moderate | **flaky** | **deterministic unit test** |
| Prereq (gen in forwarding) | n/a (bundle) | yes | n/a | yes |

---

## 6. API / behavior preservation

- No control-plane protocol change: `config_generation` / `fib_generation` on the wire and
  in `ValidationState` are unchanged. `bump_fib_generation` semantics unchanged.
- No change to status/metrics output (fib accessor untouched; config_generation still on
  `self.validation`).
- No change to HA session-sync, CoS maps, or the tunnel aux path (Path D).
- Flow-cache external behavior is *more* correct, not different: a committed config change
  still invalidates cached decisions — now including the previously-raced entry.

---

## 7. Hidden invariants / things that must hold

1. **`config_generation` is written into `ForwardingState` on EVERY path that rebuilds it**
   — same-plan refresh, full reconcile, and any disarmed refresh — using the *same*
   `snapshot.generation` the coordinator writes to `validation`. A build path that forgets to
   set it would stamp `0` and mass-invalidate (fail-*closed*, self-healing, but a perf cliff).
   **CORRECTION (SMR F1): a "no-`Default`" compile-time guard is NOT viable** —
   `ForwardingState::default()` is load-bearing: `ha_state.rs` builds the forwarding ArcSwap
   with `ArcSwap::from_pointee(ForwardingState::default())` at coordinator init, and every
   builder starts from `let mut state = ForwardingState::default();`
   (`forwarding_build/mod.rs` L206). Removing `Default` is therefore impossible. The guard is:
   (a) the field defaults to `0`, which matches `ValidationState::default().config_generation
   == 0`, so pre-first-apply stamp/lookup are coherent at 0; (b) all real forwarding flows
   through `build_forwarding_state_*` — set `config_generation = snapshot.generation` once,
   there, at the top of `build_forwarding_state_with_policy_counters_and_previous`; (c) a test
   asserts `forwarding.config_generation == snapshot.generation` after same-plan refresh, full
   reconcile, AND disarmed refresh (§9.5). This is a test/build-site guard, not a type guard.
2. **`fib_generation` MUST stay sourced from `validation`.** It bumps without a forwarding
   rebuild; sourcing it from forwarding would silently drop route-churn invalidations
   (fail-open on stale next-hops). Path D keeps it in validation — this split is the crux and
   must be explicit in code comments.
3. **Preserved-fabric / merge paths** (snapshot_refresh L266–297) mutate
   `self.forwarding.fabrics` *after* `self.forwarding = new_forwarding` but *before* the
   store. `config_generation` must be set on `new_forwarding` before those mutations (it is a
   scalar, unaffected by the fabric merge) so the stored Arc carries it.
4. **`refresh_fabric_links`** (L60/L66) re-stores `self.forwarding` without a generation
   change — it must preserve the existing `config_generation` (it clones `self.forwarding`, so
   it does, as long as the field is on the struct).
5. The stamp's other axes (owner_rg_id, owner_rg_epoch, lease) are unchanged and still
   sourced as today.
6. **#5169 monotonicity is a precondition** (SMR F3): the equality invalidation is only
   sound because `config_generation` moves forward monotonically. If a rolled-back generation
   were ever published, an entry stamped with the old value could false-hit. Path D inherits
   #5169's guarantee; do not weaken it.

---

## 8. Risk table

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| A forwarding-build path forgets to set `config_generation` | Low | Perf cliff (mass invalidation), fail-closed | Set it ONCE in `build_forwarding_state_..._and_previous` (the single funnel all builders pass through); test asserts it equals `snapshot.generation` after every apply path. (No-`Default` type guard is NOT viable — see §7.1.) |
| Sourcing fib_generation from forwarding by mistake | Low | Fail-open on route churn | Keep fib in validation; explicit comment + test that a fib bump alone still invalidates |
| Signature churn on `capture`/`for_packet` breaks a call site | Low | Compile error (caught) | Rust type system; update all sites in one change |
| Hidden reader of `validation.config_generation` in worker beyond the stamp | Low | Behavior change | §2.7 grep shows worker reads it only for the stamp; re-grep at implementation |
| Interaction with #5166 (CoS pair) fix landing concurrently | Low | Merge conflict | Coordinate ordering; Path D does not touch CoS maps |
| Path A/C only: route-churn regression / retry cost | — | — | Prefer D |

---

## 9. Test plan

Pure Rust unit/integration tests in `userspace-dp` (no cluster needed for correctness;
smoke on the loss userspace cluster only as a non-regression sanity at `/engineer` time):

1. **Coherence unit test (the fix's proof):** build `ForwardingState` at
   `config_generation = N-1`; insert a permit stamped from it; rotate the worker's forwarding
   local to `config_generation = N`; assert the next lookup MISSes (evicts + re-evaluates).
   Fails on today's code (stamp from validation N would hit); passes with Path D.
2. **Forward-schedule regression test:** simulate the torn read — worker holds validation N,
   forwarding N-1 — insert; then forwarding→N; assert eviction. (Under Path D this is just
   test 1 expressed via the worker locals.)
3. **fib-only invalidation preserved:** bump `fib_generation` via validation with forwarding
   unchanged; assert a cached entry is still invalidated (guards invariant §7.2).
4. **Exact-equal re-apply idempotency (#5169/#4036):** same generation re-apply does not
   spuriously mass-invalidate.
5. **Build-path coverage:** assert `config_generation` is non-zero and equals
   `snapshot.generation` after same-plan refresh AND full reconcile AND disarmed refresh.
6. `make test-rust` (cargo suite) green; `make test` (Go+Rust) green.
7. **/engineer-time only:** one loss-userspace-cluster smoke (v4+v6, push+reverse, CoS
   on/off) to confirm no forwarding regression — NOT part of research.

---

## 10. Out of scope

- #5166 (forwarding↔CoS owner/lease pair) — distinct store pair; separate issue.
- #5169 monotonicity guard — already shipped.
- Removing `config_generation` from the worker-visible `ValidationState` Arc — optional
  cleanup, not required to close the fail-open.
- Any bundle/rewrite of the CoS / mirror / cos-lease ArcSwaps.
- Reworking `bump_fib_generation` — must stay a cheap validation-only store.

## 11. Open questions (for reviewers)

1. Is Path D's split-source (config from forwarding, fib from validation) acceptable, or do
   reviewers prefer a *single* generation source even at the cost of the fib-bump forwarding-
   clone (Path A)? The whole recommendation hinges on the fib-bump decoupling being worth
   preserving.
2. Should `config_generation` be *removed* from the worker-visible validation Arc once the
   stamp no longer reads it (cleanup), or left in place to minimize churn?
3. Does any consumer other than the flow-cache stamp read `validation.config_generation` on
   the worker side? (§2.7 says no; asking reviewers to double-check.)
4. RESOLVED by SMR F1: a no-`Default` type guard is not viable (`ForwardingState::default()`
   is load-bearing). The plan now sets `config_generation` at the single builder funnel plus a
   post-apply test assertion (§7.1). Reviewers: is that guard sufficient, or is a
   `debug_assert` at the store site also wanted?
5. Should the fix also add a lightweight *diagnostic* — e.g. a debug assertion or counter
   that fires if a worker ever observes `validation.config_generation != forwarding.config_generation`
   — to catch any future re-introduction of a torn publish? (Detection, not correctness.)
