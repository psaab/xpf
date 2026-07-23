# #6236 — Replace `FilterState` parallel hook maps with typed records

## 1. Status

`DRAFT v1 — pending adversarial plan review`

Research base: `origin/master` @ `9951b5033` (worktree
`.claude/worktrees/6236-research`, branch
`research/6236-filterstate-typed-hooks`). Issue cites
`9da51c00c`; the `FilterState` struct has since moved to
`userspace-dp/src/filter/mod.rs:743-811` but is otherwise unchanged
(still 31 fields; the four family/direction compiler branches are now
`filter/compiler.rs:153-301`).

No production source was touched. The only file written is this plan.

---

## 2. Issue framing (in my words)

`FilterState` is the compiled, in-process runtime representation of every
firewall-filter hook. For each of the four interface hook slots (input inet,
input inet6, output inet, output inet6) plus the two lo0 host-bound slots, it
keeps a **fan of parallel per-ifindex collections** that must be updated in
lockstep by the compiler and re-joined by the packet path:

- a **name map** `FxHashMap<i32, String>` (the qualified `"family:name"` key),
- a **fast map** `FxHashMap<i32, Arc<Filter>>` (the actual hot-path filter ref),
- one or more **property sets** `FxHashSet<i32>` (ifindexes whose filter
  "affects tx-selection" / "affects route-lookup" / "has dscp match" /
  "has per-packet-L4 match" / "needs tx eval"),
- and **family-wide aggregate booleans** (`has_input_tx_selection_v4`, …).

The defect has two faces:

1. **Modularity / lockstep-edit hazard.** Adding a hook property means editing
   the struct, the compiler's four near-identical branches, and every consumer.
   An omission silently produces contradictory metadata (a fast-map entry with
   no matching property-set membership, or vice-versa) with no compile-time
   guard. The compiler branches at `compiler.rs:153-301` are the concrete
   hazard: each direction hand-maintains 3–5 `state.<set>.insert(ifindex)`
   calls plus the fast-map insert plus the aggregate-bool set, and the only
   thing keeping them consistent is that a human wrote them in the same order.

2. **Avoidable hot-path hash work.** The packet path reconstructs one logical
   hook with **two** hash probes: a property-set `.contains(&ifindex)` precheck,
   then a *separate* fast-map `.get(&ifindex)` to obtain the `Arc<Filter>` for
   evaluation. On the output-TX path it is worse — a *third* redundant step
   recomputes, inline off the fetched `Filter`, the exact predicate the property
   set already encoded (`cos_classify.rs:206/212/225`).

The issue proposes folding each hook into one typed record so a single lookup
returns the filter and its derived flags, deleting the dead name maps and the
`Filter`-duplicating property sets, and retaining only the aggregate booleans
that let the packet path skip work when a capability is globally absent.

> If reviewers conclude the perf/modularity gain is too small to justify the
> churn, PLAN-KILL is an acceptable verdict.

---

## 3. Honest scope / value framing — what the win actually is

Three distinct, independently-defensible wins. I rank them by confidence.

### 3a. Dead-field deletion (HIGH confidence, real, low risk)

Firsthand grep proof (Step-1/Step-2 census, prod = non-test files):

| Field | Kind | Prod writes | Prod reads | Verdict |
|---|---|---|---|---|
| `iface_filter_v4` | name map | 1 (`compiler.rs:198` insert) | **0** | DEAD (1 test read) |
| `iface_filter_v6` | name map | 1 (`compiler.rs:269`) | **0** | DEAD (0 reads anywhere) |
| `iface_filter_out_v4` | name map | 1 (`compiler.rs:230`) | **0** | DEAD (0 reads anywhere) |
| `iface_filter_out_v6` | name map | 1 (`compiler.rs:299`) | **0** | DEAD (1 test read) |
| `iface_filter_v4_affects_tx_selection` | property set | 1 (`compiler.rs:163`) | **0 real** | DEAD-in-prod* |
| `iface_filter_v6_affects_tx_selection` | property set | 1 (`compiler.rs:237`) | **0 real** | DEAD-in-prod* |
| `lo0_filter_v4` | name string | `compiler.rs:303` | compile-only† | cold, deletable from struct |
| `lo0_filter_v6` | name string | `compiler.rs:320` | compile-only† | cold, deletable from struct |

\* The only reader of the two input `affects_tx_selection` sets is the helper
`interface_filter_affects_tx_selection` (`tx_selection.rs:375-389`), whose
**only callers are tests** (`tests.rs:3647-3662`). No production code path
consults these sets. This exactly matches the issue's own adversarial
correction ("the input `*_affects_tx_selection` sets are not a production
hot-path consumer: their helper's callers are tests"). The candidate report's
"the four name-only maps have no production reader" is *correct*; its implication
that the sets are hot is *not*.

† `lo0_filter_v4`/`v6` are read only inside the compiler to derive
`lo0_filter_v*_fast` (`compiler.rs:308/325`) and asserted by one test
(`tests.rs:2269-2270`). They can become compiler locals; the struct keeps only
the `_fast` `Option<Arc<Filter>>` (which *is* live — see 3c).

**Win:** 8 fields removed (31 → 23), ~240 bytes off the struct
(see 3d), and the lockstep surface for these fields disappears entirely. This is
pure removal with no hot-path behavior change — the safest, highest-value slice.

### 3b. Property-set → `Filter`-flag convergence (MED confidence, real, med risk)

The six *live* input property sets each duplicate an immutable flag already
carried by `Filter`:

| Property set | Duplicates `Filter` field | Populated at |
|---|---|---|
| `iface_filter_v{4,6}_affects_route_lookup` | `affects_route_lookup` | `compiler.rs:170-174 / 244-248` |
| `iface_filter_v{4,6}_has_dscp_match` | `has_dscp_match_terms` | `compiler.rs:175-177 / 249-251` |
| `iface_filter_v{4,6}_has_per_packet_l4_match` | `has_per_packet_l4_match_terms` | `compiler.rs:178-182 / 252-256` |

Proof this is safe *and already the established pattern*: the **output**
direction has **no** such sets — `interface_output_filter_has_dscp_match`
(`cache_sensitive.rs:483-494`) and `interface_output_filter_has_per_packet_l4_match`
(`cache_sensitive.rs:560+`) already do `iface_filter_out_v*_fast.get(&ifindex)`
then read `filter.has_dscp_match_terms` off the fetched `Filter`. And the cold
rotation path `input_dscp_filter_families_changed` (`cache_sensitive.rs:461-468`)
already iterates `iface_filter_v*_fast` filtering on `filter.has_dscp_match_terms`
— it never consulted the set. Only the **hot input precheck** reads the set.

Converging input onto the output pattern (read the flag off the `Arc<Filter>`
already in the fast map) makes input/output symmetric and deletes 6 more fields.
The two output `needs_tx_eval` sets are a *composite* OR of five `Filter` flags
(`affects_tx_selection || has_counter_terms || has_log_terms ||
has_terminal_action_terms || has_three_color_policer_terms`, `compiler.rs:203-208
/ 274-278`); they can be replaced by a `Filter::needs_tx_eval()` accessor read
after the same `.get()` — which `cos_classify.rs:225-231` *already computes
inline*.

**Win:** up to 8 more fields removed (23 → 15). But — see 3c — the true
per-packet payoff is the eliminated second probe, and it only materializes where
the precheck and the subsequent eval **share one `.get()`**. That call-site
refactor is the substantive, riskier work.

### 3c. Hot-path probe elimination (the acceptance-criterion win — MED confidence)

Per-packet probe counts today, verified firsthand:

| Call site | Today | After single-lookup fold |
|---|---|---|
| Input route-lookup (`poll_descriptor/filter.rs:220` precheck + `:229` eval) | 2 probes (`affects_route_lookup.contains` + `iface_filter_v*_fast.get`) | **1** |
| Output TX eval (`cos_classify.rs:206` precheck + `:212` get + `:225` inline recompute) | 2 probes + 1 recompute | **1**, no recompute |
| PBR (`forwarding/pbr.rs:60` precheck, may skip eval) | 1 | 1 (field deleted, no probe change) |
| Input DSCP/L4 cache-gate (`flow_cache`/`poll_descriptor` — boolean only, no eval) | 1 set-probe | 1 map-probe (neutral) |

**Honest caveat:** not every site goes 2→1. The route-lookup and output-TX-eval
sites genuinely drop a probe. The pure cache-sensitivity gates that only need the
boolean (no filter eval follows) go from one set-probe to one map-probe — probe
count unchanged; the benefit there is only field deletion + lockstep removal. The
acceptance criterion "no more hash probes … for the capability-hook lookups" is
satisfied for the eval-following sites and is *neutral* (not a regression) for the
boolean-only sites. State this to reviewers; do not claim a uniform 2→1.

### 3d. Struct sizeof — real but must be measured, and it is NOT the packet-cache footprint

The issue reports 736 bytes / 31 fields at `9da51c00c`. Back-solving from that
figure: an `FxHashMap`/`FxHashSet` header is ~32 bytes (20 containers × 32 = 640,
+ 24 `Vec` + 48 two `String` + 16 two `Option<Arc>` + 8 six `bool`/pad = 736 ✓).
Estimated post-refactor:

- Increment 1 (3a): −4 name maps −2 dead sets −2 lo0 Strings ≈ −240 → ~496 B / 23 fields.
- Increment 2 (3b): −6 input sets (−192) −2 output sets (−64) ≈ −256 → ~240 B / 15 fields.

**These numbers must be re-measured with `std::mem::size_of::<FilterState>()`
printed on the branch, not hand-computed** — hashbrown inline size and enum
niche packing vary by toolchain, and the 32-byte figure is a back-solve from the
issue's own 736, not an independent measurement.

**Critical honesty (per the issue's adversarial section):** there is exactly
**one** `FilterState`, held in `ForwardingState.filter_state`
(`afxdp/types/forwarding.rs:264`) and cloned only on snapshot swap. The struct
sizeof is a **clone-cost + clarity** win, **not** a per-packet cache-line win —
the maps own their buckets on the heap separately. Do not sell the byte
reduction as a packet-path speedup; the packet-path speedup is 3c alone.

---

## 4. What's already shipped / partially done in this area

- The **output** direction is already the target design: single `.get()` +
  flags-off-`Filter`, no property sets (`cache_sensitive.rs:483-494`,
  `cos_classify.rs:212-231`). This is the existence proof that the pattern works
  on the hot path.
- `Filter` already carries every derived flag the property sets encode:
  `affects_tx_selection`, `affects_route_lookup`, `has_counter_terms`,
  `has_log_terms`, `has_terminal_action_terms`, `has_dscp_match_terms`,
  `has_per_packet_l4_match_terms`, `has_three_color_policer_terms`
  (`compiler.rs:132-149`). No new flag needs to be computed.
- The cold rotation/purge paths (`input_dscp_filter_families_changed`,
  `input_per_packet_l4_filter_families_changed`) already read flags off the fast
  map, not the sets — so the cache-sensitivity machinery needs no change to its
  data source, only the hot precheck does.
- Fail-closed `MissingFilterRef` snapshot integrity (#3296) is in place at every
  branch (`compiler.rs:186-197, 219-229, 260-268, 290-298, 309-319, 326-334`)
  and the `filter/README.md` §"Undefined interface/lo0 filter reference (#3296)"
  documents the fast-map/needs_tx_eval contract that this refactor must preserve
  and re-document.

---

## 5. Concrete design

Two design options are on the table. **Design A is recommended**; Design B is the
issue's literal proposal, retained for the reviewers to weigh.

### Design A (recommended) — delete the redundancy, converge input onto the output pattern

The insight: `iface_filter_v*_fast` **already is** the typed hook record — it
holds `Arc<Filter>`, and `Filter` already carries all derived flags. The parallel
name maps and property sets exist only because the input prechecks were written
as separate set-probing helpers. So the minimal, lowest-risk realization of the
issue is **deletion + call-site convergence**, not a new wrapper type.

Struct after Design A (registries + fast maps + aggregates + lo0 fast):

```rust
pub(crate) struct FilterState {
    // registries — unchanged, out of scope
    filters: FxHashMap<String, Arc<Filter>>,
    three_color_policer_by_name: FxHashMap<String, Arc<ThreeColorPolicerRuntime>>,
    three_color_policers: Vec<Arc<ThreeColorPolicerRuntime>>,

    // per-interface fast maps — the hook records (Arc<Filter> carries the flags)
    iface_filter_v4_fast: FxHashMap<i32, Arc<Filter>>,
    iface_filter_v6_fast: FxHashMap<i32, Arc<Filter>>,
    iface_filter_out_v4_fast: FxHashMap<i32, Arc<Filter>>,
    iface_filter_out_v6_fast: FxHashMap<i32, Arc<Filter>>,

    // lo0 host-bound — fast Option only (names become compiler locals)
    lo0_filter_v4_fast: Option<Arc<Filter>>,
    lo0_filter_v6_fast: Option<Arc<Filter>>,

    // RETAINED aggregate fast-branch booleans (skip work when globally absent)
    has_input_tx_selection_v4: bool,
    has_input_tx_selection_v6: bool,
    has_input_three_color_policer_v4: bool,
    has_input_three_color_policer_v6: bool,
    has_output_tx_selection_v4: bool,
    has_output_tx_selection_v6: bool,
}
```

31 → 15 fields. **DELETE:** 4 name maps, 2 lo0 name Strings, 2 dead input
`affects_tx_selection` sets, 6 input property sets, 2 output `needs_tx_eval`
sets = 16 fields. **RETAIN:** 6 aggregate booleans (issue mandates), 6 fast maps
+ 2 lo0 fast Options, 3 registries.

Compiler after Design A — the four branches collapse to one populate-fast-map +
set-aggregate per direction, with no per-property `.insert(ifindex)` fan:

```rust
// input inet (mirror for inet6 / output)
if let Some(filter) = state.filters.get(&key) {
    if filter.affects_tx_selection { state.has_input_tx_selection_v4 = true; }
    if filter.has_three_color_policer_terms { state.has_input_three_color_policer_v4 = true; }
    state.iface_filter_v4_fast.insert(iface.ifindex, filter.clone());
} else {
    return Err(SnapshotIntegrityError::MissingFilterRef { … }); // #3296, unchanged
}
```

Add derived accessors on `Filter` (or free fns) so consumers read one place:

```rust
impl Filter {
    #[inline] fn needs_tx_eval(&self) -> bool {
        self.affects_tx_selection || self.has_counter_terms || self.has_log_terms
            || self.has_terminal_action_terms || self.has_three_color_policer_terms
    }
}
```

Consumer rewrites (each now one `.get()`, flag read off the result):

| Consumer (today) | After |
|---|---|
| `interface_filter_affects_route_lookup` = `set.contains(&if)` | `iface_filter_v*_fast.get(&if).is_some_and(\|f\| f.affects_route_lookup)` |
| `interface_input_filter_has_dscp_match` = `set.contains` | `.get(&if).is_some_and(\|f\| f.has_dscp_match_terms)` |
| `interface_input_filter_has_per_packet_l4_match` = `set.contains` | `.get(&if).is_some_and(\|f\| f.has_per_packet_l4_match_terms)` |
| `interface_output_filter_needs_tx_eval` = `set.contains` | `.get(&if).is_some_and(\|f\| f.needs_tx_eval())` |
| `interface_filter_affects_tx_selection` (test-only) | **deleted** with its 4 tests |

Then, for the 2→1 probe win, the **route-lookup** and **output-TX-eval** call
sites (`poll_descriptor/filter.rs:219-242`, `cos_classify.rs:206-246` and its
:640-760 twin) fetch the hook once and thread the borrowed `&Filter` into the
evaluator so the eval does not re-`.get()`. This is the single-lookup API
invariant the issue's acceptance demands (adversarial point #4).

### Design B (issue literal) — `filter/hooks.rs` with typed wrappers

New module `filter/hooks.rs`:

```rust
struct FilterHookFlags(u8);              // bitset over the derived predicates
struct FilterHook { filter: Arc<Filter>, flags: FilterHookFlags }  // NO key field
struct FilterFamilyHooks { input: FxHashMap<i32, FilterHook>, output: FxHashMap<i32, FilterHook> }
```

Adversarial-mandated constraints if Design B is chosen:
- **No `key: Arc<str>` in the hot map value** (adversary blocking-correction #1).
  Proven cold: no production reader of any hook name. Omit it; if a diagnostic
  reader is ever identified, put it in a *separate cold side-table*, never in the
  packet-path bucket.
- **One private `FilterHook`, not separate `InputFilterHook`/`OutputFilterHook`**
  (adversary correction #3) unless the two enforce genuinely different invariants
  (they do not — same `{filter, flags}` shape; input and output just read
  different flag subsets).
- `flags` must be derived by the *sole* constructor with an invariant test
  proving exact equality with the `Filter` flags (adversary correction #2), or —
  simpler — drop `flags` entirely and read off `filter`, at which point Design B
  degenerates into Design A. This is why A is recommended: the flags bitset earns
  its keep only if reading `Filter` fields is measurably worse than a co-located
  bitset, which for these 1-byte reads is implausible.

### Recommendation

**Design A.** It satisfies every acceptance criterion, is strictly less code,
adds no new type to maintain, keeps `Arc<Filter>` identity, and is exactly the
representation the output direction already ships. A new `hooks.rs` is
justified only for the *naming/aggregation* clarity of
`FxHashMap<i32, FilterHook>` — a cosmetic upgrade the reviewers may request but
which is not required to fix the defect.

---

## 6. Public API preservation

All of `FilterState`'s fields are `pub(crate)`; there is no external/gRPC/wire
surface. The preserved **crate-internal** call surface (consumers keep compiling
unchanged; only the bodies change):

- `interface_filter_affects_route_lookup(&FilterState, i32, bool) -> bool`
- `interface_input_filter_has_dscp_match(&FilterState, i32, bool) -> bool`
- `interface_output_filter_has_dscp_match(&FilterState, i32, bool) -> bool`
- `interface_input_filter_has_per_packet_l4_match(&FilterState, i32, bool) -> bool`
- `interface_output_filter_has_per_packet_l4_match(&FilterState, i32, bool) -> bool`
- `interface_output_filter_needs_tx_eval(&FilterState, i32, bool) -> bool`
- `filter_state_has_input_tx_selection` / `filter_state_has_output_tx_selection` /
  `filter_state_has_input_three_color_policer` (aggregate accessors — bodies
  unchanged, fields retained)
- `evaluate_interface_filter_non_routing_counted`,
  `evaluate_filter_ref_tx_selection_cached`, and the lo0 evaluators — signatures
  unchanged (single-lookup fold changes call sites, not these signatures, unless
  a `&Filter` param is added as an *additive optional* fold).
- `three_color_policer_statuses()` and the `filters` / policer registries —
  untouched.

**Removed** (test-only, no production caller): `interface_filter_affects_tx_selection`.
Its four `tests.rs:3647-3662` assertions are deleted or rewritten against the
retained aggregate `filter_state_has_input_tx_selection`.

---

## 7. Hidden invariants to preserve

1. **No wire / HA-sync crossing.** `FilterState` is in-process only
   (`ForwardingState.filter_state`); it has **no** `Serialize`/`Deserialize`/
   `bytemuck`/`repr(C)`, is `#[derive(Clone, Debug, Default)]`, and is rebuilt
   from the snapshot on every config apply. **Verified:** the only non-filter,
   non-test references are `afxdp/types/forwarding.rs:264` (the field) and
   `afxdp/tests_support.rs`. This removes the entire wire/ABI/HA-portability risk
   class — the refactor cannot desync peers. **Keep `Default` derivable** (all
   retained fields are `Default`); keep `Clone` (snapshot swap clones it).
2. **Fail-closed `MissingFilterRef` (#3296).** Every direction's `else` branch
   must still `return Err(MissingFilterRef)` when a hook names an absent filter —
   deleting the name-map `.insert` must not delete the `filters.get()` guard that
   precedes it. A dangling output hook with no fast entry AND no `needs_tx_eval`
   flag would fail-OPEN; the guard is the only thing preventing it.
3. **`Arc<Filter>` identity.** Consumers rely on `Arc::as_ref` / `Arc::clone`
   identity (e.g. `three_color_policer_by_name` reuse in the compiler, cached
   evaluation). The fast maps keep `Arc<Filter>` values verbatim.
4. **Exact cache-sensitivity predicate (#1430 runbook).** The DSCP / per-packet-L4
   flow-cache decline gate must compute the *same* boolean after the fold.
   `set.contains(&if)` was populated iff `filter.has_dscp_match_terms` — so
   `.get(&if).is_some_and(|f| f.has_dscp_match_terms)` is bit-identical. A silent
   divergence here corrupts the flow cache (a DSCP-varying flow gets a stale
   cached verdict). `protocol/security.rs:132-143` documents this runbook by
   field name and must be updated.
5. **`needs_tx_eval` composite identity.** `Filter::needs_tx_eval()` must OR
   *exactly* the five flags the compiler ORed (`compiler.rs:203-208`), and the
   inline recompute at `cos_classify.rs:225-231` must be replaced by the same
   accessor (not left to drift as a second definition).
6. **Counter-ownership ordering (#2620).** `poll_descriptor/filter.rs:204-228`
   chooses `NonRoutingCountPolicy` based on `interface_filter_affects_route_lookup`
   *before* the eval, to avoid double/under-count. Folding precheck+eval into one
   `.get()` must preserve the ordering: decide the count policy from the fetched
   `Filter`'s `affects_route_lookup`, then evaluate with that policy — the borrow
   must outlive both uses.
7. **Family/direction correctness under NAT64 (#3642 / #5158).** `cos_classify`
   selects input-filter family from the *pre-NAT ingress* key and output-filter
   family from the *post-NAT egress* key. The fold must not collapse the two
   `is_v6` selectors into one.
8. **Aggregate-false fast branch.** `cos_classify.rs:286-292` early-returns
   `default()` when `!has_output_tx_eval && !has_input_tx_selection &&
   !has_input_three_color_policer`. All three aggregate booleans must be retained
   and populated exactly as today.

---

## 8. Risk table

| Risk | Level | Rationale / mitigation |
|---|---|---|
| Behavioral regression (cache-sensitivity divergence) | **MED** | Predicate is bit-identical by construction (inv. #4); guard with the existing `flow_cache_tests` + a new "set-membership == Filter-flag" equivalence test on the branch before deleting the sets. |
| Behavioral regression (fail-open on `MissingFilterRef`) | **MED** | Keep the `filters.get()` guard; parent-RED test: name an absent output filter, assert snapshot refused. |
| Counter double/under-count (#2620) | **MED** | Preserve count-policy-before-eval ordering; thread the borrowed `&Filter`. Covered by existing counter tests; add a route-lookup + discard exit case. |
| Borrow-checker friction (single-lookup fold) | **LOW-MED** | The fetched `Arc<Filter>`/`&Filter` must outlive precheck+eval; straightforward with a `let hook = map.get(&if);` binding. No self-referential borrow. |
| Perf regression | **LOW** | Removes probes on the eval-following sites; neutral elsewhere. `Filter` flag reads are 1-byte loads off an already-hot `Arc`. Bench gate (<1%) required by acceptance. |
| Architectural mismatch (the #946-P2 / #961 dead-end pattern — does the parallel-map layout exist for a *cache* reason?) | **LOW** | **Checked:** it does not. The output direction proves the single-map+flags layout is already the shipped hot-path design; the input sets are historical duplication, not a cache-locality optimization. There is one `FilterState`, not a per-CPU array, so no false-sharing motive. See §11 Q3. |
| Over-engineering (Design B adds a type that degenerates to A) | **LOW** | Recommend Design A; make `hooks.rs` optional cosmetic scope. |
| Scope creep across 6 consumer files in one PR | **MED** | Mitigate by the increment split (§10). |

---

## 9. Test plan

- `cargo build -p userspace-dp` + `cargo clippy` clean on the branch.
- `make test-rust` full suite (filter, CoS, forwarding, cache-rotation,
  snapshot-integrity). The most-affected tests: `filter/tests.rs` (the
  `interface_filter_*` helpers, `iface_filter_*` assertions at :2255-2270,
  :3647-3662, :4317), `afxdp/flow_cache_tests.rs` (DSCP/L4 cache gate).
- **Parent-RED**: neutralize the fix and assert an *existing* test fails — e.g.
  make `Filter::needs_tx_eval()` drop `has_counter_terms` and assert a
  counter-bearing output filter's tx-eval test goes red; make the DSCP precheck
  read the wrong flag and assert `flow_cache_tests` red.
- **New equivalence test** (added *before* deleting any set): for a compiled
  `FilterState`, assert `set.contains(&if) == fast.get(&if).is_some_and(flag)`
  for every property set, proving the fold is behavior-preserving.
- **5× flake** on the most-affected test (`make test-rust` targeted) under
  `TMPDIR=/tmp` (avoid the `sun_path` 108 trap on socket-binding tests).
- **Go suite** `make test-go` — no Go touches `FilterState`, but the retirement
  path-keyed canary requires the full Go suite regardless (per project memory).
- **Loss-cluster iperf smoke** (filter is hot-path): `make cluster-deploy` then
  `make test-failover`/`security-matrix` — v4 **and** v6, push **and** reverse,
  CoS-on **and** CoS-off, and **per-class CoS** (`cos-iperf-config.set`, ports
  5200-5211) since the output-TX-eval fold touches CoS classification. Re-apply
  CoS after deploy (`apply-cos-config.sh` — deploy wipes CoS). Serialize the
  smoke through a single agent under the shared-cluster lock.
- **Bench** (acceptance): micro-bench absent-hook / present-simple-hook /
  capability-hook lookups; assert no added probe and ≤1% regression; print
  `size_of::<FilterState>()` before/after; inspect optimized asm for no new
  alloc/indirect-call/lock/atomic on the packet path.

---

## 10. Out of scope (explicitly) / increment decision

- **Registries** (`filters`, `three_color_policer_by_name`, `three_color_policers`)
  — not touched.
- **`Filter` struct** — only an additive `needs_tx_eval()` accessor; no field
  changes.
- **Go control plane / gRPC / snapshot wire** — untouched (FilterState is
  in-process).
- **The lo0 `String` → local migration** is bundled into increment 1 (trivial).

**Increment decision (for reviewers to ratify):** the issue says "migrate one
family/direction at a time behind compatibility accessors." I recommend **two
PRs**, not one, and not four:

- **PR-1 (primary deliverable, LOW risk):** delete the 4 dead name maps + 2 dead
  input `affects_tx_selection` sets + the test-only helper + lift the 2 lo0
  `String`s to compiler locals. Pure removal, **zero** hot-path behavior change,
  31 → 23 fields. Ships the biggest safe win with the smallest blast radius.
- **PR-2 (follow-up, MED risk):** converge the 6 input property sets + 2 output
  `needs_tx_eval` sets onto `Filter`-flag reads, and do the single-lookup
  call-site fold (route-lookup + output-TX-eval). This carries the
  cache-sensitivity + counter-ordering + borrow risk and earns its own
  loss-cluster smoke. 23 → ~15 fields.

Doing both in one PR is feasible (no wire risk to gate on) but makes the
parent-RED and the smoke harder to attribute. Splitting is the safer sequencing;
the per-direction "compatibility accessor" shim the issue mentions is unnecessary
because the public accessor *signatures* never change — only their bodies — so
consumers never see an intermediate state.

---

## 11. Open questions for adversarial review (each PLAN-KILL-invitable)

1. **Is the 736→~240 byte reduction real given alignment/padding — and does it
   matter?** The 32-byte-per-container figure is back-solved from the issue's own
   736, not measured. If the true post-fold sizeof is only, say, 736→520 (niche
   packing worse than assumed), and given there is exactly one `FilterState`
   cloned per snapshot, is the sizeof win large enough to be worth citing at all,
   or should the plan drop the byte claim and stand purely on 3a (dead-field
   deletion) + 3c (probe elimination)? **PLAN-KILL if the only defensible win is
   deleting 8 test-only fields.**

2. **Do the four name maps / two `affects_tx_selection` sets truly have no
   reader, or is there a reflection/`Debug`/status path I missed?** I grepped all
   63 `FilterState` refs; the name maps appear only in `compiler.rs` (write) and
   `tests.rs` (read), and `FilterState` never serializes. But is there a
   `#[derive(Debug)]`-driven diagnostic dump, a snapshot-integrity hash, or a Go
   status RPC that indirectly depends on these fields existing? If yes, deletion
   is not free.

3. **Does the parallel-map layout exist for a cache/perf reason that typed
   records (or Filter-flag reads) would regress?** My claim is no — the output
   direction already ships the single-map pattern, and there is one non-per-CPU
   `FilterState`, so no false-sharing motive. But is there a documented reason
   (a #1430 or #2362 design note) that the *hot input precheck* was deliberately
   a small dense `FxHashSet<i32>` (cheap to probe, cache-friendly) rather than a
   larger `FxHashMap<i32, Arc<Filter>>` probe? If the set-probe is measurably
   cheaper than the map-probe for the boolean-only cache gates, converging them
   is a (tiny) regression, not a win, on those sites.

4. **Does splitting/reading-through the fast map ADD a pointer-chase the set
   avoided?** `set.contains(&if)` touches only the set's control bytes; `.get(&if)`
   then reading `filter.affects_route_lookup` chases the `Arc` to heap. For the
   eval-following sites this is free (the eval chases it anyway). For the
   boolean-only cache gate, the fold trades a set-probe for a map-probe **plus an
   Arc deref**. Is that deref measurable at line rate? (Bench must include the
   boolean-only path, not just the eval path.)

5. **Single-lookup invariant vs. borrow ergonomics under #2620/#3642.** The
   counter-ownership decision and the NAT64 family selection both happen *before*
   the eval. Threading one borrowed `&Filter` through the count-policy decision,
   the family selection, and the evaluator without a second `.get()` — is that
   clean in the actual control flow of `poll_descriptor/filter.rs` and
   `cos_classify.rs`, or does the borrow force an awkward refactor (or a clone)
   that eats the win? If the only way to get one lookup is to restructure those
   functions substantially, is PR-2 worth it, or should it stop at "delete the
   sets, read off Filter" (accepting the probe count stays 1 where a boolean
   suffices and 2 only where an eval follows — i.e. no worse than today)?

6. **(Bonus) Is Design B's `hooks.rs`/`FilterHook` net-negative?** Given that
   `Arc<Filter>` already carries the flags, does introducing a `FilterHook`
   wrapper add a type to maintain for zero behavioral gain — i.e. should the plan
   *forbid* Design B rather than merely not-recommend it?
