# #9522 — Remove the learned-route import cap cause via a chunked route verb (keep #7480 strict adjudication)

## 1. Status

DRAFT v1 — pending adversarial plan review

Worktree: `/home/ps/git/pi-xpf/.claude/worktrees/9522-learned-route-cap`, branch
`fix/9522-learned-route-cap`, base `origin/master 7ef226474` (verified: `git rev-parse HEAD`
equals base at plan time). STEP-0 verified present on base (see §2 evidence); this is not
ALREADY_FIXED.

## 2. Issue framing

Above the #8355 derived import cap (64,956 routes at head), the daemon withholds the ENTIRE
kernel-learned route import and stamps `LearnedRouteImportCapped`; the helper's
`noroute_policy_denial_gated` then returns `None` (delegate) for every `NoRoute` frame, which
the `poll_binding_process_descriptor` NoRoute arm reinjects to `xpf-usp0` for Linux
forwarding with no zone-policy adjudication, no session, no NAT and no screen. An ordinary
full Internet table crosses the cap, so this is a reachable, silent, policy-bypass posture
change with (per #9172 item 3) no operator-visible signal distinguishing it from ordinary
unroutable traffic.

STEP-0 evidence on base `7ef226474` (all read, not inferred):

- `pkg/dataplane/userspace/learned_route_cap_8355.go:129-147` — `learnedRouteCapExceeded`
  declines the whole import above `maxLearnedRoutes()` and logs the `security_note`
  ("a NoRoute frame reaches the kernel FIB without zone-policy adjudication").
- `userspace-dp/src/afxdp/forwarding/mod.rs:184-209` — `noroute_policy_denial_gated`
  returns `None` iff `forwarding.learned_route_import_capped`; otherwise identical to
  `noroute_policy_denial` (#7480 adjudication against the #3110 unzoned sentinel).
- `userspace-dp/src/afxdp/poll_descriptor/mod.rs:5093-5267` — the NoRoute arm adjudicates
  via the gated helper, then falls through to the shared #1913 `slow_path_admit` reinject
  chokepoint (`maybe_reinject_slow_path_from_frame`, ~line 6443), which admits `NoRoute`.
- `pkg/daemon/daemon_transit_gate.go:69-80`, `pkg/nftables/transit_barrier.go:23-33` —
  kernel forwarding stays on and the transit barrier is removed while armed (cited in issue;
  not re-read here, taken from the issue's verified citation).

The issue explicitly rejects both horns of the current tradeoff: restoring fail-closed-above-cap
is the #9054 silent total blackhole of the dynamic FIB (rejected by all three reviewers), and
keeping silent delegation is the unowned posture change. The converged direction is to remove
the cap's *cause*: a chunked/delta route verb on the `update_neighbors`
(`userspace-dp/src/server/handlers/neighbors.rs`) pattern — no route equivalent exists in
`server/handlers/` today — so a full table reaches the helper FIB in budget-fitting pieces and
#7480 adjudication stays strict. Fallback if the channel work is too large: kernel route lookup
on a miss returning the real egress zone, adjudicate-before-delegate.

Acceptance (from the issue): a capped route miss and an uncapped route miss produce the SAME
policy result, permitted traffic still passes through an explicitly adjudicated path, the
uncapped-deny positive control keeps passing, and a full-table cap crossing must not silently
change posture.

## 3. Honest scope / value framing

This is a correctness/security fix, not a performance change. There is no throughput, cycle or
memory win to claim; the win is that a full-table box stops transiting deny-policy traffic with
no decision. At absolute scale the cost is real and the benefit is binary:

- Cost: a new control-socket verb + an incremental FIB mutation path in the helper + Go-side
  chunking/retry state — the largest control-plane surface added since `update_neighbors`
  itself, touching the single most security-sensitive disposition arm (`NoRoute` → reinject).
- Benefit: the `LearnedRouteImportCapped` state becomes unreachable for size reasons
  (route count no longer bounded by one publish's socket hold), so #7480 adjudication applies
  uniformly and the #9054 gate can be deleted rather than tuned.

*If reviewers conclude the channel work is too large to justify against the narrower
kernel-lookup-on-miss fallback — or that the fallback alone closes the adjudication hole with
less new mechanism — PLAN-KILL (of the chunked-verb half) is an acceptable verdict. Killing
the whole issue is also acceptable if reviewers conclude neither half is shippable without
regressing the #9054 availability property.*

## 4. What's already shipped / partially batched

- #7480: `noroute_policy_denial` + NoRoute-arm adjudication (uncapped deny = positive control).
  Cells: `forwarding/tests_noroute_adjudication_7480.rs`. Must keep passing unchanged.
- #8355: derived cap (`learnedRoutePublishBudget = 10s`, ~113 B/route, 64 MiB
  `MaxControlRequestBytes` lockstep Go↔Rust) + `LearnedRouteCapHits()` counter.
- #9054: `LearnedRouteImportCapped` wire bit (protocol v10, NOT skew-tolerant by design),
  `noroute_policy_denial_gated` early-`None`, route-only republish recompute
  (`manager_overlay.go`), refusal of the snapshot on pre-v10 helpers. Cells:
  `tests_noroute_capped_import_9054.rs`; Go guards:
  `learned_route_cap_blackhole_9054_test.go`.
- `update_neighbors` incremental-verb pattern: `neighbors.rs` replace/clear semantics (#5864
  present-empty clear), replace-generation envelope + stale fence + ACK (#6034), `refresh_status`
  after every verb, `content_digest.clear()` on out-of-band mutation (#9520), epoch tracking
  for partial-update outcome (#9684), writeback guards (#6986, #1197/#5306).
- Route-only overlay path: `Manager.PublishRouteOverlaySnapshot` + `bump_fib_generation`
  (fib-only advance invalidating flow-cache entries by pair equality, #3767 H4/H5, #5169).
- #7409 learned import (gap-fill: config route always wins; order-independent emission),
  #7437 rtnetlink listener driving coalesced republish (debounce 1s / throttle 3s), #9654
  capped-absence-is-unknown status semantics.
- #9172 item 3 (observability half) is explicitly OUT of scope here; fixing the bypass must not
  claim to fix the signal.

## 5. Concrete design

### 5a. Primary: `update_routes` chunked verb (mirrors `update_neighbors`)

Wire (additive fields on `ControlRequest`, both sides; Go `protocol.go`, Rust
`protocol/control.rs`):

```go
// Go ControlRequest additions (omitempty everywhere — old helper ignores them).
RouteChunk         []RouteSnapshot `json:"route_chunk,omitempty"`
RouteGeneration    uint64          `json:"route_generation,omitempty"`
RouteReplace       bool            `json:"route_replace,omitempty"` // first chunk clears
RouteChunkIndex    uint32          `json:"route_chunk_index,omitempty"`
RouteChunkTotal    uint32          `json:"route_chunk_total,omitempty"`
RouteChunkComplete bool            `json:"route_chunk_complete,omitempty"` // last chunk: FIB now whole
```

```rust
// Rust ControlRequest additions (all #[serde(default)] — old control plane never sends them).
pub route_chunk: Option<Vec<RouteSnapshot>>,
pub route_generation: u64,       // default 0
pub route_replace: bool,         // default false
pub route_chunk_index: u32,      // default 0
pub route_chunk_total: u32,      // default 0
pub route_chunk_complete: bool,  // default false
```

Handler `userspace-dp/src/server/handlers/routes.rs`, dispatched as `"update_routes"` from
`handlers/mod.rs` next to `"update_neighbors"`:

```rust
pub(super) fn update(
    guard: &mut ServerState,
    chunk: Option<&Vec<RouteSnapshot>>,
    generation: u64,
    replace: bool,
    index: u32,
    total: u32,
    complete: bool,
) {
    // 1. Fence stale/reordered replaces exactly like #6034 (per-verb last-applied
    //    route generation; applied==false → eprintln + refresh_status + return).
    // 2. If replace && index==0: clear the LEARNED-route partition of the live FIB
    //    (config-derived routes untouched — gap-fill invariant: operator routes win).
    // 3. Validate + insert chunk into the learned partition via the same
    //    per-route path populate_routes uses (destination parse #6568, dedupe #3770).
    // 4. If complete: mark learned partition whole, set
    //    forwarding.learned_route_import_capped=false path (see §5c),
    //    bump fib_generation ONCE so flow-cache entries stamped under the
    //    pre-table pair invalidate exactly once per table, clear content_digest
    //    (#9520: stored snapshot no longer describes enforced routes), persist.
    // 5. refresh_status(guard) on every arm (success, fence, validation no-op).
}
```

Go sender (`pkg/dataplane/userspace/manager_routes_chunk.go`, new file):

```go
// buildLearnedRouteChunks splits the learned import into publishes each fitting
// BOTH ceilings: serialized body < MaxControlRequestBytes AND
// controlRoundtripDeadline(body) <= learnedRoutePublishBudget.
// First chunk sends RouteReplace=true + generation=nextRouteReplaceGen (new
// monotone counter seeded from status like neighborReplaceGen #6034);
// chunks carry index/total; last sets RouteChunkComplete=true.
// Each chunk uses requestLocked (advances partialUpdateEpoch #9684) and
// requires an ACK of (generation, index) in ProcessStatus before sending
// the next (stop-and-wait: preserves order without a reorder buffer).
// On transport failure (not in-band refusal): retain retry debt, do NOT
// mark complete, do NOT clear the capped flag; next status tick resumes
// from the first un-ACKed chunk.
```

Sizing: chunk by serialized estimate (`len(routes) * learnedRouteBytesEach` plus measured
base snapshot overhead) with a hard re-measure per chunk (`json.Marshal` length check before
send; shrink-and-retry if over). Target budget keeps each chunk's socket hold to a fraction of
the 10 s publish budget so the 1/s status poll, HA sync and session installs are never held
for seconds, let alone ~56 s.

FIB data structure: the learned partition MUST be separable from config routes at apply time.
Today `populate_routes` folds everything into one table set; the plan adds a learned-route
partition (or, minimally, a `learned: bool` tag per FIB entry + a learned-key index) so
replace-clear and chunk-append never disturb config routes. Exact shape (partition vs tag) is
the first implementation decision and must be nailed before code (see Q1).

### 5b. Fallback (if §5a is judged too large): kernel route lookup on miss, adjudicate-before-delegate

If reviewers kill §5a, the smaller half: on the NoRoute arm (slow path ONLY — never the hot
forward path), perform a synchronous kernel route lookup for the destination (helper-side
netlink `RTM_GETROUTE`, new `rtnetlink`-family dependency; or a Go-side oracle — rejected,
the miss is observed in the helper and a per-packet Go round trip reintroduces the socket-hold
problem), resolve the REAL egress ifindex → real to-zone, evaluate policy against the real
pair, delegate (reinject) only on Permit and downgrade to `PolicyDenied` otherwise. Genuinely
unroutable destinations still resolve NoRoute → today's #7480 path (default action decides).
This keeps the cap and the capped flag but removes the *unadjudicated* half: every delegated
frame carries a permit verdict against its real egress zone. Honest cost: new netlink
dependency in the helper, per-miss RTT (slow path only, but measurable under scan), TOCTOU
between lookup and reinject, table/VRF selection must match the kernel FIB exactly or the
"real" zone is wrong — each of which is a kill reason on its own (see §8, §11).

The two halves are ordered, not alternative-equal: land §5a if shippable; §5b only if §5a is
killed AND §5b survives its own review. Shipping both (chunked table + lookup for the residual
inter-push window) is explicitly deferred — it doubles the new mechanism for a window #7437
already narrowed to ~1–3 s.

### 5c. Cap removal (lands with whichever half ships)

- Go: `learnedRouteCapExceeded` stops declining the import; the full learned set flows through
  chunking (§5a) or the flag becomes advisory-only (§5b — capped + adjudicated, never capped +
  unadjudicated). `LearnedRouteCapHits` stays as a telemetry counter (reset semantics: counts
  refused publishes; post-fix it should read 0 — do NOT delete the symbol, #9172-adjacent
  callers may exist).
- Rust: `noroute_policy_denial_gated`'s early-`None` is deleted; the NoRoute arm calls
  `noroute_policy_denial` unconditionally (§5a) or the new real-zone adjudication (§5b).
  `ForwardingState.learned_route_import_capped` becomes always-false (§5a) or an advisory
  status bit (§5b); the wire bit stays decoded (skew tolerance for rolling upgrade) but stops
  gating the disposition. Protocol version stays at 10 (no new refusal semantics).
- The #9054 tests are updated, not deleted: `a_capped_import_delegates_noroute…` becomes the
  fail-on-revert cell asserting a full-table import NEVER delegates-despite-deny (i.e. capped
  miss ≡ uncapped miss), and the uncapped-deny control
  (`noroute_is_denied_on_a_default_deny_box_7480`) keeps passing untouched.

## 6. Public API preservation

Preserved verbatim (no signature changes):

- `noroute_policy_denial(policy, from, to, src, dst, proto, ports, icmp, len)` — semantics
  unchanged; the positive control.
- `apply_snapshot`, `bump_fib_generation`, `update_neighbors` verbs — untouched.
- `MaxControlRequestBytes` ↔ `MAX_CONTROL_REQUEST_BYTES` 64 MiB lockstep + reachable-deadline
  analysis (#7675) — untouched; chunking works UNDER both ceilings.
- `LearnedRouteCapHits()` — symbol retained (telemetry); post-fix expectation is 0 hits.
- `ProcessStatus.learned_route_import_capped` absence-is-unknown (#9654) — retained.
- New surface is purely additive: `update_routes` verb, `route_*` wire fields, one Go sender
  file, one Rust handler file, one status ACK field
  (`manager_route_generation`, mirroring `manager_neighbor_generation`).

## 7. Hidden invariants the change must preserve

1. **Single-recycle / slow-path ownership.** The NoRoute arm's terminal paths produce a
   `StageOutcome` consumed by the single push+continue site (#6432, #1327 split-borrow
   discipline). The adjudication change must not add a recycle, drop, or early `continue`.
2. **ONE authority for "may this reach the kernel" (#6664/#1913).** The arm evaluates, then
   downgrades to `PolicyDenied` and lets the trailing `slow_path_admit` chokepoint refuse.
   No second gate, no bypass around it — for EITHER half.
3. **Flow-cache pair-equality validity (#3767/#5169).** Cache entries are stamped
   `(config_generation, fib_generation)`. Chunk application must invalidate exactly once per
   completed table (fib bump on `complete`), never per chunk mid-table (would thrash the cache
   N times per publish) and never zero times (would revive stale permits — fail-open).
4. **Monotonicity + content-identity gates (#3767 H5, #9520).** The route verb needs the #6034
   stale-replace fence from day one; out-of-band route mutation MUST clear `content_digest`
   or a same-generation retry of the last full apply passes the identity gate against routes
   it no longer describes.
5. **Allocation discipline.** Hot forward path stays zero-alloc; chunk decode/validate/insert
   is cold control-socket work. No per-packet netlink (§5b: strictly slow-path NoRoute arm;
   a hot-path lookup is a revert-on-sight defect).
6. **Gap-fill precedence.** Config routes always win over learned for the same
   (table, family, canonical-destination). Chunk insert must apply the `covered` rule per
   route, not per chunk — a chunk boundary must never let a learned route sit beside the
   operator's route for one prefix.
7. **Control-socket sharing.** The socket is shared with the 1/s status poll, HA sync, session
   installs, snapshot sync and forwarding sync. Stop-and-wait chunking must bound each hold to
   well under the status period and yield between chunks; a chunked publish that holds the
   socket for 56 s in N slices is the same outage with better framing.
8. **Deterministic emission.** Learned order is canonicalised (table, family, destination,
   next-hops) so unchanged tables don't flap the FIB. Chunking must preserve the canonical
   order end-to-end (split the SORTED set; reassembled order ≡ sorted order) or every publish
   reinstalls the FIB.
9. **Serde skew.** All new wire fields `omitempty` (Go) / `#[serde(default)]` (Rust). Old
   helper ignores them; old control plane never sends them; first-refusal-sticky behaviour
   follows the #8121 precedent if a verb is refused.
10. ** HA/session-sync portability.** No new per-session wire state; route chunks carry only FIB
    content + generation envelope, so rolling upgrade and HA sync need no negotiation beyond
    the existing protocol-version gate.
11. **#9521 steered-port / #3292 / #4024 / #3110 interactions.** The NoRoute arm's flowless
    handling (`ports=None`, `l4_present=false`) and the unzoned-sentinel semantics stay as-is
    under §5a; under §5b the real-zone evaluation must still use the flowless closed-ports rule
    when there is no L4.

## 8. Risk assessment

| Class | Rating | Reason |
|---|---|---|
| Behavioral regression | HIGH | Touches the NoRoute→reinject disposition (the #6664/#7480/#9054 line) and adds a live FIB mutation path. Wrong chunk boundary, fence, or invalidation = blackhole (availability) or bypass (security). The #9054 composition history is exactly this class of mistake. |
| Lifetime / borrow-checker | LOW-MED | Handler follows the `neighbors.rs` shape (owned decode → resolved vec → single `&mut ServerState` apply). Risk concentrates in the FIB partition design (Q1): a tag-per-entry vs partition split changes borrow shape of the lookup path. Lookup path itself is read-only and unchanged under §5a. |
| Performance regression | MED | §5a: N control round trips per full-table publish + one FIB reinstall per completed table (not per chunk, by design). Inter-chunk yields keep the socket free but stretch convergence to ~N×RTT. §5b (if taken): per-miss netlink RTT on the slow path — bounded by miss rate, unbounded under scan. Either needs the loss-cluster matrix (§9), not reasoning. |
| Architectural mismatch (#961 / #946-Phase-2 dead-end) | MED | The risk this plan EXISTS to surface: is a stateful chunked verb with generation envelope, ACK, retry debt and FIB partitioning the right shape for "move a big table across a small socket", or does it replay the #946-Phase-2 mistake of building protocol machinery around a premise (full-table-in-helper-FIB) that the fallback (lookup-on-miss) shows is unnecessary? Q6 invites the kill on exactly these grounds. |

## 9. Test plan

- `cargo build` clean at every commit boundary (bisectable history, one logical unit per commit).
- `cargo test --release`: full suite green (952+ cells); most-affected named tests 5/5 flake check:
  - `noroute_is_denied_on_a_default_deny_box_7480` (positive control — must stay green untouched),
  - new `capped_miss_equals_uncapped_miss_9522` (fail-on-revert: full-table import present, deny
    box, NoRoute miss → `Some(deny)`; delete the chunking/mutation and it reds),
  - new chunk-handler cells (stale-generation fence, replace-clear preserves config routes,
    out-of-order chunk refused, partial table does NOT clear the capped bit / bump fib).
- `go test` affected packages (`pkg/dataplane/userspace/...`): chunk sizing cells (every chunk
  body `< MaxControlRequestBytes` AND `controlRoundtripDeadline(body) <= learnedRoutePublishBudget`),
  reassembly-equals-sorted-full-set, stop-and-wait retry-debt resumption, cap-unreachable cell
  (full 1M-route synthetic table chunks without a single `learnedRouteCapExceeded` refusal).
- Source guards updated in place (not deleted): the `slow_path_admit_single_site_6664.rs` NoRoute
  wiring guard and the #9054 composition cells keep covering the arm; the capped-delegates cell is
  rewritten as the §5c cell above.
- Loss-cluster smoke (REQUIRED — dataplane disposition changes): deploy, then v4+v6 ×
  push+reverse on 5201, multi-stream `-P 12 -R` reproducers, plus a full-table synthetic
  (or capped-fixture) run proving deny-policy traffic to a learned-only destination drops and
  permit-policy traffic to the same destination forwards — with `xpf_userspace_binding_slow_path_no_route_packets_total`
  and `LearnedRouteCapHits()` captured. Per-class CoS 5201-5206 matrix per the triple-review
  standing rules.
- NEVER fake numbers: every throughput/retrans figure in the PR body comes from a captured run.

## 10. Out of scope (explicitly)

- #9172 item 3 observability half (`ProcessStatus` capped field, `LearnedRouteCapHits` call
  sites). This plan deletes the STATE the signal would describe; the signal work stays separate.
- Raising `learnedRoutePublishBudget` or `MaxControlRequestBytes` (moves the cap, doesn't remove
  the cause; invalidates the #7675 reachable-bound analysis).
- Filtering what FRR installs into the kernel (operator remedy, already documented; not a fix).
- Combining §5a AND §5b in one PR (doubles the mechanism; the residual inter-push window stays
  on today's #7480 semantics until a follow-up says otherwise).
- Fail-closed-above-cap restoration (rejected by the issue and all three reviewers; not on the table).
- General FIB performance work (LPM, sharding, incremental withdraw beyond chunk replace).

## 11. Open questions for adversarial review

1. **Partition vs tag for the learned FIB slice?** Clearing "the learned partition" on
   `route_replace && index==0` needs learned routes to be separable from config routes at
   apply time. Is a hard partition (two table sets merged at lookup) or a per-entry tag +
   learned-key index the right shape — and does either change the lookup hot path's borrow or
   branch structure? If the answer is "neither composes with `populate_routes` cleanly",
   is that a PLAN-KILL for §5a?
2. **Per-chunk vs per-table flow-cache invalidation?** The plan bumps fib once on `complete`.
   During a multi-chunk publish the helper enforces a MIXED table (old tail + new head) under
   the old pair — is that window's forwarding correct, or must each chunk bump (N invalidations
   per publish)? If neither is clean, does chunking break the pair-equality contract?
3. **Is stop-and-wait chunking actually kinder to the socket than one 56 s hold?** N chunks ×
   (RTT + apply + status) still occupies the socket N times and stretches convergence to
   seconds-to-tens-of-seconds, during which the FIB is deliberately incomplete. Does the
   1/s status poll + session-install starvation analysis genuinely improve, or does chunking
   convert one long outage into a repeating short one? Numbers invited.
4. **What does the inter-chunk window adjudicate?** While chunks 1..k of N are applied, most
   learned destinations still resolve NoRoute. Under §5a semantics (strict #7480, no gate) the
   box drops-or-delegates per the DEFAULT action for the whole convergence window — is that a
   functional return of the #9054 blackhole in miniature, and does the plan need a
   "publishing" state distinct from both capped and whole?
5. **Should the fallback WIN — is the full table even needed in the helper?** §5b asks whether
   a per-miss kernel lookup (real egress zone → adjudicate → delegate-on-permit) closes the
   hole with one code path and no table-movement protocol at all. If the miss rate on a
   full-table box is low (established flows hit session/flow-cache; only first packets miss),
   is §5a over-engineering — PLAN-KILL §5a and ship §5b? What miss-rate measurement would
   decide this?
6. **Architectural mismatch (#961/#946-Phase-2)?** Is a stateful replace-generation-fenced,
   ACKed, retry-debt-carrying chunked route verb the kind of protocol machinery this tree has
   killed before at plan time — and does the existence of `update_neighbors` as "the pattern"
   actually transfer, given neighbors are ~hundreds of entries with clear-on-empty semantics
   while routes are ~10⁶ entries where clear-and-refill per publish is itself an outage?
   KILL is the expected answer if the analogy doesn't hold.
7. **VRF/table fidelity for §5b?** A kernel `RTM_GETROUTE` answer is only as good as the
   query's table selector, fwmark, iif and TOS. Can the helper reconstruct the kernel's exact
   routing decision from the descriptor metadata on the NoRoute arm — and if any of those
   inputs is unavailable, does the "real zone" become a guess that reintroduces the bypass
   through mis-zoning? Enumerate the required inputs or kill §5b.
