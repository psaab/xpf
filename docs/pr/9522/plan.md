# #9522 — Adjudicate-before-delegate on a NoRoute miss via kernel egress-zone lookup (Design A); chunked route transport deferred (Alternative B)

## 1. Status

DRAFT v2 — pending adversarial plan review (round 2). Supersedes v1 (commit `ee9b3d6`).

Round-1 record (raw outputs preserved under `docs/pr/9522/reviews/`):

- Codex Astra: **PLAN-KILL**, scoped — "kill the proposed live clear-and-refill architecture,
  not the issue or chunked transport itself." Required reset: stage an immutable replacement
  off the live view, validate, bind to config context, publish finished FIB + fresh validation
  pair together; abort leaves the previous complete view intact.
- GLM: **NEEDS-MAJOR**. Six required revisions (§5a must not proceed as specified; FIB data
  structure in scope or lower the target; single carrier; protocol version; Go-owned fib bump;
  re-plan §5b as the primary candidate with input enumeration and measured cost).

Both reviewers converged on two points this revision accepts outright: (1) v1's clear-at-chunk-0
live mutation is wrong (availability + invalidation), and (2) the kernel-lookup half must be
re-planned as the primary candidate because it plausibly closes the filed **security** hole
without moving 10⁶ routes. V2 does exactly that. V1's Q2 is acknowledged self-contradictory
("mixed table" vs specified clear — Astra F1/GLM F1 correct; the question described a different
design than §5a specified). V1's control-socket sharing paragraph is corrected below (session
sync has a dedicated socket and off-lock serve; the shared contention is the status poll under
the `ServerState` lock, snapshot/FIB bumps and HA updates), and `controlRoundtripDeadline` is
henceforth treated as a timeout allowance, never as a service-time measurement.

## 2. Issue framing

Unchanged from v1: above the #8355 derived import cap (64,956 routes), the daemon withholds the
entire learned import, `LearnedRouteImportCapped` is stamped, `noroute_policy_denial_gated`
returns `None`, and the NoRoute arm reinjects to `xpf-usp0` for Linux forwarding with no
zone-policy adjudication. STEP-0 evidence on base `7ef226474` stands (v1 §2; both round-1
reviewers re-verified the citations independently). Fail-closed-above-cap remains rejected
(#9054). Acceptance is unchanged: capped miss ≡ uncapped miss; permit traffic passes through an
explicitly adjudicated path; the uncapped-deny control keeps passing.

Reframing the cap (new in v2, forced by GLM F2): the runtime FIB lookup is a per-table linear
scan (`forwarding/fib.rs:428-431` — `routes.iter().find(...)` over longest-prefix-first vecs),
and a `NoRoute` verdict is NOT flow-cacheable (`flow_cache_tests.rs:1570-1592`). Every
delegated permit packet therefore pays a full scan per packet (delegated flows never sessionize,
so nothing caches them). The ~65k cap is currently an *accidental bound* on that scan. V2 keeps
a bound on helper-FIB size deliberately — restated honestly as a lookup-performance bound, not
as a socket-hold accident — while removing the *unadjudicated* half of the capped state. The
cap stops being the cause of a bypass and starts being a documented scan ceiling.

## 3. Honest scope / value framing

Security fix, no throughput win claimed. The win: a full-table box stops transiting
deny-policy traffic with no decision, without moving 10⁶ routes into a linearly-scanned FIB
and without a new multi-message control transaction. The cost: a helper-side synchronous
kernel route query on the NoRoute slow path (bounded by a zone-answer cache + rate limits),
plus a bounded FIB-scan measurement gate that decides whether any future table-growth work
(Alternative B) is even admissible.

*If reviewers conclude the kernel-lookup fidelity enumeration (§5) has a hole that fails open,
or that the per-miss cost under scan is unbounded in a way the rate limits cannot contain,
PLAN-KILL is an acceptable verdict. If reviewers conclude Alternative B's fast-path value
justifies its mechanism despite §5, promoting B and killing A is likewise acceptable — but
shipping both halves in one PR is not on the table.*

## 4. What's already shipped / partially batched

V1 §4 stands in full (#7480 cells, #8355 cap + counter, #9054 gate + composition cells,
`update_neighbors` envelope idioms #5864/#6034/#9520/#9684, route-only overlay + `bump_fib`,
#7409 gap-fill, #7437 coalesced republish, #9654 absence-is-unknown). Additions verified during
round-1 follow-up (all read at head, not inferred):

- Publication shape: `Coordinator::publish_runtime_view` clones the full `ForwardingState` and
  rotates the worker-visible `Arc` (`coordinator/mod.rs:1590-1598`); neighbor pushes already pay
  this per push (mod.rs:757-768). Any per-chunk live FIB mutation would pay it per chunk —
  one more reason v1 §5a is dead.
- Neighbor atomicity: `bulk_replace_neighbors` under a single bulk acquisition — readers see
  pre- or post-replace, never half (`coordinator/mod.rs:736-748`). The property v1 §5a
  discarded; Design A needs none of it (no FIB mutation at all).
- Unknown verb refusal: `handlers/mod.rs:360-363` (`unknown request type` → `ok:false`). Any
  future verb is loudly refused by old helpers — the safe direction. (Design A adds NO verb.)
- FIB generation ownership: values come from the BPF shim map (`manager_generation.go:10-23`
  `readFIBGeneration`); helper self-advance would desync Go stamps and wedge on the `<` fence
  (`handlers/snapshot.rs:505-534`, #1844). Design A needs NO generation change.
- Coalescing bounds: debounce 1 s / throttle 3 s / actuate timeout 30 s
  (`pkg/coalesce/coalesce.go`, `daemon_route_listener.go:actuateLearnedRouteRefresh`). Any
  multi-second transfer must converge inside the 30 s actuate budget or it retry-loops.
- Resolver precedent: a single shared `NeighborResolver` thread serves all workers'
  single-key `RTM_GETNEIGH` misses with a 1 s per-key rate limit inside a 3 s negative TTL
  (`afxdp/neighbor_resolver.rs`, `neg_neigh.rs`, `mod.rs:1410-1414`). Design A follows this
  shape where it fits and says explicitly where it does not (§5).
- Miss-site context (verified in scope, see §5): `meta.routing_table: u32` (XDP-stamped table
  selector, `afxdp/types/mod.rs:132`), the PBR `route_table_override` and
  `effective_resolution_target` in the session-miss arm (`poll_descriptor/mod.rs:1771-1798`),
  `meta.ingress_ifindex`/`ingress_vlan_id`, `meta.dscp`, and the flow's src/dst addrs + ports.

## 5. Concrete design — Design A (primary): real-egress-zone adjudication on the NoRoute slow path

No wire change. No new verb. No FIB mutation. No generation change. No protocol bump (see §5e
for why none is needed). The `LearnedRouteImportCapped` bit keeps its exact current meaning
("the helper FIB is deliberately incomplete") and its status/telemetry path; it stops being
the condition for *unadjudicated* delegation because delegation itself becomes adjudicated.

### 5a. The query and its exact inputs

On the NoRoute arm — slow path only, after the existing L3-identity derivation and before the
`noroute_policy_denial_gated` call site — resolve the kernel's egress for THIS packet and
adjudicate against the real pair:

```
inputs (all in scope at the arm today):
  dst            = adj_flow.dst_ip                      (attacker's destination — the lookup key)
  src            = adj_flow.src_ip                      (source-specific policy rules)
  table          = route_table_override                 (PBR `then routing-instance`, when set)
                     else table derived from meta.routing_table + ingress routing domain
  iif            = logical ingress ifindex              (resolve_ingress_logical_ifindex — MUST be
                     passed explicitly: post-reinject the kernel sees xpf-usp0, so an iif-
                     matching rule evaluated at reinject time would decide differently)
  tos            = meta.dscp-derived TOS                 (ip-rule tos selector)
  proto/ports    = meta.protocol + flow ports where present (port-bearing rules, where the
                     kernel consults them; flowless uses the existing closed-ports rule)
```

The lookup is `RTM_GETROUTE` with the above selectors — i.e. the same decision the kernel will
make milliseconds later at reinject, computed BEFORE the policy verdict instead of after the
forward. On success it yields the egress ifindex → `egress_zone_id` via the existing
`ifindex_to_zone_id` map → evaluate with the real `(from_zone, to_zone)` pair using the
existing flow-backed / flowless port rules verbatim. Permit → delegate (reinject exactly as
today, with the verdict now explicit); non-Permit → downgrade to `PolicyDenied` through the
existing #1913 chokepoint (single-recycle and trailing-admit invariants untouched).

### 5b. Every indeterminate case falls back to today's #7480 sentinel path — never to delegation

The lookup is allowed to answer "I don't know", and every such answer takes the EXACT current
uncapped path (`noroute_policy_denial` against the #3110 unzoned sentinel → default action).
Indeterminate cases (enumerated; each gets a named counter):

- kernel reports no route (genuinely unroutable — the common uncapped case, behavior identical);
- multipath answers whose nexthops resolve to DIFFERENT zones (zone-ambiguous; same-zone ECMP
  adjudicates normally);
- non-unicast results (multicast/broadcast/local-table oddities);
- snapshot-attested complex policy routing (§5d) that the helper cannot reproduce;
- resolver thread down, rate-limit overflow, or lookup timeout (fail-closed to sentinel path).

There is no third outcome. "Delegate without a verdict" ceases to exist in the tree: the gated
early-`None` is deleted and the type-level shape becomes
`resolve_real_egress(...) -> Option<ifindex>` feeding the unchanged evaluator. The rewritten
#9054 cell asserts capped-miss ≡ uncapped-miss by construction (same function, same fallback).

### 5c. Cost containment: zone-answer cache + rate limits, policy re-evaluated per packet

A synchronous worker-side `GETROUTE` per NoRoute packet is unbounded under scan (distinct dsts
never hit anything, and NoRoute is uncacheable at the flow layer). Containment, three layers:

1. **Zone-answer cache (new, small, bounded):** key `(table-selector, dst, src-class, tos)` →
   `(egress_ifindex, zone, expires)`. Caches ONLY the zone answer, NEVER the policy verdict:
   policy is re-evaluated per packet against fresh policy tables (cheap — policy tables are
   small; correctness does not depend on cache coherence for config changes). TTL short
   (1–3 s, the `neg_neigh` 3 s precedent); hard entry cap with expired-first/oldest reclaim
   (the #6905 discipline); cleared on every FIB publish (fib_generation change — free coherence
   with the existing pair, no new epoch).
2. **Staleness bound, disclosed:** a cached zone may lag a route change by at most the TTL.
   This is the same TOCTOU class as kernel forwarding itself (lookup-to-reinject race is
   µs–ms; a change landing inside it forwards one packet under the just-withdrawn route with
   a verdict computed against the real zone at decision time — not a bypass). The TTL is the
   bound; the plan does not claim zero.
3. **Rate limit with loud fail-closed overflow:** per-worker in-flight cap + global per-second
   ceiling on kernel queries; overflow takes the sentinel path and bumps a dedicated counter
   (indistinguishable from "unroutable" in disposition, distinguishable in telemetry — the
   #9172-adjacent signal without claiming #9172).

Sync-vs-thread (decision, reviewers invited to overturn): the query runs SYNCHRONOUSLY in the
worker slow path, not via the #1769 shared-thread shape. Rationale: async would leave THIS
packet without a verdict — forcing a first-packet sentinel verdict (a miniature of the rejected
posture hole for every new flow) or a buffer-and-revisit path with its own ordering hazards.
Slow-path-only keeps it off the hot forward path; the cache keeps the steady-state cost at one
hash lookup for repeated dsts. Measured RTT gates this choice (§9): if p99 synchronous RTT
exceeds the slow-path budget, the design falls back to the thread shape with an explicit
first-packet rule, as a documented revision — not a silent optimization.

### 5d. Capability-scoped activation (the anti-F4 device)

Go already enumerates the kernel ip-rule set for leak-route synthesis (#3772 M9 surface). At
snapshot build it additionally attests one additive bool,
`complex_policy_routing: true`, when ANY rule uses a selector the helper cannot reproduce
(mark-based rules — meta carries no mark — `l3mdev` nuances beyond the table selector, or any
future selector outside §5a's list). While set, the arm uses the sentinel path (today's uncapped
behavior) and counts it. This bounds the fidelity claim positively: Design A activates exactly
where its inputs are complete, and says which selector killed it everywhere else. The attested
set is conservative by construction (unknown selector ⇒ attest complex).

### 5e. Version-skew matrix (no bump required — demonstrated, not asserted)

- New helper + old sender, above cap: sender withholds as today; helper's lookup succeeds from
  the kernel and adjudicates with the real zone. Permit delegates, deny drops. NO blackhole —
  the blackhole required adjudication against the unzoned sentinel, which is now only the
  fallback. Strictly better than today in this pairing.
- New helper + old sender, below cap / uncapped: identical to today plus lookup refinement for
  genuine misses (lookup fails → sentinel path, byte-identical verdicts).
- Old helper + new sender: impossible — Design A sends nothing new. There is no new sender.
  This is the structural reason no `update_routes`-style capability negotiation exists: nothing
  to negotiate.
- Hence no `CONFIG_SNAPSHOT_PROTOCOL_VERSION` change: v10's refusal semantics are untouched,
  and the tree's version doctrine (no semantic redefinition under a shared version) is
  satisfied because the *meaning* of the capped bit ("FIB deliberately incomplete") does not
  change — only the disposition of a frame it describes, which is helper-local behavior.

### 5f. Alternative B (deferred, sketched to round-1's reset — NOT this PR)

Chunked learned-route transport survives ONLY in the stage-off-live-view form both reviewers
mandated: Go chunks the sorted learned set; the helper stages into an/off-live partition;
completeness + content identity validated; bound to the config/interface context present at
transfer start (abort/rebase on change); atomic swap + single Go-owned fib bump
(complete-ACK → Go bumps shim → existing `bump_fib_generation`) + `content_digest` handling at
swap; supersede/restart/empty/replay/total-mismatch rules; snapshots exclude learned once the
verb is negotiated (single carrier, v11); `partial_update_outcome_9684` section types extended.
PREREQUISITE GATE (GLM F2): bounded FIB-scan measurement at 65k/250k/500k/1M miss-path pps —
without an LPM answer (trie for the route maps, or learned-partition trie with a defined
cross-partition LPM rule), activation above the current bound is refused and B stays a
follow-up workstream. B's marginal value over A is fast-path throughput for learned
destinations — a performance goal outside #9522's acceptance — so B waits regardless of
mechanism elegance.

## 6. Public API preservation

Preserved verbatim: `noroute_policy_denial` (semantics + signature — the fallback and the
positive control); `apply_snapshot`, `bump_fib_generation`, `update_neighbors`;
`MaxControlRequestBytes` ↔ `MAX_CONTROL_REQUEST_BYTES` lockstep + #7675 analysis;
`LearnedRouteCapHits()` (still counts withheld publishes — now WITH an adjudicated delegation,
so the counter keeps meaning "FIB incomplete", never "bypass active");
`ProcessStatus.learned_route_import_capped` absence-is-unknown (#9654); the #1913 chokepoint
and single-recycle discipline. Deleted: only the `learned_route_import_capped` early-`None` in
`noroute_policy_denial_gated` (the gate collapses into the §5b fallback type). Added: one
helper-local resolver (query + zone cache + counters), one Go attestation bool
(`complex_policy_routing`, additive `omitempty`/`#[serde(default)]`), named telemetry counters.
No verb, no generation, no version change.

## 7. Hidden invariants the change must preserve

1. **Single-recycle / slow-path ownership (#6432, #1327):** the arm still evaluates, then
   downgrades to `PolicyDenied`, then falls to the single admit site. No new recycle, no new
   reinject call site — the query result NEVER routes around the chokepoint.
2. **ONE authority for "may this reach the kernel" (#6664/#1913):** unchanged; §5b only changes
   what zone pair the evaluation asks about.
3. **Flow-cache pair-equality (#3767/#5169):** no FIB mutation ⇒ no invalidation question at
   all. The zone cache is NOT flow state and is cleared on FIB publish; it can neither revive a
   stale ALLOW (it never produces one — verdicts are per-packet) nor suppress one.
4. **Monotonicity / content-identity (#3767 H5, #9520, #6034):** untouched — no generation, no
   digest interaction, no new verb to fence. The attestation bool rides the existing snapshot
   content it describes.
5. **Allocation discipline:** hot path unchanged; query + cache consult live strictly in the
   NoRoute slow arm. Cache entries are fixed-size, pre-capped, pool-free.
6. **Gap-fill precedence:** untouched — decided Go-side at build time as today; the helper
   learns nothing new about precedence.
7. **Control-socket sharing (corrected):** Design A emits ZERO new control traffic — no
   socket-hold question exists. `sync_session`'s dedicated socket/off-lock serve is now
   correctly excluded from the sharing claim; remaining shared contention (status poll,
   bumps, HA updates) is unaffected by this plan.
8. **Determinism:** kernel answers are inherently unordered across multipath; the determinism
   rule is "same-zone ECMP ⇒ same verdict; cross-zone ⇒ sentinel fallback", pinned by cells.
9. **Serde skew:** one additive bool, both directions defaulted. Old helper ignores it (stays
   on today's behavior — the documented posture, unchanged); old sender omits it (helper treats
   absent as complex ⇒ sentinel path — fail-closed direction).
10. **HA/session portability:** no new per-session wire state; zone cache is per-worker RAM,
    rebuilt lazily, never synced.
11. **Flowless + #3110 interactions (#3291/#4024/#3110/#9529):** the real-zone evaluation keeps
    the flow-backed vs flowless port rules verbatim; the sentinel fallback keeps today's
    unzoned semantics byte-identical. A real zone of 0 (unmapped egress ifindex) is treated as
    indeterminate ⇒ sentinel path, never as a novel third zone semantic.

## 8. Risk assessment

| Class | Rating | Reason |
|---|---|---|
| Behavioral regression | MED-HIGH | Same security-sensitive arm (#6664/#7480/#9054 line), but the change narrows the question the arm asks (which zone pair?) without touching disposition plumbing, FIB content, or publish ordering. Wrong-zone answers are the failure mode; §5b's closed fallback list + §5d attestation bound it. The #9054 composition history keeps this above MEDIUM regardless. |
| Lifetime / borrow-checker | LOW | Query context borrows existing arm locals; zone cache is a plain bounded map owned by the worker/binding struct it serves. No `Arc` rotation, no cross-thread FIB sharing beyond what exists. |
| Performance regression | MED | Steady state adds one bounded-hash consult per NoRoute packet (cache hit) — negligible. Miss cost is one synchronous netlink RTT, rate-limited, slow-path-only. Residual risks: scan-storm pps for permit-delegated flows (pre-existing at cap scale, unchanged by A — quantified in §9 rather than hand-waved), and p99 RTT gating the sync-vs-thread choice. |
| Architectural mismatch (#961 / #946-Phase-2) | LOW | Design A follows in-tree precedent instead of inventing mechanism: #1769's resolver shape for kernel queries, #1651's negative-cache TTL/cap discipline, the arm's evaluate-then-downgrade convention. No new protocol, no stateful transaction, nothing to fence. |

## 9. Test plan

- `cargo build` clean at every commit boundary; logical bisectable commits (resolver → arm
  wiring → attestation → counters → test-only commits separate).
- `cargo test --release` full suite green; 5/5 flake on the affected cells:
  - `noroute_is_denied_on_a_default_deny_box_7480` — untouched positive control;
  - NEW `capped_miss_equals_uncapped_miss_9522` (fail-on-revert: capped snapshot + deny box +
    learned-only dst with kernel route in a DENY pair → `Some(deny)`; delete the lookup call
    and it reds — the exact master behavior);
  - NEW real-zone cells: permit-pair delegates with verdict recorded; genuinely-unroutable
    falls to sentinel (default decides); cross-zone multipath fails closed to sentinel;
    unmapped-egress-ifindex ⇒ sentinel; flowless closed-ports preserved under real zones;
    complex-attestation set ⇒ sentinel path + counter.
  - NEW cache cells: zone-answer TTL expiry, cap reclaim discipline, clear-on-FIB-publish,
    verdict-never-cached (config policy change between two packets with hot cache entry
    changes the verdict).
- Measurement gates (numbers in the PR, never asserted):
  - FIB linear-scan cost at 65k/250k/500k/1M routes (microbench miss-path ns + loss-cluster
    NoRoute pps) — documents the scan bound §2 claims and gates Alternative B;
  - synchronous `GETROUTE` RTT p50/p99 on the slow path (gates sync-vs-thread, §5c);
  - NoRoute-miss pps under full-table synthetic + scan (sizes the rate limits, §5c).
- `go test` affected packages: attestation cell (mark-rule config ⇒ complex=true; ordinary
  rules ⇒ false; enumeration failure ⇒ complex=true — fail-closed), plus the untouched cap
  derivation cells as regression.
- Source guards updated in place: `slow_path_admit_single_site_6664.rs` NoRoute wiring guard
  extended to the lookup call (a deleted lookup must red it); #9054 composition cells rewritten
  as the §5b equivalence cell, not deleted.
- Loss-cluster smoke (REQUIRED — disposition changes): deploy; v4+v6 × push+reverse on 5201;
  `-P 12 -R` reproducers; full-table synthetic run — deny-pair learned-only dst DROPS,
  permit-pair learned-only dst FORWARDS with verdict telemetry;
  `xpf_userspace_binding_slow_path_no_route_packets_total` + new lookup/ambiguity/fallback
  counters + `LearnedRouteCapHits()` captured. Per-class CoS 5201-5206 matrix per standing
  rules. NEVER faked: every figure from a captured run.

## 10. Out of scope (explicitly)

- #9172 item 3 observability (still separate; this plan only adds the minimal counters its own
  fallback list needs to be distinguishable).
- Alternative B implementation (follow-up workstream, gated on the §9 scan measurements + LPM).
- Raising `learnedRoutePublishBudget` / `MaxControlRequestBytes` (untouched).
- FRR-side table filtering (operator remedy, documented, unchanged).
- Fail-closed-above-cap (rejected; not on the table).
- General FIB LPM work (measurement-gated prerequisite of B, not of A).

## 11. Open questions for adversarial review

1. **Is the §5a input list complete against real `ip rule` selectors?** Enumerate any kernel
   selector beyond (dst, src, table, iif, tos, proto/ports) that can change a `GETROUTE` answer
   on a supported topology (nftables-derived marks? `l3mdev` master-index subtleties? realm?
   `ip rule ... uidrange`?). Each missing input is either a §5d attestation addition or a
   PLAN-KILL of Design A — no middle ground is acceptable for a security adjudication.
2. **Does synchronous netlink in the worker slow path hold up under adversarial miss rates?**
   A scan across distinct unroutable dsts pays full linear-scan + failed lookup per packet with
   nothing cacheable. Is the §5c rate limit + sentinel-fallback sufficient, or does this need a
   negative-zone cache (with its own staleness analysis) to avoid a slow-path pps collapse that
   reads as an availability regression? Numbers invited; "slow path is rare" is not evidence.
3. **Is caching the zone answer but not the verdict the right split?** It re-evaluates policy
   per packet (correct under config change, costs policy-eval per NoRoute packet). Should
   instead the VERDICT be cached with the policy generation stamped (invalidated by the #8356
   re-derivation generation already published per pass)? Which coherence story is actually
   tighter — argue for flipping it.
4. **Cross-zone multipath fails closed to the sentinel — but is SILENT fallback correct there?**
   A same-prefix ECMP across zones with a deny default drops traffic the operator's
   per-zone permits would have allowed on whichever member the kernel picked. Should the
   fallback instead be loud (per-prefix counter + log) or even a distinct disposition? And does
   the kernel's own hash choice vs the helper's ignorance of it constitute a determinism hole
   worth killing over?
5. **Is the TOCTOU bound honestly stated?** Lookup-to-reinject is µs–ms, but the ZONE CACHE
   extends the window to the TTL (seconds). A route withdrawal inside the TTL forwards
   permitted packets toward a dead/changed egress. The plan claims this matches kernel
   behavior — does it, or does the kernel's synchronous FIB make this strictly weaker in a way
   that matters for a deny that arrived 2 s ago? Quantify or kill the TTL length.
6. **Should Alternative B die entirely rather than wait?** If Design A closes the filed hole
   and B's only marginal value is fast-path throughput (perf, outside this issue), is keeping B
   sketched an invitation to rebuild the v1 mechanism later — i.e. should v2 delete §5f and let
   any future fast-path work justify itself from zero? KILL-B is an acceptable verdict.
7. **Does §5e's no-bump argument survive a hostile reading of the version doctrine?** The
   capped bit's *described meaning* stays fixed, but its *operational consequence* (delegate
   vs adjudicate) changes under every old sender. Is "helper-local behavior needs no version"
   actually consistent with the v9 lesson (same bytes read differently), or does the
   new-helper+old-sender pairing deserve a loud status-level signal (not refusal) so an
   operator watching `LearnedRouteImportCapped=true` understands delegation is now adjudicated?
   (Note: this overlaps #9172 without claiming it.)
