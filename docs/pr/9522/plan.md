# #9522 — Adjudicate-before-delegate on a NoRoute miss via reinject-mirror kernel lookup (Design A v3); chunked transport a gated future pointer

## 1. Status

DRAFT v3 — pending adversarial plan review (round 3, final). Supersedes v2 (`e2b4724f`).

Round-2 record (raw outputs preserved under `docs/pr/9522/reviews/`):

- Codex Astra: **PLAN-KILL**, scoped to Design A as specified — "the replacement architecture
  still does not establish that the zone authorized is the zone Linux actually forwards into."
  Four blockers: (1) query uses origin-ingress context while forwarding uses the reinject
  context; (2) cache key drops security-relevant inputs; (3) TTL ≠ forwarding parity;
  (4) sentinel fallback is neither universally fail-closed nor availability-preserving; plus
  attestation incompleteness, the `omitempty`-vs-absence encoding contradiction, sync-lookup
  budget, and "defer B, do not approve its sketch".
- GLM: **NEEDS-MAJOR**, with determined fixes for each: rewrite §5a as reinject-mirror
  (fewer inputs, not more), restore the capped gate as the fallback condition, make §5d
  enumerable-and-conservative with a named reader, specify multipath/negative-cache/TOCTOU/
  scan-gate, strip §5f to prerequisites + pointer.

V3 accepts every load-bearing point from both reviews. The three MAJORs change the design's
fidelity target (F-A), its fail direction (F-B) and its attestation surface (F-C); each fix
makes §5 strictly *simpler* — fewer lookup inputs, one restored fallback condition, one
hardened reader. V2's `omitempty`-vs-absence contradiction (Astra blocker 6 / GLM F-B) is
acknowledged as a genuine spec bug and fixed by tri-state encoding with absent ⇒ legacy
behavior verbatim. V2's "no third outcome" (v2 §5b) is retracted as overreach.

## 2. Issue framing

Unchanged: above the #8355 cap the daemon withholds the learned import, the gated early-`None`
delegates every `NoRoute` frame unadjudicated, and a full Internet table reaches the cap.
STEP-0 on base `7ef226474` stands (both reviewer generations re-verified it independently).
Fail-closed-above-cap remains rejected (#9054). The cap stays restated as a documented
linear-scan bound (`forwarding/fib.rs:428-431`; NoRoute uncacheable).

Acceptance, restated honestly after F-B (this replaces v2's unconditional form): for the
**determinate class** — kernel can route AND the rule set is helper-reproducible — a capped
miss and an uncapped miss produce the SAME adjudicated result, and permit traffic passes
through an explicitly adjudicated path. For the **indeterminate class** (no kernel route,
unreproducible rules, resolver failure/overflow) the plan preserves TODAY's posture loudly
(capped ⇒ counted delegation as on master; uncapped ⇒ sentinel path as on master) — improved
only by counters and a status signal, not by a verdict change. The uncapped-deny positive
control keeps passing untouched. What v3 refuses to promise: identical results where the helper
cannot determine the zone. That refusal is the F-B fix.

## 3. Honest scope / value framing

Security fix, no throughput win. The win: on a full-table box with ordinary rules, deny-policy
traffic to learned destinations stops transiting with no decision — without moving 10⁶ routes,
without a new verb, without FIB mutation. The residual: capped + indeterminate + default-deny
still delegates (today's posture, now counted and status-signalled). The scan-bound caveat
(F-G): delegated permit pps is ALREADY scan-bounded on master at cap scale; v3 does not move
that ceiling and the PR states measured permit throughput rather than asserting it.

*If reviewers conclude the reinject-mirror contract (§5a) still has a fidelity hole that fails
open, or that the indeterminate-class residual is the issue's core rather than its edge,
PLAN-KILL is an acceptable verdict. KILL-B (deleting §5f entirely) is likewise acceptable.*

## 4. What's already shipped / partially batched

V2 §4 stands in full; the round-2 follow-up verified three more load-bearing facts (read at
head):

- **The reinject context is MAIN, provably.** `tests_fragment.rs:826-841` (#7409 second
  vector): a PBR-steered NoRoute frame is reinjected and "the kernel ... resolves it in the
  MAIN table and forwards it down the very path the operator steered it away from" — because
  `BuildPBRRules` deliberately drops unrepresentable terms from the kernel mirror. Any query
  that reproduces *operator intent* (origin iif, forced PBR table) therefore authorizes a zone
  the kernel will never forward into. The ONLY coherent fidelity target is the kernel's
  post-reinject RPDB walk. This single fact kills v2 §5a and dictates v3 §5a.
- **iif-scoped rules exist in-tree.** Next-table leak rules are scoped to the authoring
  instance's ingress ifaces (#9420, `pkg/routing/rules.go`); PBR mirrors ride band
  31000–31999 (`pbrRulePriority`). An origin-iif query matches rules the reinject walk never
  evaluates — F-A's third data point, confirmed.
- **The tree's own DSCP-blindness precedent + remedy.** `rule_dscp_kernel_7796_test.go:108-112`:
  "netlink's own RuleList cannot be used as the reader here: the library has no FRA_DSCP
  support at all ... it would silently report every rule as having no DSCP" — and the fix
  uses iproute2 `ip` as an INDEPENDENT reader. V3 names exactly this reader for attestation.
- **TUN identity + metrics docs.** `DEFAULT_SLOW_PATH_TUN = "xpf-usp0"`
  (`afxdp/mod.rs:445`); reinject-path metric descriptors live in
  `pkg/api/metrics_descriptors_binding.go`.

## 5. Concrete design — Design A v3 (primary and only half in this PR)

### 5a. The query: mirror the reinject walk, not the operator's intent (rewrites v2 §5a)

On the NoRoute arm — slow path only, after L3-identity derivation — issue `RTM_GETROUTE` with
the context the kernel will have MILLISECONDS LATER at reinject:

```
dst    = adj_flow.dst_ip            (the lookup key)
src    = adj_flow.src_ip            (source-specific rules; forwarded => same src both sides)
iif    = xpf-usp0 ifindex           (DEFAULT_SLOW_PATH_TUN; the device the reinject arrives on.
                                     NOT the origin ingress — v2's inversion, fixed.)
mark   = 0                          (a TUN write carries no mark on either side)
uid    = INVALID (overflowuid)      (forwarded packets carry no socket on either side, so
                                     uidrange rules are inert for this path on BOTH sides —
                                     no divergence to attest, stated not assumed)
tos    = packet TOS                 (FRA_DSCP-relevant rules; input, not attested)
proto/ports = meta.protocol + flow ports where present (flowless: closed-ports rule verbatim)
table  = NONE FORCED                (ordinary RPDB traversal from the above context — v2's
                                     mode contradiction fixed by deleting the second mode.
                                     route_table_override and meta.routing_table are NOT
                                     lookup inputs; the #7409 vector proves the kernel
                                     ignores them at reinject.)
```

The answer is the egress ifindex the kernel WILL select → existing `ifindex_to_zone_id` map →
evaluate the real pair with the flow-backed/flowless port rules verbatim. Permit → delegate
(reinject exactly as today, verdict now explicit); non-Permit → `PolicyDenied` via the existing
chokepoint. Unmapped egress ifindex (0) ⇒ indeterminate ⇒ §5b fallback.

Why this is exact rather than approximate: same rule engine, same packet context, same
multipath hash inputs (the helper passes the identical tuple, so flowi-hash selection picks
the SAME member the reinject walk will pick — F-D resolved to adjudicate-selected-member; the
FIB_MATCH full-member enumeration is deleted as unnecessary). The §9 suite pins it with the
PBR-disagreement cell: PBR table says zone X, MAIN says zone Y ⇒ adjudicates Y (the #7409
vector AS the contract), plus a hash-parity cell (same tuple twice ⇒ same member; documents
the iif-participation check — mirror mode matches regardless since iif is equal both sides).

Remaining divergence sources, stated (not hand-waved): (i) TOCTOU between query and reinject
(§5c); (ii) selectors outside the list — each is either proven-inert (uidrange, oif-rules
which never match a forward lookup) or attested (§5d). Any NEW selector family discovered in
review is attestation-or-KILL per Q1.

### 5b. Fallback: the capped gate survives as the fallback condition (F-B fix; retracts "no third outcome")

```
lookup success      (either capped state)  → real-zone adjudication (§5a)
indeterminate + capped                     → TODAY's gated delegation (counted, status-visible)
indeterminate + uncapped                   → TODAY's sentinel path (byte-identical to master)
```

Indeterminate = kernel-no-route, attested-complex (§5d), resolver down/overflow/timeout,
unmapped egress, (deleted: cross-zone-multipath — F-D makes it determinate). "Delegate without
a verdict" therefore survives ONLY as the bounded capped fallback — strictly no worse than
master in every pairing, and the old-sender pairing (every deployment at rollout) is
byte-identical to today with NO blackhole and NO claimed improvement (rewrites v2 §5e row 1
honestly). The `noroute_policy_denial_gated` early-`None` is KEPT for exactly this fallback
and loses its "temporary" framing: it is the named, counted, status-signalled capped-fallback
condition. The rewritten #9054 cell asserts the determinate equivalence AND the fallback
preservation (capped+complex+deny ⇒ delegates as on master — pins the residual so no future
change silently "fixes" it into a blackhole).

Default-permit/indeterminate is now specified, not elided (Astra blocker 4): indeterminate
evaluates the default action — permit ⇒ delegates (real-pair denials NOT enforced in this
class; the counter + status signal say so), deny ⇒ drops. The test matrix gains the
default-permit/explicit-pair-deny indeterminate cell asserting delegation-with-signal (the
documented residual, pinned against silent drift in EITHER direction).

### 5c. Cost containment: full-key zone cache + negative entries + bounded sync query

- **Cache key = (dst, src, tos, proto, ports) exact.** No `src-class` (term deleted), no
  dropped inputs: iif/mark are fixed constants (excluded by construction, documented), domain
  is excluded because the mirror walk is domain-independent (RPDB from TUN — stated with the
  §9 domain-independence cell). Routing-distinct packets cannot share an entry by construction.
- **Negative entries** ("kernel has no route either", F-E): same TTL/cap/clear discipline, so
  the distinct-dst unroutable scan costs one cached lookup per key, mirroring `neg_neigh`.
- **Sync query, bounded:** per-worker netlink socket, hard recv deadline (numeric budget in
  §9, not "p99"), per-worker in-flight cap (1: a worker never pipelines queries), global
  per-second ceiling; overflow ⇒ indeterminate ⇒ §5b fallback + dedicated counter. Slow-path
  only; the hot forward path is untouched.
- **Verdicts never cached** (GLM Q3 answered with the stronger argument: the arm ALREADY
  evaluates policy per packet on master — `poll_descriptor/mod.rs:5236+` — so verdict-freshness
  costs nothing versus master, while a verdict cache would invent a third generation-coupled
  cache for zero gain). Zone answers: TTL ≤ 3 s, hard entry cap with expired-first/oldest
  reclaim (#6905 discipline), cleared on every FIB publish.
- **TOCTOU, honestly split** (F-F rewrite): withdrawal-inside-TTL ⇒ kernel drops at reinject
  (availability blip ≤ TTL, NOT a bypass); change-inside-TTL to a deny-pair egress ⇒ bounded
  transient residual ≤ TTL — same order as the standing inter-push residual the arm already
  documents (1 s/3 s coalescing), strictly narrower than today's unbounded capped window.
  Rule-set changes arrive via commit (new snapshot ⇒ new attestation ⇒ FIB publish ⇒ cache
  clear); out-of-band kernel rule edits are outside the supported topology (stated).

### 5d. Attestation: iproute2 readback as the presence reader (F-C fix)

Go's attestation is computed from an **iproute2 `ip rule list` readback** (the #7796 remedy:
independent reader, not `netlink.RuleList`, which is proven blind to `FRA_DSCP`) — or,
equivalently, a raw `FRA_*` attribute-presence parse. The plan mandates ONE of the two (Go
names it in the commit) under the conservative rule: any rule carrying a selector outside
§5a's list (mark/mask, uidrange, v6 flowlabel, tun_id, l3mdev forms beyond TUN-consistent,
inversion/goto/suppression constructs the reader cannot reduce to canonical xpf-emitted
shapes) ⇒ `complex=true`. Encoding (contradiction fixed): `ComplexPolicyRouting *bool`
tri-state — **absent (old sender) ⇒ legacy behavior verbatim** (no lookup attempted; capped
gate as on master in both states), `Some(true)` ⇒ sentinel/capped-gate fallback,
`Some(false)` ⇒ lookup eligible. Old helper ignores the field ⇒ today's behavior. No pair
enters a NEW unsafe state in either mixed direction; no version change (additive field,
absent = legacy — consistent with the v10 two-question test).

### 5e. Skew matrix (rewritten; the no-bump claim now holds)

- New helper + old sender (all rollout pairs): absent attestation ⇒ legacy behavior,
  byte-identical to today. No blackhole (F-B's helper-first direction closed by keeping the
  gate), no claimed improvement.
- New helper + new sender: determinate class adjudicated; indeterminate class per §5b.
- Old helper + new sender: old helper ignores attestation ⇒ today's behavior (the documented
  tradeoff, unchanged — the v9 doctrine's "old behavior unchanged" is now TRUE rather than
  aspirational, because the defect being fixed is helper-local disposition, not wire content).
- Required deliverables (not optional): operator-facing status signal distinguishing
  adjudicated-delegation from legacy capped delegation + `metrics_descriptors_binding.go`
  doc update for the new counters.

### 5f. Alternative B: prerequisites + pointer (sketch deleted per round-2 convergence)

B returns ONLY when ALL hold: (1) §9 scan measurements show helper-FIB growth is admissible
through the target table size (LPM answer or measured headroom — GLM F2's gate, unchanged);
(2) a from-zero plan for staged-off-live atomic publication with joint FIB+generation
  visibility (Astra's reset, unmodified); (3) single-carrier + v11-class negotiation designed
  first. No mechanism is pre-approved here; any future B justifies itself from zero. (KILL-B —
  deleting even this pointer — remains an acceptable reviewer verdict.)

## 6. Public API preservation

Preserved verbatim: `noroute_policy_denial` (fallback + control); the capped-gate fallback
path (byte-identical disposition in its class); `apply_snapshot`, `bump_fib_generation`,
`update_neighbors`; 64 MiB lockstep + #7675; `LearnedRouteCapHits()`; #9654 absence semantics;
#1913 chokepoint + single-recycle. Deleted: nothing (v2's gate deletion retracted). Added:
helper-local resolver (query + full-key/negative cache + counters), ONE Go attestation field
(tri-state), named counters + status signal + metrics-docs update. No verb, no generation
change, no version change.

## 7. Hidden invariants the change must preserve

V2's eleven stand, amended: (2) the evaluation question changes from "default action on the
sentinel" to "real pair where determinate" — authority (one chokepoint) unchanged; (4) no
generation/digest interaction (no FIB mutation; attestation rides the snapshot it describes,
recomputed per build); (7) ZERO new control traffic (attestation is a bool inside existing
snapshots); (9) ABSENT ⇒ legacy verbatim (the skew rule §5d states); (11) real-zone 0 ⇒
indeterminate, flowless closed-ports verbatim in both classes. New (12): **mirror-equality** —
the query context MUST equal the reinject context field-for-field (TUN iif, mark 0, INVALID
uid, no forced table); any future input added to one side is added to both with a paired cell,
or the design is void.

## 8. Risk assessment

| Class | Rating | Reason |
|---|---|---|
| Behavioral regression | MED-HIGH | Same arm, but the change is now (a) a context-exact mirror rather than a counterfactual, (b) fallback-preserving rather than gate-deleting. Failure mode is wrong-zone or indeterminate-misclassified answers; §5d + full-key cache + §5b bound it. #9054 history keeps this above MEDIUM. |
| Lifetime / borrow-checker | LOW | Arm-local borrows + worker-owned bounded maps. No Arc rotation, no shared FIB writes. |
| Performance regression | MED | Per-NoRoute-packet: one full-key hash consult (hit) or one bounded sync GETROUTE (miss, rate-limited). Pre-existing scan cost unchanged. Scan-storm class handled by negative cache + overflow-to-fallback. §9 gates wiring. |
| Architectural mismatch | LOW | Follows #1769/#1651/#6905 precedent; no protocol, no transaction, nothing fenced. B's machinery explicitly refused. |

## 9. Test plan

Order is load-bearing (F-G): **measurements before arm wiring** (go/no-go gates), then cells,
then suites, then smoke.

- M1 (gate): FIB linear-scan cost at 65k/250k/500k/1M (miss-path ns + NoRoute pps) — documents
  the §2 scan ceiling AND states measured permit-delegated throughput (the "permit crawls"
  caveat, if present, ships in the PR with numbers).
- M2 (gate): sync GETROUTE RTT p50/p99 + worst-case under churn; fixes the numeric recv
  deadline (§5c) or forces the documented thread-shape revision.
- M3 (sizing): NoRoute-miss pps under full-table synthetic + distinct-dst scan — sizes rate
  limits and proves the negative cache holds the unroutable-scan class.
- Cells (each fail-on-revert): `capped_miss_equals_uncapped_miss_9522` (determinate:
  capped ≡ uncapped; delete lookup ⇒ RED); PBR-disagreement ⇒ MAIN's zone (the #7409 vector
  as contract); hash-parity (same tuple ⇒ same member); full-key isolation (tos/src/port
  variants do NOT share entries); negative-entry consult; TTL-expiry + clear-on-publish +
  cap-reclaim; verdict-never-cached (policy change with hot zone entry flips the verdict);
  complex-attested ⇒ fallback + counter (mark-rule AND DSCP-rule — the latter pins the F-C
  reader choice); enumeration-failure ⇒ complex; default-permit indeterminate ⇒
  delegation-with-signal (residual pinned both directions); uncapped-deny control untouched.
- Guards: `slow_path_admit_single_site_6664.rs` extended to the lookup call (deleted lookup
  reds it); #9054 composition cells rewritten as equivalence + fallback-preservation.
- Suites: `cargo build` clean per commit; full `cargo test --release`; 5/5 flake on affected
  cells; `go test` affected pkgs (attestation tri-state incl. absent ⇒ legacy).
- Smoke (REQUIRED): deploy; v4+v6 × push+reverse; `-P 12 -R`; full-table synthetic —
  deny-pair learned-only dst DROPS (determinate), permit-pair FORWARDS with verdict telemetry,
  indeterminate-class counters + `LearnedRouteCapHits()` captured; per-class CoS 5201-5206.
  Every figure captured, none asserted.

## 10. Out of scope (explicitly)

V2's list stands (observability #9172 beyond the §5e signal + counters; B implementation;
budget/ceiling changes; FRR filtering; fail-closed-above-cap; general LPM).

## 11. Open questions for adversarial review

1. **Mirror-equality completeness:** is there ANY kernel input at reinject beyond
   (dst, src, iif=TUN, mark 0, uid INVALID, tos, proto/ports, RPDB rules+tables) — conntrack
   state for a first packet? rpfilter on the TUN (`rp_filter` deliberately 0 — verified or
   assumed?)? TCP-MD5/MPTCP options influencing routing? Each candidate is either proven-inert
   with a cell or kills Design A. No middle ground.
2. **uidrange-inert: proven or assumed?** The plan claims forwarded packets carry INVALID_UID
   on both sides. Cite the kernel path (no socket ⇒ `INET_ECN`... precisely: `fib_rule_uid`
   match against `skb->sk` NULL ⇒ INVALID) or replace the claim with attestation of uidrange
   rules. An unproven inertness is a fail-open hole on paper.
3. **Is the capped+indeterminate delegation residual the issue's core?** If the deployments
   that cross the cap ALSO run complex rules (mark-based PBR is common on full-table edge
   boxes — the plan's own target population), the determinate class may be small and v3 fixes
   little while preserving the hole where it matters. Kill on population grounds if the
   numbers say so — what measurement would decide?
4. **Negative-cache poisoning:** a negative entry ("no kernel route") consulted during a
   route-flap window delegates... no — negative entries take the SENTINEL path (uncapped) /
   gate fallback (capped), never delegation-with-verdict. Confirm the direction is right, or
   show a flap sequence where a stale negative entry harms availability beyond its TTL.
5. **Sync-query worker stall under (M2+M3) worst case:** with the numeric deadline D and
   ceiling R, what is the worst-case added latency for an unrelated flow sharing the worker,
   and is it within the slow-path budget the tree already accepts for session installs? If the
   arithmetic fails, thread-shape is forced — say so now, not in smoke.
6. **Should §5f die entirely (KILL-B)?** V3 keeps prerequisites + pointer. If even the pointer
   invites v1's resurrection, delete it and let future fast-path work start from zero.
7. **Status-signal sufficiency:** does distinguishing adjudicated vs legacy delegation in
   status + metrics-docs satisfy "must not silently change posture" for the indeterminate
   residual, or does the residual need its own alert-level signal (log on first capped
   indeterminate delegation per generation)? #9172 adjacent — draw the line explicitly.
