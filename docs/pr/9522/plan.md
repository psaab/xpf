# #9522 — Adjudicate-before-delegate on a NoRoute miss via reinject-mirror kernel lookup (Design A v4); chunked transport a gated future pointer

## 1. Status

DRAFT v4 — pending adversarial plan review (round 4; parent-authorized final targeted round).
Supersedes v3 (`277da0b8`).

Round-3 record (raw outputs preserved under `docs/pr/9522/reviews/`):

- Codex Astra: **PLAN-KILL**, scoped to Design A v3 — mirror equality unproven
  (flow-label/inner-hash ECMP parity, attestation completeness incl. v6/netns/sysctls),
  weaker-invariant approval missing, withdrawal-covering-route falsifies "kernel drops",
  fallback-table capped/default-deny contradiction, doctrine requires refusal/versioning or an
  approved exception, cost unquantified with pre-wiring thresholds missing.
- GLM: **NEEDS-MINOR** — all four round-2 required items satisfied in mechanism; 4 minor fixes
  (R3-1 uidrange-inert FALSE as worded — the query socket has an owner, move uidrange to
  attested or probe RTA_UID; R3-2 name nft-prerouting/NAT-on-TUN exclusion; R3-3 name iproute2
  the primary reader; R3-4 WARN lines as deliverables). GLM accepts the weaker invariant as
  proposed (≤3 s, cleared on publish, narrower than master's unbounded capped window).

V4 addresses every item from both reviews. Where the two reviewers disagree on severity
(approval/thresholds/doctrine), v4 writes the decision as an explicit approval gate (§2, §5e)
rather than assuming parent pre-approval. Astra's two conceded overreaches (TCP-MD5/MPTCP as
independent blockers — withdrawn by Astra; rpfilter as bypass evidence — availability-only,
agreed) are recorded and not re-litigated.

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
control keeps passing untouched. What v4 refuses to promise: identical results where the helper
cannot determine the zone. That refusal is the F-B fix.

**Explicit approval gates (not assumed — parent must approve each in the PR, otherwise v4 does
not proceed):**

- **G1 — weaker authorization invariant.** The determinate class carries a bounded residual:
  a route/rule change inside the zone-cache TTL (≤3 s, §5c) can authorize against a zone the
  kernel no longer selects at reinject. V4 states the bound as *authorization freshness*
  (≤ TTL + reinject delay), NOT as a forwarding residual, with the withdrawal taxonomy in
  §5c. Parent approval of this invariant is REQUIRED; rejection kills Design A (no silent
  fallback to the v2/v3 wording).
- **G2 — doctrine exception vs version bump.** §5e offers two paths: (E) ship the tri-state
  attestation under v10 with the behavioral-identity argument, or (V) bump to v11 with loud
  refusal of mixed pairings. Parent must pick E or V in the PR; v4 does NOT pre-pick and does
  not assume E is pre-approved.
- **G3 — numeric acceptance thresholds (§9).** Wiring proceeds only if M1–M4 meet the
  pre-stated thresholds; otherwise the no-go action fires (thread-shape revision or STOP).

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
- **V4 verifications (round-3 follow-up, read at head/on host):** `RTA_UID` exists
  (`rtnetlink.h:395`) but the query socket's owner uid is uncontrolled, so v4 moves uidrange
  to the attested list (GLM R3-1 preferred fix) instead of claiming inertness — the
  INVALID-vs-overflowuid numerics dispute is sidestepped, not resolved. Multipath hash fields
  are sysctl-configurable INCLUDING flow-label and inner-header bits
  (`FIB_MULTIPATH_HASH_FIELD_FLOWLABEL/INNER_*`, host `ip_fib.h`); `RTM_GETROUTE` has no
  flowlabel request attribute, so v4 excludes non-covered hash masks (see §5a). iproute2 on
  the build host is 7.1.0. rpfilter: `networkd.go:restoreSlowPathRPFilter` writes per-device 0
  on `xpf-usp0` and warns (never mutates) on `conf/all` override (#2378) — availability-only,
  never zone divergence (agreed with Astra). Single-netns deployment verified: no
  `setns`/netns-pinning anywhere in tree — helper, daemon, TUN, rules and resolver socket are
  host-netns by construction. Additive-unknown-field tolerance is a PINNED property, not an
  assumption (`protocol/tests.rs` #6853 rests on the ABSENCE of `deny_unknown_fields`).
  Resolver bounds confirmed (`neighbor_resolver.rs`: 4096 queue, 1 s per-key, 3 s negative
  TTL). Metric homes: `#7409` reinject series at `metrics_descriptors_binding.go:58-111`,
  cap-status at `metrics_descriptors_global.go:93`.

## 5. Concrete design — Design A v4 (primary and only half in this PR)

### 5a. The query: mirror the reinject walk, not the operator's intent (rewrites v2 §5a)

On the NoRoute arm — slow path only, after L3-identity derivation — issue `RTM_GETROUTE` with
the context the kernel will have MILLISECONDS LATER at reinject:

```
dst    = adj_flow.dst_ip            (the lookup key)
src    = adj_flow.src_ip            (source-specific rules; forwarded => same src both sides)
iif    = xpf-usp0 ifindex           (DEFAULT_SLOW_PATH_TUN; the device the reinject arrives on.
                                     NOT the origin ingress — v2's inversion, fixed.)
mark   = 0                          (a TUN write carries no mark on either side)
tos    = packet TOS                 (FRA_DSCP-relevant rules; input, not attested)
proto/ports = meta.protocol + flow ports where present (flowless: closed-ports rule verbatim)
table  = NONE FORCED                (ordinary RPDB traversal from the above context — v2's
                                     mode contradiction fixed by deleting the second mode.
                                     route_table_override and meta.routing_table are NOT
                                     lookup inputs; the #7409 vector proves the kernel
                                     ignores them at reinject.)
```

Deliberately NOT passed (each with its disposition, R3-1/R3-3/Astra-1):

- **uid:** v3's "inert on BOTH sides" sentence is RETRACTED (GLM R3-1: the query socket has an
  owner; `RTA_UID` probing is rejected as kernel-version-fragile). `uidrange` rules join the
  §5d attested-complex list. Forwarded traffic still carries no socket at reinject, but the
  plan no longer leans on it.
- **v6 flowlabel:** `RTM_GETROUTE` carries no flowlabel request attribute, so a v6 ECMP member
  selected by flowlabel hash cannot be mirrored. Covered by the hash-mask exclusion below.
- **Multipath hash parity rule:** the helper reads `fib_multipath_hash_fields` (v4 + v6
  sysctls) at attestation time. Masks ⊆ {SRC_IP, DST_IP, IP_PROTO, SRC_PORT, DST_PORT} are
  fully covered (every input passed). Any FLOWLABEL or INNER_* bit set ⇒ the configuration is
  EXCLUDED (indeterminate, §5b) — INNER bits despite same-bytes dissection, conservatively,
  because encapsulated-fragment dissection parity is asserted, not proven. `hash_policy`
  L3-vs-L4 only selects among passed inputs (covered); `fib_multipath_use_neigh` member
  liveness is same-state both sides modulo the §5c TOCTOU bound (stated).

The answer is the egress ifindex the kernel WILL select → existing `ifindex_to_zone_id` map →
evaluate the real pair with the flow-backed/flowless port rules verbatim. Permit → delegate
(reinject exactly as today, verdict now explicit); non-Permit → `PolicyDenied` via the existing
chokepoint. Unmapped egress ifindex (0) ⇒ indeterminate ⇒ §5b fallback.

Generality note (Astra-1 concession, accepted): the #7409 MAIN-resolution vector is ONE pinned
cell, not a universal proof. The general target is the RPDB result from the mirror context;
the §9 suite adds table-diversity cells (VRF/instance tables whose reinject walk selects
non-MAIN) alongside the MAIN cell. The parity cells compare QUERY vs INPUT-PATH
(`ip route get` with identical context in the same netns) AND query-vs-observed-reinject
(loss-cluster smoke: queried member vs egress member observed on the wire for ECMP
destinations) — never two oracle calls against each other.

Remaining divergence sources, stated (not hand-waved): (i) TOCTOU between query and reinject
(§5c); (ii) selectors outside the list — each is either proven-inert (oif-rules, which never
match a forward lookup) or attested (§5d, now including uidrange and non-covered hash masks).
Any NEW selector family discovered in review is attestation-or-KILL per Q1.

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

Default-permit/indeterminate is now specified, not elided — and SCOPED (Astra-4 fix): the
following sentence applies to UNCAPPED indeterminate only. Capped indeterminate ⇒ delegation
regardless of default action (the table governs; today's gate, preserved).
Uncapped-indeterminate evaluates the default action — permit ⇒ delegates (real-pair denials NOT
enforced in this class; the counter + status signal say so), deny ⇒ drops. The test matrix
gains the default-permit/explicit-pair-deny indeterminate cell asserting delegation-with-signal
(the documented residual, pinned against silent drift in EITHER direction).

### 5c. Cost containment: full-key zone cache + negative entries + bounded sync query

- **Cache key = (dst, src, tos, proto, ports) exact.** No `src-class` (term deleted), no
  dropped inputs: iif/mark are fixed constants (excluded by construction, documented), domain
  is excluded because the mirror walk is domain-independent (RPDB from TUN — stated with the
  §9 domain-independence cell). Routing-distinct packets cannot share an entry by construction.
- **Negative entries** ("kernel has no route either", F-E): same TTL/cap/clear discipline, so
  the distinct-dst unroutable scan costs one cached lookup per key, mirroring `neg_neigh`.
- **Sync query, bounded with numbers (Astra-6):** per-worker netlink socket, hard recv
  deadline D (stipulated D = 5 ms; M2 confirms p99 ≤ 1 ms worst ≤ D or fires the no-go);
  per-worker in-flight cap 1 (worst-case head-of-line cost to an unrelated flow on the worker
  = D); global per-second ceiling R (stipulated start R = 1000/s; M3 confirms against the
  measured legitimate miss rate with headroom, or fires the no-go); overflow ⇒ indeterminate
  ⇒ §5b + dedicated counter. M2's no-go action is "switch to the resolver-thread shape"
  (already implemented at `neighbor_resolver.rs`) — never "raise D". Slow-path only.
- **Unsupported-topology exclusion (GLM R3-2):** operator nft prerouting mark/TOS/DSCP
  mutation and kernel-side NAT on `xpf-usp0` make mirror-equality field-for-field false —
  EXCLUDED by name (not attested: undetectable from `ip rule`). Detection: best-effort
  per-snapshot-build `nft --json list` prerouting-mangle presence check; non-empty (or
  parse failure) ⇒ force `complex=true` with a loud log. The operational exclusion draws the
  line; the check is the signal. Netns-segmented deployments excluded likewise (single-netns
  verified, §4 — no setns in tree; resolver socket, TUN, rules and routes are host-netns by
  construction).
- **Verdicts never cached** (GLM Q3 answered with the stronger argument: the arm ALREADY
  evaluates policy per packet on master — `poll_descriptor/mod.rs:5236+` — so verdict-freshness
  costs nothing versus master, while a verdict cache would invent a third generation-coupled
  cache for zero gain). Zone answers: TTL ≤ 3 s, hard entry cap with expired-first/oldest
  reclaim (#6905 discipline), cleared on every FIB publish.
- **TOCTOU, honestly split with withdrawal taxonomy** (F-F rewrite + Astra-3): the bound is
  *authorization freshness* (≤ TTL + reinject delay), never a forwarding guarantee. (a)
  Withdrawal with NO covering route ⇒ kernel drops at reinject (availability blip ≤ TTL, NOT a
  bypass). (b) Withdrawal EXPOSING a covering route/next-hop (Astra-3's falsifier — accepted:
  v3's "kernel drops" was false without qualification) ⇒ forwarding outcome can CHANGE zone:
  same-zone covering ⇒ availability-neutral; different-zone covering ⇒ bounded transient
  residual ≤ TTL — same order as the standing inter-push residual the arm already documents
  (1 s/3 s coalescing), strictly narrower than today's unbounded capped window. (c) Rule-set
  changes arrive via commit (new snapshot ⇒ new attestation ⇒ FIB publish ⇒ cache clear);
  out-of-band kernel rule edits are outside the supported topology (stated). G1 approval of
  this invariant is REQUIRED (§2); the plan does not smuggle it.

### 5d. Attestation: iproute2 PRIMARY, raw FRA_* fallback, fail-closed parse (F-C fix, R3-3)

Go's attestation reader is **iproute2 `ip rule list` + `ip -6 rule list` (PRIMARY)** — the #7796
remedy for `netlink.RuleList`'s proven `FRA_DSCP` blindness — with a **raw `FRA_*`
attribute-presence parse as FALLBACK** (for iproute2-absent environments). The choice is made
here, not deferred (GLM R3-3). Conservative rule: any rule carrying a selector outside §5a's
list — mark/mask, **uidrange (moved here from §5a's retracted inertness claim, R3-1)**,
v6 flowlabel/tun_id, l3mdev forms beyond TUN-consistent, non-covered hash-mask configurations
(§5a), inversion/goto/suppression constructs not reducible to canonical xpf-emitted shapes
(rules.go bands are the SSOT) — ⇒ `complex=true`. BOTH families enumerated every build;
either family's readback failing ⇒ `complex=true`. Parse discipline: **any unparseable rule
line ⇒ `complex=true`** (unknown future attributes fail closed through the shape-match, not
through reader completeness — this is what bounds the "independent reader omits attributes"
residual; version floor recorded from `ip -Version` in attestation debug, host 7.1.0, but the
parse-fail-closed is the guarantee, not the version number). Multipath sysctls read at the
same time (`fib_multipath_hash_fields` v4+v6; unreadable ⇒ complex). Encoding: tri-state
`ComplexPolicyRouting *bool` — **absent (old sender) ⇒ legacy behavior verbatim** (no lookup
attempted; capped gate as on master in both states), `Some(true)` ⇒ sentinel/capped-gate
fallback, `Some(false)` ⇒ lookup eligible. Old helper ignores the field ⇒ today's behavior.
No pair enters a NEW unsafe state in either mixed direction (behavioral-identity argument for
gate G2-E; the v11 alternative is §5e path V).
### 5e. Skew matrix + doctrine decision gate G2 (Astra-5 fix: exception written, not assumed)

- New helper + old sender (all rollout pairs): absent attestation ⇒ legacy behavior,
  byte-identical to today. No blackhole, no claimed improvement.
- New helper + new sender: determinate class adjudicated; indeterminate class per §5b.
- Old helper + new sender: old helper ignores attestation ⇒ today's behavior. Unknown-field
  tolerance is a PINNED property (`protocol/tests.rs` #6853 rests on the ABSENCE of
  `deny_unknown_fields`), not an assumption.
- **Gate G2 — parent picks one:**
  - **Path E (exception):** ship under v10. Rationale: absent ⇒ legacy is byte-identical on
    both mixed directions (proven by the two-question test + #6853 pin), so no pairing enters
    a new unsafe state; the v9 refusal precedent targeted a redefinition that changed mixed
    behavior, which v4 does not cause. Requires explicit parent approval in the PR.
  - **Path V (version bump):** bump to v11 with loud refusal of mixed pairings (old-helper +
    new-sender refuses attested snapshots; new-helper + old-sender refuses capped snapshots
    until first complete attested table — i.e. fail-closed pairing, availability cost at
    rollout). Requires no doctrine exception but imposes a flag-day pairing discipline.
  - V4 implements the winner; the loser is deleted from the doc, not left as an option.
- Required deliverables either path (GLM R3-4 + §5b): operator-facing status signal
  distinguishing adjudicated-delegation from legacy capped delegation; `WARN` on first
  complex-attestation per snapshot build; `WARN` on sustained capped-indeterminate delegation
  (stipulated >100/min, confirmed by M3); `metrics_descriptors_binding.go` doc update for the
  new counters (`bindingSlowPathNoRoutePackets` neighborhood, lines 58-111) + cap-status
  descriptor note (`metrics_descriptors_global.go:93).

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
the query context MUST equal the reinject context field-for-field (TUN iif, mark 0, no forced
table, uidrange attested-not-passed, non-covered hash masks excluded); any future input added
to one side is added to both with a paired cell, or the design is void. Netns is part of the
equality by construction (single-netns verified — no setns in tree); a netns-segmented
deployment voids it by exclusion (§5c), not by attestation.

## 8. Risk assessment

| Class | Rating | Reason |
|---|---|---|
| Behavioral regression | MED-HIGH | Same arm, but the change is now (a) a context-exact mirror rather than a counterfactual, (b) fallback-preserving rather than gate-deleting. Failure mode is wrong-zone or indeterminate-misclassified answers; §5d + full-key cache + §5b bound it. #9054 history keeps this above MEDIUM. |
| Lifetime / borrow-checker | LOW | Arm-local borrows + worker-owned bounded maps. No Arc rotation, no shared FIB writes. |
| Performance regression | MED | Per-NoRoute-packet: one full-key hash consult (hit) or one bounded sync GETROUTE (miss, rate-limited). Pre-existing scan cost unchanged. Scan-storm class handled by negative cache + overflow-to-fallback. §9 gates wiring. |
| Architectural mismatch | LOW | Follows #1769/#1651/#6905 precedent; no protocol, no transaction, nothing fenced. B's machinery explicitly refused. |

## 9. Test plan

- M1 (gate): FIB linear-scan cost at 65k/250k/500k/1M (miss-path ns + NoRoute pps) — documents
  the §2 scan ceiling AND states measured permit-delegated throughput (the "permit crawls"
  caveat, if present, ships in the PR with numbers).
- M2 (gate): sync GETROUTE RTT p50/p99/worst under churn; PASS requires p99 ≤ 1 ms AND worst ≤
  D = 5 ms (the §5c deadline). No-go: switch to the resolver-thread shape — never raise D.
- M3 (sizing + census): NoRoute-miss pps under full-table synthetic + distinct-dst scan (sizes
  R from the measured legitimate miss rate with ≥2× headroom; confirms the >100/min WARN
  threshold); fleet census: run the §5d reader over capped boxes, report the out-of-list
  (complex) share + traffic-weighted determinate-vs-fallback fractions in the PR.
- M4 (gate, Astra-6): sustained admitted lookup capacity + unrelated-flow slow-path latency
  delta (must be ≤ D) + baseline-versus-A permit throughput. PASS thresholds: fallback
  population ⊆ today's delegated population (monotone shrink — the fix only moves packets OUT
  of unadjudicated delegation); indeterminate+capped delegation rate ≤ today's rate in the
  same window. Numbers in the PR before wiring; thresholds are G3 (§2).
- Cells (each fail-on-revert): `capped_miss_equals_uncapped_miss_9522` (determinate:
  capped ≡ uncapped; delete lookup ⇒ RED); PBR-disagreement ⇒ MAIN's zone PLUS table-diversity
  cells (VRF/instance reinject walks selecting non-MAIN); query-vs-input-path parity
  (`ip route get`, identical context, same netns) AND query-vs-observed-reinject (ECMP member
  on the wire == queried member); hash-parity incl. non-default-mask exclusion cell
  (FLOWLABEL/INNER-bit mask ⇒ indeterminate); uidrange-rule ⇒ complex (R3-1 pin);
  DSCP-rule ⇒ whatever the chosen reader sees (F-C pin the netlink surface cannot pass);
  mark-rule ⇒ complex; enumeration-failure ⇒ complex; unparseable-line ⇒ complex;
  full-key isolation; negative-entry consult + clear-on-publish; TTL-expiry + cap-reclaim;
  verdict-never-cached; default-permit indeterminate ⇒ delegation-with-signal; uncapped-deny
  control untouched; absent attestation ⇒ legacy-verbatim (old-sender pairing byte-identical).
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

1. **Mirror-equality completeness (final sweep):** with uidrange attested, flowlabel/INNER
   masks excluded, nft/NAT/netns excluded by name, rpfilter verified availability-only
   (networkd per-device 0 + #2378 conf/all warning), conntrack closed transitively via
   mark-attestation, and oif-rules proven-inert — is there ANY remaining kernel input at
   reinject outside §5a's list? Each candidate is proven-inert with a cell, attested, or
   kills Design A. No middle ground.
2. **G1 — approve the weaker invariant?** Authorization freshness ≤ TTL + reinject delay, with
   the (a)/(b)/(c) withdrawal taxonomy. Rejection kills Design A; rewrite-smuggling it past
   review is itself a kill reason.
3. **G2 — exception or version bump?** Path E (behavioral-identity + #6853 pin, ship under v10)
   or path V (v11 with loud mixed-pairing refusal)? Pick one; the plan implements the winner
   and deletes the loser.
4. **G3 — are the M2/M3/M4 thresholds the right gates?** D = 5 ms, p99 ≤ 1 ms, R = 1000/s start
   with 2× headroom, fallback ⊆ today, WARN >100/min. Too lax (residual dominant) or too
   strict (unshippable)? Numbers, not adjectives.
5. **Population (Astra Q3):** the M3 census decides — if the complex share dominates capped
   boxes, the determinate class is small and v4 preserves the hole where it matters. What
   census fraction is a kill threshold? Name it now, before the measurement exists.
6. **Should §5f die entirely (KILL-B)?** Prerequisites + from-zero pointer kept. Delete even
   the pointer if it invites v1's resurrection.
7. **Status-signal sufficiency (GLM Q7 as specified):** counters + adjudicated-vs-legacy
   distinction + rate-limited WARNs (first complex-attestation per build; sustained
   capped-indeterminate delegation). Sufficient for "not silently," or does the residual need
   alert-level? #9172 stays out either way.
