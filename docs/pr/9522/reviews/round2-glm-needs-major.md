# Adversarial PLAN review — ROUND 2 — psaab/xpf#9522

**Reviewed:** `docs/pr/9522/plan.md` v2 @ `e2b4724f`, base `7ef226474`, worktree `9522-learned-route-cap`. All citations read at head; round-1 record (`docs/pr/9522/reviews/round1-{glm,astra}*.md`) re-read for continuity.

**Round-1 disposition honored:** v2 genuinely kills v1 §5a (no FIB mutation anywhere in Design A), demotes chunked transport to a gated sketch, and re-plans the kernel-lookup half as primary. That was the round-1 convergence and it is real. The §2/§3 honesty framing (security fix, cap restated as scan bound) is accepted — `forwarding/fib.rs:428-431` (`routes.iter().find`) and `flow_cache_tests.rs:1570-1592` (`NoRoute should not produce a cache entry`) both verify. But v2's own §5 carries three load-bearing defects, two of which fail in the *fail-open* and *#9054* directions respectively. This is a review of the design's spine, not its cosmetics.

---

## Findings

### F-A — MAJOR (fidelity, fail-open): §5a's query is mode-incoherent, and the logical-iif input computes a *counterfactual* — it does not compute "the same decision the kernel will make milliseconds later at reinject" that §5a's own preamble promises

**Grounding:** `plan.md:101-127` (inputs at 106-120: `table = route_table_override else meta.routing_table` at :109, `iif = logical ingress ifindex ... MUST be passed explicitly` at :111); `userspace-dp/src/afxdp/tests_fragment.rs:826-841` (the #7409 second vector: a PBR-steered NoRoute frame is reinjected and "the kernel ... resolves it in the MAIN table and forwards it down the very path the operator steered it away from"); `pkg/routing/rules.go:34-44,100-124` + `#9420` (xpf's own next-table rules are **iif-scoped**); `pkg/routing/rules.go:85-91,791-797` (xpf's own PBR mirror rules carry from/to/DSCP/ipproto/sport/dport selectors, pref band 31000-31999, installed "so the kernel also honors PBR for XDP_PASS'd packets"); `pkg/flowexport/README.md:364-367`…

Two independent defects:

1. **Mode contradiction.** One `RTM_GETROUTE` cannot simultaneously force a table (`RTA_TABLE` → direct `fib_table_lookup`, rule walk skipped, iif/tos/ports irrelevant except multipath hash) and run the rule walk where those selectors matter (§5a passes both `table` at :109 and `iif/tos/proto/ports` at :111-118). As specified, the query is not a query — it's two designs fused. The plan never says which mode runs.

2. **The iif value is inverted.** The packet's actual fate is decided at reinject with `iif = xpf-usp0`, `mark = 0` (TUN write carries no mark, no conntrack, no meta). §5a passes `iif = logical ingress` to capture the operator's *intent* — but the delegated packet does not follow the operator's intent; it follows the kernel's reinject walk. The tree proves the divergence on xpf's **own first-class features**, not on exotic operator configs: iif-scoped next-table rules (#9420) match the helper's query and never match at reinject; mark-based PBR (rules.go, documented unreproducible in flowexport/README.md:364-367) matches neither side but the *helper-side* `route_table_override`/`meta.routing_table` steer is invisible to the reinject walk entirely — th…

Not a kill — Design A survives with the corrected query, and the correction removes inputs rather than adding them. But it is a rewrite of §5a, and the §9 real-zone cells must pin the *reinject-mirror* semantics (a cell where the PBR table and main disagree on egress zone must adjudicate main's zone, or the design is wrong again).

### F-B — MAJOR (the deleted gate recreates #9054 through the indeterminate door; §5e and §7.9 directly contradict each other on the fail direction)

**Grounding:** `plan.md:140` ("There is no third outcome. 'Delegate without a verdict' ceases to exist ... the gated early-`None` is deleted"); `plan.md:189-191` (§5e row 1: new helper + old sender above cap — "helper's lookup succeeds from the kernel and adjudicates ... Strictly better than today"); `plan.md:258` (§7.9: "old sender omits it (helper treats **absent as complex ⇒ sentinel path** — fail-closed direction)"); `userspace-dp/src/protocol/snapshot.rs:645-658` (v10 was bumped because "an older helper that ignores this one keeps black-holing, and black-holing IS the defect it was added to fix"); `pkg/dataplane/userspace/learned_route_cap_blackhole_9054_test.go:336-343` (the two-question rule: "does an old reader still enforce what it enforc…

§5e row 1 requires absent ⇒ *not* complex (else the lookup never runs with an old sender and "strictly better" is false). §7.9 requires absent ⇒ complex. Both cannot ship. Take §7.9's default: new helper + old sender (i.e., **every deployment at rollout**) above cap ⇒ complex ⇒ sentinel path ⇒ `noroute_policy_denial` against the unzoned sentinel ⇒ default action ⇒ on a default-deny box, the **entire learned FIB drops**. That is the #9054 blackhole, helper-first direction, failing the two-question test quoted in the tree's own test, and violating the plan's own acceptance ("Fail-closed-above-cap remains rejected (#9054)", plan §2). §7.9's "fail-closed direction" label is exactly wrong: it is fail-closed for *availability* and it is the r…

The resolution is determined, not open: **the capped gate must survive as the fallback condition, not be deleted.** Fallback for *capped + indeterminate/complex* = today's gated delegation (counted, strictly no worse than master); *uncapped + indeterminate* = today's sentinel path (identical to master); *lookup success* = real-zone adjudication in both states. "Delegate-without-verdict ceases to exist" (plan.md:140) is the overreach — it must exist as the bounded capped fallback. With that, §5e row 1 is rewritten honestly (old-sender pairing = byte-identical to today, no blackhole, no claimed improvement), the §7.9 default becomes harmless, and **no-version-bump becomes genuinely defensible** under the v10 precedent: additive field, old helper ignores…

### F-C — MAJOR (attestation): §5d's "conservative by construction (unknown selector ⇒ attest)" is **false on the enumeration surface §5d itself names** — the tree proves the surface is blind to at least one selector

**Grounding:** `plan.md:178-185` ("Go already enumerates the kernel ip-rule set for leak-route synthesis (#3772 M9 surface) ... The attested set is conservative by construction (unknown selector ⇒ attest complex)"); `pkg/dataplane/userspace/routes.go:17-19,272-278` (the surface: `ruleListFn = netlink.RuleList`, fail-closed per #3772 M9 — verified); `pkg/routing/rule_dscp_kernel_7796_test.go:108-112`: *"netlink's own RuleList cannot be used as the reader here: the library has no FRA_DSCP support at all ... it would silently report every rule as having no DSCP"*.

`netlink.RuleList` decodes a fixed struct; an attribute the library doesn't parse is indistinguishable from an attribute that isn't present. A whitelist test "unknown selector ⇒ attest" cannot be implemented on a reader that under-reports selectors — on this exact surface, the product's **own** DSCP rules (#3730/#7796, installed in the PBR band) are invisible, so the attestation would read `complex=false` on a box whose rule set §5a can only partially reproduce. This is the round-2 Q1 enumeration, answered concretely — every kernel fib-rule selector beyond §5a's list, and its disposition:

| Selector | Effect on GETROUTE-vs-reinject | Covered? |
|---|---|---|
| fwmark/fwmask (+ nft-mangle marks at TUN prerouting) | GETROUTE mark=0 vs kernel's post-mangle mark; diverges only if a *rule* consults mark | Attest mark-rules — covered **only if enumerable** (F-C) |
| uidrange | forwarded packets carry INVALID_UID; GETROUTE from the helper process carries its own uid — real divergence | Attest — same enumerability requirement |
| l3mdev / VRF master | consistent with iif=TUN (TUN unslaved); **diverges under §5a's logical-iif** (F-A data point #3) | Fixed by F-A's iif correction |
| flowlabel (v6), tun_id | diverge; rare | Attest (catch-all) |
| oif-selector rules | never match on either side (fwd lookup oif=0) | No action — correct to ignore |
| suppress_prefixlen / suppress_ifgroup / FRA_PROTOCOL | honored identically by GETROUTE (same rule engine) / non-matching metadata | No action |
| DSCP (FRA_DSCP) | in-scope as tos input | enumerable? **No — proven blind** |

So the §5a input *set* is complete; the gaps are the iif **value** (F-A), the forced-table **mode** (F-A), and the attestation **enumerability** (F-C). Fix for F-C: parse raw `FRA_*` attribute presence (own netlink parse), or shell `ip rule list` as #7796 already does for its readback leg, or shape-match *only* the canonical rule forms xpf itself emits (rules.go bands are the SSOT) and attest anything that fails to parse as one of ours. Any of the three is conservative; the plan must pick one and pin it with the §9 attestation cells (mark-rule ⇒ complex; **DSCP-rule ⇒ whatever the chosen reader actually sees**; enumeration failure ⇒ complex).

### F-D — MINOR→required (multipath mechanism unspecified): a single `RTM_GETROUTE` returns the *flowi-hash-selected* member, not the member set

**Grounding:** `plan.md:134` ("multipath answers whose nexthops resolve to DIFFERENT zones"); §7.8 determinism invariant.

`ip route get`-style GETROUTE answers one nexthop — the same per-flow hash selection the kernel applies to this 5-tuple at reinject. That is *better* than the plan claims: per-flow determinism is exact, so the helper could adjudicate the selected member directly. Enumerating "nexthops that resolve to different zones" requires an `RTM_F_FIB_MATCH`-style full-member dump plus nexthop-object (`RTA_NH_ID`) resolution — neither is specified. Specify which mechanism runs; either outcome is safe (adjudicate-selected-member, or FIB_MATCH + cross-zone ⇒ sentinel). The fail-closed sentinel fallback for cross-zone ECMP is acceptable *with* the named counter (present, §5b) — but on a default-deny box it drops whole prefixes the per-flow answer would have adj…

### F-E — MINOR→required (adversarial miss rate): the positive-only zone cache loses to a distinct-dst scan; the plan's own Q2 has the right answer and should adopt it

**Grounding:** `plan.md:148-163` (cache key, TTL, rate limit); `neighbor_resolver.rs:71-83` (the #1769 precedent: shared thread, per-key 1 s rate limit, **negative** TTL 3 s, bounded queue, enqueue-drop counters — the exact shape §5c claims to follow but drops the negative half).

A scan over distinct unroutable dsts never hits the positive cache; every packet pays the GETROUTE RTT until the per-second ceiling, then every overflow packet flips to the fallback — under F-B's corrected fallback that is per-packet **disposition flapping** between adjudicated and delegated across the rate-limit boundary, at line rate, on the slow arm. Required: negative zone-answer entries ("kernel has no route either" — cheap, nearly always correct, TTL-bounded, same cap/reclaim/clear discipline) so the unroutable-scan class costs one cached lookup, mirroring `neg_neigh`. The sync-vs-thread choice itself is defensible as specified: GETROUTE is a direct RCU lookup, the same class the resolver's header explicitly distinguishes from "the RTNL-mutex du…

### F-F — MINOR (TOCTOU wording): "the same TOCTOU class as kernel forwarding itself" (plan.md:158) overstates

The kernel's lookup is synchronous; the zone cache makes the window `max(TTL, publish lag)`. Two sub-cases must be stated separately: withdrawal-inside-TTL → permitted packets delegated toward a route the kernel no longer has → kernel drops (availability blip ≤ TTL, not a bypass); *change*-inside-TTL to a deny-pair egress → transient bounded bypass, honest residual, strictly better than today's unbounded capped window and same order as the standing inter-push residual the NoRoute arm already documents (poll_descriptor/mod.rs:5122-5135, coalesce 1 s/3 s). Reword; keep TTL ≤ 3 s; no design change.

### F-G — MINOR (Q8 answered): the scan math indicts delegated pps **today**, not Design A — but the measurement must gate, not trail, the wiring

65k entries × ~48 B ≈ 3 MB streamed per NoRoute packet (`fib.rs:429-431`) plausibly bounds delegated throughput at ~10⁴ pps/worker *on master* — pre-existing, unchanged by A (A adds one cached hash lookup + a policy eval the arm already pays per packet today — verified: the arm evaluates `noroute_policy_denial_gated` per packet, `poll_descriptor/mod.rs:5236+`). Acceptance: §2's "documented scan ceiling" framing is honest. Required: move the §9 scan measurement **before** the arm-wiring commits (a go/no-go, since if cap-scale scan is already collapsing pps, the fix's deliverable on full-table boxes is "deny drops correctly; permit crawls," which the PR must state with measured numbers, not assert). This measurement already gates Alternative B (…

---

## Answers to the eight round-2 verification questions

1. **§5a input-list completeness:** The *set* (dst, src, iif, tos, proto/ports) is complete for value-passing — full selector table in F-C. But the list is wrong in **value** (logical-iif — F-A) and **mode** (forced table — F-A), and two selector families (fwmark, uidrange) plus v6 flowlabel/tun_id are safe only via §5d attestation, which is not conservative-by-construction on the named surface (F-C — proven blind to FRA_DSCP by `rule_dscp_kernel_7796_test.go:109-112`). nftables-derived marks are covered *iff* mark-consulting rules are attested; `l3mdev` is covered by F-A's iif correction. Each gap as it stands is attestation-or-KILL; all three are repairable by revision, so not a kill.
2. **Sync vs shared thread:** Sync in the worker is defensible — GETROUTE is a direct lookup, not the RTNL dump path (resolver header, neighbor_resolver.rs:32-34), the arm is slow-path-only, and the p99 gate (plan.md:165-176) pre-authorizes the documented fallback. Required additions: per-worker socket, bounded recv timeout, negative-zone cache (F-E). Verdict as specified: incomplete but not wrong.
3. **Zone-cached/verdict-fresh split: correct — keep it.** The arm already evaluates policy per packet today (`noroute_policy_denial_gated` per packet, mod.rs:5236-5266), so verdict-freshness costs nothing versus master, while a verdict cache would introduce a third generation-coupled cache with its own coherence story for zero gain. The plan's answer is right; its "policy tables are small" argument is weaker than the available one — use that one.
4. **Cross-zone multipath:** Determinism is *better* than the plan claims (per-flow hash selection is exact and identical at reinject — see F-D); the detection mechanism is unspecified and needs FIB_MATCH/nexthop-object handling. Silent fail-closed fallback is acceptable with counters; add the per-prefix log line. Not a determinism kill.
5. **TOCTOU honesty:** Not honest as worded (F-F); honest after the rewrite. TTL survives at 1-3 s with clear-on-publish.
6. **No-version-bump (§5e):** As written, **fails** — §5e:189 contradicts §7.9:258, and §7.9's branch recreates the #9054 posture that the tree's own v10 two-question test (`learned_route_cap_blackhole_9054_test.go:336-343`, `snapshot.rs:645-654`) exists to refuse. After F-B's repair (gate survives as the capped fallback; old-sender pairing = today's behavior), the no-bump claim becomes genuinely consistent with the doctrine: additive field, old helper ignores and enforces today's semantics. The loud status signal moves from open question to required (F-B).
7. **Should B die entirely:** Keeping §5f as a gated sketch is acceptable — its PREREQUISITE GATE (measured LPM answer at 65k-1M) is exactly round-1 F2's requirement. But §5f's mechanism sketch invites v1's resurrection; recommend replacing it with prerequisites + a pointer, forcing any future fast-path plan to justify itself from zero. Not a blocker either way (KILL-B acceptable per the plan's own §3).
8. **Scan-bound reframe:** Accepted and verified (`fib.rs:429-431`; uncacheable NoRoute at `flow_cache_tests.rs:1570-1592`). The math already collapses delegated pps at cap *today*; it indicts B (growth without LPM) and A's *value claim* (permit throughput stays scan-bounded), not A's *correctness*. F-G's measurement-first requirement closes it.

---

## Required before PLAN-READY

1. **Rewrite §5a's query** (F-A): reinject-mirror mode — no table forcing, `iif` = the `xpf-usp0` TUN ifindex, mark = 0, tos, proto/ports, src/dst; delete `route_table_override`/`meta.routing_table` from the lookup; pin with a §9 cell where the PBR table and main disagree on egress zone.
2. **Restore the capped gate as the fallback condition** (F-B): capped+indeterminate/complex ⇒ today's delegation (counted); uncapped+indeterminate ⇒ sentinel; rewrite §5e row 1 and §5b's "no third outcome"; make the operator-facing status signal and the `metrics_descriptors_global.go:90-95` doc update required deliverables.
3. **Make §5d enumerable-and-conservative** (F-C): choose and name a selector-presence reader (raw FRA_* parse / iproute2 readback / canonical-xpf-shape matching); add the DSCP-rule attestation cell that the current netlink surface provably cannot pass.
4. Specify the multipath mechanism and outcome (F-D); add the negative-zone cache + per-worker socket/timeout spec (F-E); reword the TOCTOU claim (F-F); make the scan measurement a pre-wiring gate with the permit-throughput caveat stated (F-G).

**Verdict: NEEDS-MAJOR**

Not PLAN-KILL: the architecture that survived round 1 — helper-local, no wire verb, no FIB mutation, no generation change, fallback-bounded — survives round 2 untouched; every finding above has a determined fix that makes §5 strictly *simpler* (fewer lookup inputs, one restored fallback condition, one hardened reader). Not NEEDS-MINOR: F-A inverts the design's fidelity target in the fail-open direction, F-B contradicts itself on the fail direction and recreates the rejected #9054 posture at fleet rollout, and F-C's central "conservative by construction" claim is disproven by the tree on the very surface the plan names. Fix those three and the minors, and this is PLAN-READY material.
