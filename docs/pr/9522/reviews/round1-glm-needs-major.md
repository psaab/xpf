# Adversarial PLAN review — psaab/xpf#9522 (`docs/pr/9522/plan.md` @ ee9b3d6, base 7ef226474)

All citations verified by reading source in this worktree. The plan's STEP-0 evidence claims check out (cap at `pkg/dataplane/userspace/learned_route_cap_8355.go:129-147`, gate at `userspace-dp/src/afxdp/forwarding/mod.rs:184-209`, NoRoute arm at `userspace-dp/src/afxdp/poll_descriptor/mod.rs:5093-5267`). The plan is honest and self-hostile, but its §5a primary design is architecturally broken in four independent places, and its own Q2 misdescribes its own mechanism.

---

## Findings

### F1 — MAJOR (architecture): the inter-chunk window is a *full-scale, recurring* #9054, and the plan's Q2 framing of it is factually wrong about the plan's own design

- Plan §5a step 2 (plan.md §5a): *"If replace && index==0: clear the LEARNED-route partition of the live FIB."* Plan §5c: the gated early-`None` is **deleted**. Therefore from chunk 0 until `complete`, **every** learned destination resolves `NoRoute`, and on a default-deny box the #7480 arm drops it (`poll_descriptor/mod.rs:5093-5267`; gate deleted per §5c). That is not "#9054 in miniature" — it is #9054 **at full scale, transiently**, because the clear removes *all* learned routes, not just above-cap ones.
- Plan Q2's framing — *"the helper enforces a MIXED table (old tail + new head)"* — contradicts §5a's own step 2. There is no old tail after chunk 0 clears. The reviewer cannot evaluate Q2 as posed because the question describes a different design than the one specified.
- Recurrence: every #7437 churn event drives a republish (`pkg/daemon/daemon_route_listener.go:229-263`, throttle 3s via `pkg/coalesce/coalesce.go:41-43`), and the plan's sender has **no delta and no unchanged-skip** — every republish is a full clear + N-chunk refill. A full-table box under BGP churn re-enters the empty-FIB window nearly continuously. The issue (plan §2) explicitly rejected the permanent form of this posture ("rejected by all three reviewers"); the plan bakes in a recurring form without a "publishing" state and without quantifying the window.
- Compounding staleness: the single `fib_generation` bump at `complete` means flow-cache ALLOWs stamped `(G,F)` (`userspace-dp/src/afxdp/flow_cache.rs:124-131` pair-equality) survive the entire window — flows over *withdrawn* routes keep forwarding from cache while **new** flows to those same destinations are policy-denied. Simultaneously stale and blackholing.
- The obvious repair — apply chunks into a **shadow** partition, atomically swap + single bump at `complete` (one `publish_runtime_view`, `userspace-dp/src/afxdp/coordinator/mod.rs:1590-1598`) — is never considered. It would collapse Q2 and Q4. As specified, the design is wrong, not underspecified.

### F2 — MAJOR (premise collision): removing the cap removes the only bound on a linear-scan FIB lookup, while the fix (LPM) is explicitly out of scope

- Runtime lookup is a linear scan: `userspace-dp/src/afxdp/forwarding/fib.rs:429-431` — `routes_v4.get(table).and_then(|routes| routes.iter().find(|entry| entry.prefix.contains(ip)))`, over vecs sorted longest-prefix-first (`forwarding_build/fib.rs:160-180`). A destination matching a short prefix must scan past every longer prefix; a `NoRoute` verdict scans the whole table.
- Today the ~65k cap is an *accidental bound* on that scan. At 1M routes every cache-miss resolution and every NoRoute determination costs ~15× more. Plan §10 explicitly excludes "LPM, sharding"; §8 rates perf MED and worries about control RTTs; invariant 5 only claims zero-alloc. The plan's own target (full Internet table in the helper FIB) is unshippable as scoped. Either LPM enters scope or the 1e6 premise dies.

### F3 — MAJOR (dual-writer ambiguity): which path carries learned routes after the change is unspecified, and the two candidate carriers conflict

- Today learned routes ride `buildRouteSnapshots` → `snapshot.Routes` → `apply_snapshot` → `populate_routes` into the **same** `routes_v4/v6` maps as config routes (`pkg/dataplane/userspace/routes.go:42` ff., `addLearnedRouteSnapshots` ~:690; `forwarding_build/fib.rs:44-140`). Gap-fill precedence is enforced **Go-side at build time** (`learnedRouteGapKey`), not in the helper.
- §5c says the cap "stops declining" and "the full learned set flows through chunking" — but never states that `buildRouteSnapshots` **excludes** learned from snapshots. If it doesn't: every full publish over the cap re-triggers the original 56s-hold problem *and* installs learned routes into the main partition while `update_routes` installs the same routes into the learned partition — two writers, double install, no precedence rule (the neighbor precedent produced exactly this class of desync: #1659). If it does: `PublishRouteOverlaySnapshot` (`pkg/dataplane/userspace/manager_overlay.go:147-260`, incl. the #9054 capped-flag recompute at ~:175-190), the #7437 actuator (`daemon_route_listener.go:259`), the snapshot content-hash unchanged-skip (`manage…

### F4 — MAJOR (protocol skew): "protocol version stays at 10" while redefining `learned_route_import_capped` from gating to advisory re-creates #9054 in the helper-first upgrade direction, with no refusal gate

- v10 exists precisely so mismatched pairings refuse loudly (`userspace-dp/src/protocol/snapshot.rs:646-658`), and the tree's version doctrine forbids semantic redefinition under a shared version (`userspace-dp/src/protocol/control.rs:30-131`, the v4→v5 lesson: "two binaries… both advertise [the same version] and read the same bytes differently").
- New helper (gate deleted) + old control plane (declines import above cap, stamps `capped=true`, never chunks): the new helper adjudicates strictly → **silent total blackhole of the learned FIB for the entire mixed window** — the exact defect #9054 was filed against. §5c's "no new refusal semantics" is the bug. Needs v11 (or an equivalent loud refusal / "gate until first complete chunk table observed").

### F5 — MAJOR (generation ownership): "Rust bumps fib_generation on complete" collides with the Go-owned monotone counter

- `fib_generation` values are assigned by Go from the BPF shim map (`pkg/dataplane/userspace/manager_generation.go:10-22` `readFIBGeneration`; `BumpFIBGeneration` bumps the shim then sends the verb). The helper's bump handler refuses strictly-less (`userspace-dp/src/server/handlers/snapshot.rs:505-534`; coordinator `<` fence). A helper-side self-advance at chunk-complete desyncs Go's shim-derived stamps → next `bump_fib_generation` = "fib generation rollback rejected" → #1844 retry loop / non-convergence, and session-sync stamps (`protocol/binding.rs:1213`) skew. The bump must be Go-driven (complete-ACK → Go bumps shim → `bump_fib_generation`), which §5a does not say.

### F6 — Minor but a claimed-invariant violation: `content_digest` cleared at `complete`, not at first enforced divergence

- `neighbors.rs:54-59` clears the digest on **every applied mutation**; `snapshot.rs:120-160` is the gate it protects. Chunk 0's clear means enforced content diverges from the installed digest immediately; until `complete` a stale *matching* digest vouches for content the helper no longer enforces. The plan's own invariant 4 is misplaced in its own handler sketch.

### F7 — Minor: the 30s actuate timeout vs multi-tens-of-seconds chunk streams

- `pkg/coalesce/coalesce.go:43` `DefaultActuateTimeout = 30s` bounds `actuateLearnedRouteRefresh`. A stop-and-wait stream of 20-30 chunks over the shared socket may exceed it → reported non-converged → retry → **another clear cycle** (compounding F1). Unexamined.

### F8 — Minor: live-mutation mechanics unspecified

- Worker visibility rides Arc rotation via a full `ForwardingState` clone (`coordinator/mod.rs:1590-1598`) — tens of MB per rotation at 1M routes; per-chunk rotation is O(N×table) memcpy, and the handler sketch says nothing about rotation or about maintaining the `sort_routes` invariant (`forwarding_build/fib.rs:160-180`) when appending into live sorted vecs.

### F9 — Minor: invariant 6 mislocates gap-fill

- "Chunk insert must apply the `covered` rule per route" implies helper-side coverage logic that does not exist; gap-fill is Go-build-time (`routes.go` `learnedRouteGapKey`). Restate as "suppression precedes chunking" and own the config-changes-mid-sequence staleness explicitly.

### F10 — Verified sound (no finding)

- Serde skew: additive fields are structurally fine — `ControlRequest` has no `deny_unknown_fields` (`userspace-dp/src/protocol/control.rs:238-268`); Go `omitempty` symmetric. The #6034 fence/ACK-via-status envelope and `refresh_status`-on-every-arm idioms transfer cleanly. The #1913 chokepoint and single-recycle invariants hold under §5a's arm shape (disposition downgrade only, `poll_descriptor/mod.rs:5236-5267`). Partition-vs-tag (Q1) is mechanically answerable both ways (tag keeps the single-map lookup) and is not a kill.

---

## Answers to the eight verification questions

1. **Does the `update_neighbors` analogy transfer?** No, not where it matters. Neighbors are atomic single-message replaces of ~10² entries; §5a is a **multi-message transaction** over ~10⁶ entries with cross-verb interleaving — a consistency class with no precedent in `server/handlers/`, at 4 orders of magnitude more state, against a consumer (F2) that was never sized for it. The envelope idioms transfer; the atomicity — the property that makes `update_neighbors` safe — does not. Q6's suspicion is correct.
2. **Per-chunk vs per-table invalidation:** per-table-once is the right *frequency*, but under clear-at-chunk-0 it leaves a window of cached-ALLOW staleness over withdrawn routes (F1); under shadow-swap it would be exactly correct. As specified: neither clean.
3. **Socket math:** stop-and-wait with in-band responses is genuinely kinder than one 56s hold — *provided* chunks are sized ≤1-2 MiB (deadline ≈ 4-5s, `process_control.go:42-53`) and yield. But convergence stretches to tens of seconds (vs atomic), each chunk holds `m.mu` for its round trip (`control_shutdown_8526.go:54-56`), and the 30s actuate timeout (F7) can convert slowness into retry loops. The plan's "numbers invited" is never answered.
4. **Inter-chunk adjudication:** yes — as designed it is a *full-scale* recurring #9054 (F1), not miniature, and a "publishing" state is mandatory, not optional. The design as written defaults to the posture the issue rejected.
5. **FIB partition vs tag vs `populate_routes`:** both compose mechanically (F10), but neither fixes F2/F3; the question is subordinate to the real blockers.
6. **Gap-fill across chunk boundaries:** Go-side suppression precedes chunking, so boundaries don't break it *within* one build; the real issue is dual-carrier and mid-sequence config change (F3, F9).
7. **Should the kernel-lookup fallback win outright?** Not outright — §5b's fidelity problem is load-bearing (wrong table/iif/fwmark → wrong ifindex → wrong zone → the bypass re-enters *silently* on default-permit; Q7's enumeration is genuinely unfinished), per-miss netlink is unbounded under scan, and NoRoute flows never sessionize so *every* packet pays. But §5b is the only half that closes the filed **security** hole without moving 10⁶ routes, and it also covers #7480's residual inter-push window. §5a's marginal value over §5b is fast-path *throughput* — a performance goal outside this issue's acceptance criteria.
8. **Skew/monotonicity/digest/chokepoint invariants:** serde additive OK; fence envelope OK; but the v10 semantic redefinition (F4), fib-bump ownership (F5), and digest placement (F6) each violate an invariant the plan claims to preserve.

---

## Verdict

**NEEDS-MAJOR**

Not PLAN-KILL: the issue direction is alive, the fallback half is viable pending its own fidelity design, and the plan pre-authorizes killing §5a — but §5a as specified must not proceed, and the revision is architectural, not cosmetic. Required before any PLAN-READY:

1. **Kill §5a's clear-at-chunk-0 design.** If the chunked verb survives at all, it must build into a shadow partition and atomically swap + single-bump at `complete`, with an explicit publishing/converging state; quantify the window against the 3s throttle and the 30s actuate timeout (F1, F7).
2. **Put the FIB data structure in scope or lower the target.** No cap removal without an answer to the linear scan at 1M routes (F2). Otherwise §5a is a future LPM-gated workstream, not this fix.
3. **Specify the single carrier:** snapshots exclude learned; wire the #7437 actuator, overlay publish, dedup-skip, and apply_snapshot interplay (F3).
4. **Bump the protocol version** (or equivalent refusal) so a new helper cannot silently blackhole under an old control plane's capped snapshots (F4).
5. **Make the fib bump Go-owned** via the existing shim-counter + `bump_fib_generation` flow; clear `content_digest` at the first enforced divergence (F5, F6).
6. **Re-plan §5b as the primary candidate** with Q7's input enumeration (table selector, iif-of-reinject vs iif-of-origin, fwmark, TOS, VRF/l3mdev) and a measured per-miss cost — it plausibly dominates for this issue's acceptance criteria, but that must be demonstrated, not asserted.
