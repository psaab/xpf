# Claude SMR hostile plan review — #1914 r1

**Reviewer:** Claude (domain SMR + design). HOSTILE pass, not synthesizer.
**Verdict: PLAN-NEEDS-REVISION** — the diagnosis is correct and empirically
grounded, but the recommended fix (§4) is internally inconsistent on the
crux (O1) and the "view 1 narrowing" idea is provably unsound. The plan
must commit to ONE coherent collector strategy.

## What the plan gets right (verified)

- Both defects are real and I reproduced both independently:
  - Defect A: the 3-line wildcard config compiles clean, zero warnings,
    both `wg78.unit0` and `wg1408.unit0` carry wireguard tunnels (fold 824).
  - Defect B: the gate registers `gr-0/0/0.0` for a src/dst-incomplete GRE
    the builder's `addEndpoint` (`tunnels.go:62`) drops.
- The wildcard-merge fact is correct: `mergeNodes` (`ast_groups.go:236-245`)
  merges a `<*>` group body onto interface containers ALREADY present in
  dst; it never synthesizes interfaces. So post-expansion concrete names are
  enumerable and bounded.
- The HA-symmetry framing is the right hard constraint.
- Rejecting Path 2 (gate-local mini-expander) for drift risk is correct —
  the #1910 r2-r6 history is exactly that drift class.

## FINDING 1 (Critical to the design) — the "narrow view 1 to complete-only" idea is unsound; split-supply breaks it both ways

§4 and O1 propose keeping view 1 (pre-expansion union) but "narrowed to WG
+ already-complete refs to drop the Defect-B phantom." I constructed the
counter-examples that kill this:

- **Split-supply (proven):** `set interfaces gr-0/0/9 unit 0 tunnel mode
  gre` with `source`/`destination` supplied by `set groups endp interfaces
  gr-0/0/9 unit 0 tunnel source/destination ...` + `apply-groups endp`.
  Post-expansion the builder EMITS `gr-0/0/9.0` (mode=gre, src=10.0.0.1,
  dst=10.0.0.2). Pre-expansion, view 1 walking the `interfaces` block sees
  `gr-0/0/9` with mode but NO src/dst → a "complete-only" view 1 would NOT
  register it (under-register). If that ref collides with a real one, view 1
  misses it. Views 2/3 (post-expansion) DO catch it — so view 1 narrowing
  buys nothing and risks a miss.
- **Un-applied complete group (proven):** `groups node1 interfaces gr-0/0/9
  unit 0 tunnel {mode gre; source; destination}` with NO apply-groups on
  node0. The current presence-only view 1 registers `gr-0/0/9.0` (fold
  11775) — this is the symmetry guarantee that
  `TestTunnelEndpointIDCollisionAcrossGroupsIsSymmetric` pins. Views 2/3
  would NOT see it on node0 (node0 never applies it) and node1 can't even
  compile it (`groups node1` referenced via `${node}` is undefined for the
  un-applied case). So view 1 is the ONLY thing covering the un-applied
  cross-node collision, and it MUST stay presence-only to do so reliably —
  the moment you make it src/dst-aware you break split-supply.

**Conclusion:** view 1 must stay EXACTLY as-is (presence-only union). That
means Defect B's phantom for incomplete non-WG tunnels in view 1 is NOT
removable without re-opening a false-accept. The plan's §4 claim "Path 1
fixes B for every operationally reachable case while keeping the symmetry
guarantee" is FALSE as written — it conflates "views 2/3 fix B for applied
groups" (true) with "view 1 can be narrowed to fix the rest" (unsound).

**Required revision:** commit to this clean split:
- **View 1 stays byte-identical to today** (presence-only union — fixes
  nothing, breaks nothing, preserves #1873 cross-node symmetry).
- **Views 2/3 (post-expansion node0/node1) are ADDED** and fix Defect A in
  full and Defect B for every applied-group case (they run the real
  builder src/dst gate).
- **Defect B's residual** = an incomplete non-WG tunnel that (a) appears in
  view 1's presence-only union AND (b) is never emitted by either node's
  builder AND (c) folds onto a real emitted ref. This residual is a
  phantom false-REJECT, and since view 1 cannot be narrowed without
  re-opening a false-accept, the ONLY safe options for the residual are:
  (i) accept it (document — Path 4 for B), or (ii) compute view 1's union
  from the post-expansion node0 ∪ node1 emitted sets ONLY and DROP the raw
  pre-expansion presence union — but that loses the un-applied cross-node
  symmetry guarantee (#1873 test fails). So (i) is the answer.

The plan already half-says this in §4's last sentence but then contradicts
itself with the "narrow view 1" clause. Pick (i) explicitly.

## FINDING 2 (High) — does Path 1 actually preserve cross-node symmetry once views 2/3 are added? Yes, but the un-applied-group compile-error needs handling

Probed: `groups node0 interfaces wg500 ... ; set interfaces wg500
apply-groups "${node}"`. `CompileConfigForNode(tree, 1)` ERRORS:
`apply-groups references undefined group "node1"`. So "emitter(compile(
expand(candidate, node1)))" cannot be computed when node1's group is
undefined. The gate must NOT propagate that compile error as the gate's
verdict (that would make the gate reject a config that node0 commits fine
and node1 would too via its own real compile error path elsewhere). The
revision must specify: **if a per-node expansion/compile fails, that node's
view contributes the empty set to the union (or falls back to view 1
only)** — NOT a gate error. Otherwise commit symmetry breaks: node0's gate
would reject because "node1's view failed to compile" even though that is a
separate, already-handled condition. This is a real correctness hole the
plan does not address.

## FINDING 3 (Medium) — SSOT emitter: confirm no import cycle, and that the emitter is the EXACT builder logic

The plan's O3 (factor the name emitter into `pkg/config`) is the right
call. Verified the import direction is sound: `pkg/dataplane/userspace`
already imports `pkg/config` (`tunnels.go:10`), so moving the
name-emission into `pkg/config` and having the builder call it introduces
NO cycle. But the plan must mandate a **differential parity test** (it does
in §6.6) AND state that `buildTunnelEndpointSnapshots` is REFACTORED to
call the emitter (not a parallel copy) — otherwise the drift the SSOT is
meant to kill survives. Make the SSOT consumption mandatory, not optional.

## FINDING 4 (Medium) — double-compile cost + tree mutation safety

The plan claims two extra expand+compile passes are acceptable (commit is
not hot-path) — agreed. Tree mutation: `CompileConfig*` Clone() the tree
before ExpandGroups (`compiler.go:123,182`), so compiling node0 then node1
from the same candidate is safe. BUT if the gate calls
`ExpandGroupsWithVars` directly on the candidate to build views 2/3, it
MUST Clone() first (the gate today does NOT clone — it reads the raw tree).
Spell this out: the view-2/3 construction clones per node.

## FINDING 5 (Low) — frozen-fold contract + lenient severity unchanged

Good that the plan freezes `StableTunnelEndpointID` and keeps the
strict-error / lenient-warn split. Confirm the new wildcard/Defect-A
rejections also follow the lenient-warns path (an already-active config
with a wildcard collision must still BOOT on load/peer-sync). §6.2 covers
this — keep it.

## Required revisions for r2

1. **§4: drop the "narrow view 1" clause.** State explicitly: view 1 stays
   byte-identical (presence-only union); Defect B's un-applied-group
   residual is ACCEPTED + documented (Path 4 for B); views 2/3 fix A fully
   and B for all applied-group cases. (Finding 1)
2. **Add per-node-compile-failure handling:** a failed node expansion
   contributes empty to the union, never a gate error. (Finding 2)
3. **Mandate the builder consumes the SSOT emitter** (not a copy) + the
   differential parity test. (Finding 3)
4. **Specify Clone() before per-node expansion in the gate.** (Finding 4)
5. Optionally tighten O4: with Finding 1, the answer to O4 is decided —
   Defect B is document-only for its residual; the applied-group part is
   fixed for free by views 2/3.

With these, the design is sound and I will move to PLAN-READY.
