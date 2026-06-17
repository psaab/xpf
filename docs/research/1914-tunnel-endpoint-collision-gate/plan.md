# Plan of Action — #1914: tunnel-endpoint collision gate, wildcard apply-groups false accept + src/dst-incomplete over-registration

- **Issue:** #1914
- **Mode:** `/research` — STOP at PLAN-READY. No PR, no production code.
- **Revision:** r1 (draft)
- **Branch:** `research/1914-tunnel-endpoint-collision-gate`
- **Base:** `origin/master` @ `26e4a112d`
- **Author:** Claude (research driver)

---

## 1. Problem statement

`validateTunnelEndpointIDCollisionAST` (`pkg/config/tunnelid.go:162`) is the
#1873 R-B commit-time gate that fails a commit when two tunnel-endpoint
interface names fold to the same 16-bit `StableTunnelEndpointID`. It runs
on the **pre-expansion** AST (before `ExpandGroups`) by design: it collects
the **union** of tunnel names from `interfaces` and every `groups` block so
both HA nodes accept/reject identically (pre-expansion union is a pure
function of the candidate config, so node0 and node1 compute the same
verdict regardless of which `${node}`-scoped group each would actually
apply).

Two defects, both **pre-existing since #1873 R-B landed** (PR #1882) and
neither widened nor narrowed by PR #1910/#1904. Found by Codex r6 during
PR #1910 review.

### 1.1 Defect A — wildcard apply-groups false accept (High)

`collectTunnelEndpointNamesAST` hashes the **literal** group-AST interface
name. A wildcard group:

```
set groups wgtun interfaces <*> unit 0 tunnel mode wireguard
set interfaces wg78   apply-groups wgtun
set interfaces wg1408 unit 0 tunnel mode wireguard
```

registers the gate ref `<*>.0` (id **50477**), never the concrete
post-expansion `wg78.0` (id **824**). The literal `wg1408.0` registers id
**824**. The gate sees `{<*>.0=50477, wg1408.0=824}` — no collision —
and **accepts the commit**. But `ExpandGroups`' wildcard merge
(`mergeNodes`, `ast_groups.go:236`) splices the `unit 0 tunnel mode
wireguard` body onto the **existing** `wg78` interface container, so the
typed compiler emits `wg78.0` AND `wg1408.0`, **both fold to 824**. The
snapshot builder's `usedIDs` belt (`tunnels.go:101`) then drops the
later-sorting one with a loud `slog.Error` — a deterministic runtime drop
instead of a commit rejection.

**Confirmed empirically** (this research, throwaway test against master):
the above three-line config compiles clean with zero warnings; both
`wg78.unit0` and `wg1408.unit0` carry wireguard `TunnelConfig` in the typed
`cfg.Interfaces.Interfaces` map. Folds verified live: `<*>.0`=50477,
`wg78.0`=`wg1408.0`=824.

**Severity rationale:** a real builder-emitted collision escapes the
strict commit gate. The runtime belt keeps both nodes consistent (same
deterministic drop), so it is not a split-brain / TCP-death class bug — it
is a "loud silent" drop: one tunnel never installs and the operator only
learns from `slog.Error`, not a commit error. Wildcard WG groups are rare;
the per-pair fold-collision probability is 1/65535.

### 1.2 Defect B — src/dst-incomplete non-WG tunnels over-registered (Medium)

`collectTunnelEndpointNamesAST` registers a ref from **tunnel-node
presence alone**. But the builder's `addEndpoint` (`tunnels.go:62`) drops
any **non-WireGuard** tunnel whose `Source` or `Destination` is empty:

```go
if !isWireguard && (tunnel.Source == "" || tunnel.Destination == "") {
    return
}
```

So a half-configured GRE (`set interfaces gr-0/0/0 unit 0 tunnel mode
gre`, no source/dest) registers a gate ref the builder will never emit.
**Confirmed empirically:** the gate registers `gr-0/0/0.0` for exactly
this shape. If that phantom ref collides (1/65535 per pair) with a *real*
emitted ref, the commit is **falsely rejected** — the operator cannot
commit a config the builder would have accepted.

**Why it is conservative-by-design today:** AST-level src/dst presence
cannot be judged reliably pre-expansion, because apply-groups can SUPPLY
the source/destination later. A pre-expansion collector that modeled the
src/dst gate would **under-register** (false ACCEPT — strictly worse than a
false REJECT). So the current over-register is the safe direction given
the pre-expansion constraint. Item B is only fully fixable if the collector
sees an expanded view (couples to Defect A's fix).

---

## 2. Current behavior walk (code-grounded)

| Layer | Function | File:line | Sees groups? | src/dst gate? | wildcard? |
|-------|----------|-----------|--------------|---------------|-----------|
| Commit gate | `validateTunnelEndpointIDCollisionAST` | `tunnelid.go:162` | union, **pre-expansion** | no | hashes `<*>` literally |
| Gate collector | `collectTunnelEndpointNamesAST` | `tunnelid.go:61` | per-block | no (presence-only) | literal name |
| Hash | `StableTunnelEndpointID` | `tunnelid.go:25` | — | — | — |
| Expansion | `ExpandGroups` / `mergeNodes` | `ast_groups.go:13,225` | resolves | — | wildcard merges onto **existing** dst ifaces only |
| Builder | `buildTunnelEndpointSnapshots` / `addEndpoint` | `tunnels.go:13,54` | **post-expansion typed cfg** | **yes** (drops incomplete non-WG) | n/a (concrete names) |
| Runtime belt | `usedIDs` map | `tunnels.go:101` | — | — | deterministic later-sorting drop + `slog.Error` |

**Key asymmetry:** the gate runs on pre-expansion union AST; the builder
runs on the post-expansion **typed** `cfg.Interfaces.Interfaces`. The gate
therefore cannot see (a) wildcard-expanded concrete names, nor (b)
group-supplied source/destination. The builder sees both but only fails
"loudly silent" via the belt.

**Important wildcard semantics fact** (proven by reading `mergeNodes`,
`ast_groups.go:236-245`): a wildcard apply-group merges its body onto
interface containers **already present** in the dst tree — it does NOT
synthesize new interfaces. So the post-expansion concrete name set is
exactly `{ interfaces that (a) exist in the candidate AND (b) reference the
wildcard group via apply-groups }`. This bounds the cardinality and makes
post-expansion enumeration tractable.

**HA-symmetry invariant (the thing #1873 chose pre-expansion to protect):**
the accept/reject verdict must be a pure function of the candidate config
(identical bytes on both nodes ⇒ identical verdict), so config-sync never
splits (originator accepts, peer rejects). Any fix MUST preserve this. A
naive "expand for *this* node then collect" breaks it, because `${node}`
resolves differently on node0 vs node1.

---

## 3. Design space — Multiple Path Options

This is a **design-decision** issue (the issue body says so). Four viable
paths, with the HA-symmetry invariant as the hard constraint.

### Path 1 — Union of {pre-expansion} ∪ {post-expansion node0} ∪ {post-expansion node1}, all computed from the same candidate tree (RECOMMENDED)

Collect gate names from THREE views, all derived from the SAME candidate
AST on both nodes:

1. the existing pre-expansion union (unchanged — preserves the
   group-scoped-collision coverage that
   `TestTunnelEndpointIDCollisionAcrossGroupsIsSymmetric` pins), PLUS
2. the concrete tunnel names the builder would emit after expanding for
   node0, PLUS
3. the concrete tunnel names the builder would emit after expanding for
   node1.

Because (2) and (3) are *both* computed on *both* nodes from the *same*
candidate config, the union is still a pure function of config ⇒ still
symmetric. node0 expanding "what would node1 see" is deterministic (it is
just `ExpandGroupsWithVars(node1)` on the shared candidate). The gate
rejects if ANY of the three views contains a fold collision.

To make (2)/(3) faithful to the builder — including the src/dst gate
(Defect B), the WG single-lowest-unit pick, the leading-zero/overflow unit
canonicalization, and last-wins duplicate-unit — the cleanest realization
is to **reuse the actual builder path**: for each node, clone → expand →
`CompileConfig*` → `buildTunnelEndpointSnapshots` → read back the emitted
endpoint names, OR factor the name-emission out of `addEndpoint` into a
pure `config`-package helper the builder also calls (single source of
truth). See §4 for the SSOT factoring.

- **Defect A:** FIXED — post-expansion views contain `wg78.0`, collision
  with `wg1408.0` detected → commit rejected.
- **Defect B:** FIXED — views are built through the real src/dst gate, so
  incomplete non-WG tunnels are not registered (and group-supplied src/dst
  IS modeled, because expansion ran first). No phantom refs.
- **HA-symmetry:** PRESERVED — all three views are pure functions of the
  shared candidate config; both nodes compute the identical union.
- **Complexity:** Medium-high. Needs the builder's name-emission logic
  reachable from the gate (SSOT factoring) and two extra expand+compile
  passes at commit time (cost: commit is not hot-path; acceptable).
- **Risk:** the pre-expansion union (view 1) must STAY, or a collision
  hidden entirely in an un-applied `groups node1` block (no apply-groups on
  either node — see the existing symmetry test) would stop being caught.
  Keep all three; the union is monotone (more refs ⇒ stricter), so adding
  views can only ADD rejects, never remove the existing ones. That makes
  Defect-B's de-registration the ONLY direction that could *relax* a
  reject — and it only relaxes phantom (never-emitted) refs, which is
  correct.

  Subtle interaction: view 1 (pre-expansion, presence-only) STILL
  over-registers incomplete GRE refs. So keeping view 1 unchanged does NOT
  fix Defect B by itself — view 1 would still phantom-reject. **Resolution:**
  view 1's role narrows to "catch group-scoped collisions invisible to any
  single node's expansion"; to avoid re-introducing the Defect-B phantom,
  view 1 must ALSO be built through a src/dst-aware collector — but
  pre-expansion it cannot judge group-supplied src/dst. **This is the crux
  the reviewers must rule on** (see §3.5 open question O1). The honest
  framing: Path 1 fixes A cleanly; fixing B fully requires either dropping
  view 1's incomplete-GRE refs (re-opening the theoretical group-supplied
  under-register — but views 2/3 now cover the applied cases) or accepting
  that view 1 still over-registers for the *un-applied-group* corner only.

### Path 2 — Expand wildcards inside the collision pass only

Keep the gate pre-expansion but teach `collectTunnelEndpointNamesAST` to
resolve `<*>` group refs against the set of interfaces that apply that
group, producing concrete names — a narrow, gate-local mini-expander.

- **Defect A:** FIXED for the wildcard case.
- **Defect B:** NOT fixed (still presence-only).
- **HA-symmetry:** PRESERVED if the mini-expander is a pure function of the
  candidate (it is).
- **Complexity:** Medium, but introduces a SECOND expansion implementation
  that must track `mergeNodes` wildcard semantics forever (drift risk —
  exactly the class of bug #1910 r2-r6 kept finding when the gate's unit
  logic drifted from the builder's). **Anti-pattern per the repo's own
  history.** Rejected unless Path 1's cost is prohibitive.

### Path 3 — Gate only complete src+dst tunnels (Defect B narrow fix)

For non-WG tunnels, register a gate ref only when source AND destination
are present in the AST (mirror the builder's gate).

- **Defect A:** NOT fixed.
- **Defect B:** PARTIALLY fixed — but pre-expansion it cannot see
  group-supplied src/dst, so it would UNDER-register (false ACCEPT) when a
  group supplies the missing endpoint. The issue body explicitly calls this
  out as "worse than" the current over-register. Rejected as a standalone
  fix.

### Path 4 — Accept as documented limitation (do nothing structural)

Document both gaps in `tunnelid.go` + an operator doc, lean on the runtime
`usedIDs` belt + `slog.Error`, and add a metric/log so the silent drop is
observable. Optionally add a `commit` warning that says "wildcard
apply-groups tunnel refs are not collision-checked at commit; a collision
will be dropped at runtime."

- **Defect A:** UNFIXED, documented.
- **Defect B:** UNFIXED, documented.
- **HA-symmetry:** trivially preserved (no change).
- **Complexity:** Trivial. Honest about the 1/65535 × rare-feature joint
  probability.
- **Risk:** leaves a real (if rare) false-accept. Acceptable ONLY if the
  reviewers judge the joint probability (wildcard WG group × 16-bit fold
  collision) negligible and the runtime belt sufficient.

---

## 3.5 Open questions for the reviewers (design decision inputs)

- **O1 (crux):** In Path 1, does view 1 (pre-expansion union) stay
  presence-only (keeps Defect B's phantom for *un-applied-group* refs) or
  also get the src/dst gate (risk: under-register for group-supplied src/dst
  in un-applied groups)? Recommendation: keep view 1 presence-only but
  scoped to the WG/complete cases the builder can emit without expansion,
  and rely on views 2/3 for everything an apply-group touches. Reviewers
  must confirm this does not re-open a false-accept.
- **O2:** Is the two-extra-expand-and-compile cost at commit acceptable, or
  should the gate read back `buildTunnelEndpointSnapshots` output directly
  (requires the gate to live where it can call the builder — package layer
  question: `config` vs `dataplane/userspace`)?
- **O3:** Should the name-emission logic be factored into ONE pure function
  (SSOT) so the gate and `addEndpoint` can never drift again (the #1910
  r2-r6 drift class)? Strong recommendation: yes.
- **O4:** Is Defect B worth fixing at all, or is the phantom-reject (1/65535
  × half-configured-tunnel-that-also-collides) so rare that Path 4 for B +
  Path 1 for A is the right split?

---

## 4. Recommended approach (subject to reviewer convergence)

**Path 1 for Defect A** (the High-severity false accept), with the
name-emission SSOT factoring (O3 = yes). **Path 4 (document) for Defect B**
UNLESS Path 1's expanded views fix it for free — which they do for any
apply-group-touched interface; the residual is only the un-applied-group
incomplete-GRE phantom, which Path 1 view 1 can shed by registering non-WG
refs only when src+dst are present *in the expanded node views* (views
2/3), and keeping view 1 to WG + already-complete refs.

Concretely, the recommended shape:

1. **Factor a pure SSOT name emitter** in `pkg/config`: a function that,
   given a typed `*config.Config` (post-expansion), returns the exact set
   of unit-qualified endpoint names `buildTunnelEndpointSnapshots` would
   emit — same WG-lowest-unit pick, same src/dst gate, same canonical
   decimal formatting, same last-wins. `addEndpoint`/`buildTunnelEndpointSnapshots`
   then consume this helper so there is ONE name-emission truth.
   (Package note: the builder lives in `pkg/dataplane/userspace`; the
   emitter must live in `pkg/config` so the gate can call it without an
   import cycle. The builder already imports `pkg/config`, so this is the
   correct direction.)
2. **Gate computes the union** of: pre-expansion group/interface union (view
   1, narrowed to WG + complete non-WG refs to drop the Defect-B phantom)
   ∪ emitter(compile(expand(candidate, node0))) ∪
   emitter(compile(expand(candidate, node1))).
3. **Reject** if any fold collision appears in the union. Strict path
   errors; lenient path warns (unchanged severity split).

This is fully symmetric (every input is the shared candidate config),
fixes A, and fixes B for every operationally reachable case while keeping
the #1873 group-scoped-symmetry guarantee.

---

## 5. Blast radius

- `pkg/config/tunnelid.go` — gate + collector (rewrite collector path /
  add SSOT emitter call). ~80 LOC.
- `pkg/dataplane/userspace/tunnels.go` — `addEndpoint`/builder consume the
  new SSOT emitter (mechanical; no behavior change to emitted snapshots).
- `pkg/config/tunnelid_test.go` — existing 13 tests are the regression
  contract; ADD wildcard-false-accept + incomplete-GRE-phantom cases. All
  existing folds (`824`, `14730`, `17799`, `50477`) stay frozen.
- No wire/protocol change. No HA sync-protocol change (the id fold is
  untouched — `StableTunnelEndpointID` MUST stay byte-frozen, #1873).
- Commit-path only (not hot-path). Two extra expand+compile passes per
  commit/commit-check is acceptable cost.

---

## 6. Test plan

1. **Regression (must stay green):** all 13 existing `tunnelid_test.go`
   tests, including the frozen-fold pins and the group-symmetry test.
2. **Defect A:** the §1.1 three-line wildcard config must now FAIL strict
   commit with a `wg78.0`/`wg1408.0` + `824` + `collision` + `rename`
   error; must WARN (not error) on the lenient path.
3. **Defect A symmetry:** the wildcard config must reject identically under
   `CompileConfigForNode(tree, 0)` and `CompileConfigForNode(tree, 1)`.
4. **Defect B:** a half-configured GRE (no src/dst) that folds onto a real
   emitted ref must NOT falsely reject (phantom shed); a COMPLETE GRE that
   genuinely collides must still reject.
5. **No false positives:** the existing non-colliding multi-tunnel config
   stays clean; a WG wildcard group applied to a single interface (no
   second colliding ref) compiles clean.
6. **SSOT parity:** a differential test asserting the gate's emitted-name
   set equals `buildTunnelEndpointSnapshots`' emitted-name set for a corpus
   of tunnel configs (the anti-drift guard that O3 is about).
7. `make test` for `pkg/config` + `pkg/dataplane/userspace`.

No cluster smoke needed at /research time. At /engineer time: a failover
smoke is NOT required (commit-path-only change, no dataplane/VRRP/sync
code), but a `make test` + a manual two-node commit-symmetry check on the
loss cluster confirms the gate rejects identically.

## 7. Rollback

Pure revert — single PR, no migration, no persisted-state change. The id
fold is untouched so no node renumbering on rollback.

## 8. HA / cluster considerations

The whole point of the design is HA symmetry. The recommended Path 1 keeps
the verdict a pure function of the candidate config. `StableTunnelEndpointID`
is byte-frozen and untouched — no `SessionValue.FibGen` wire change, no
cross-node renumbering. The new logic adds expand-for-node0 + expand-for-node1
passes that BOTH run on BOTH nodes, so the union is identical everywhere.

## 9. Observability / docs

- Keep the runtime `usedIDs` `slog.Error` belt (defense in depth even after
  the gate closes A).
- Update the doc comments on `validateTunnelEndpointIDCollisionAST` and
  `collectTunnelEndpointNamesAST` to describe the three-view union.
- If Path 4 is chosen for B, add an operator note that incomplete non-WG
  tunnels are conservatively registered.

## 10. Alternatives considered (summary)

See §3. Path 2 (gate-local mini-expander) rejected for drift risk; Path 3
(complete-only, standalone) rejected for under-register; Path 4 (document
only) acceptable ONLY for Defect B's residual, not for the High Defect A.

## 11. Reviewer convergence ledger

See `reviewer-ids.md`. Target: 3-way PLAN-READY (Claude SMR + Codex + AGY)
on the final rev. Round verdicts recorded per round below.

| Round | Claude SMR | Codex | AGY |
|-------|-----------|-------|-----|
| r1 | pending | pending | pending |
