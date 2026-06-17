# Plan of Action — #1914: tunnel-endpoint collision gate, wildcard apply-groups false accept + src/dst-incomplete over-registration

- **Issue:** #1914
- **Mode:** `/research` — STOP at PLAN-READY. No PR, no production code.
- **Revision:** r3 (r2 corrected after Codex r2 caught two precision bugs:
  Defect B is NOT fixed by an unchanged view 1 even for applied groups — it
  is document-only entirely; and the SSOT emitter must return `{Name,
  *TunnelConfig}` not bare names so the builder can populate snapshot fields)
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

Because (2) and (3) are *both* computed on *both* nodes from the *same*
candidate config, the union is still a pure function of config ⇒ still
symmetric. The realization is the SSOT emitter in §4.1 (a recursion-free,
config-pure, pre-`usedIDs` helper), NOT a re-call of `CompileConfig*` (that
recurses — see §3.5-O2). See §4 for the full reconciled shape.

- **Defect A:** FIXED — post-expansion views contain the concrete `wg78.0`,
  collision with `wg1408.0` (824) detected → commit rejected.
- **Defect B:** NOT fixed — document-only (see §3.5-O1/O4). View 1 stays
  presence-only (required so the Defect-A fix does not re-open a
  false-accept), so the incomplete-non-WG phantom persists for all cases.
- **HA-symmetry:** PRESERVED — all three views are pure functions of the
  shared candidate config; both nodes compute the identical union (with
  identical per-node-expansion-error→empty-set handling, §4.3).
- **Complexity:** Medium. SSOT emitter + two extra clone+`compileInterfaces`
  passes per commit (not hot-path; `Clone()` is deep so no mutation).
- **Risk:** view 1 MUST stay byte-identical, or an un-applied-group
  cross-node collision (the `TestTunnelEndpointIDCollisionAcrossGroupsIsSymmetric`
  guarantee) stops being caught, AND narrowing it to src/dst-aware
  re-opens a false-accept (split-supply / un-applied nested-apply-groups —
  proven in §3.5-O1). The union is monotone over view 1 (adding views 2/3
  only ADDS rejects), so the existing reject set is strictly preserved.

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

## 3.5 Resolved design questions (after r1 three-way review)

All four r1 reviewers (Claude SMR + Codex + AGY) converged on the answers
below; they are now design decisions, not open questions.

- **O1 (crux) — RESOLVED: view 1 stays byte-identical (presence-only
  union).** Both the "narrow view 1 to complete-only" and "make view 1
  src/dst-aware" ideas are provably unsound:
  - Split-supply (Claude SMR, proven): `set interfaces gr-0/0/9 unit 0
    tunnel mode gre` with src/dst supplied by an applied group → a
    complete-only pre-expansion view 1 UNDER-registers (the literal AST has
    no src/dst), missing a real emitted ref.
  - Un-applied nested-apply-groups group (AGY F3 + Codex F2, proven shape):
    `groups group-c interfaces gr-0/0/0 unit 0 {tunnel mode gre;
    apply-groups my-group}` where `my-group` supplies src/dst, `group-c`
    un-applied → a complete-only view 1 drops `gr-0/0/0.0`, views 2/3 never
    expand the un-applied group, the ref is registered NOWHERE → **false
    ACCEPT**, violating the #1873 group-symmetry invariant.

  Therefore view 1 MUST remain the existing presence-only union, AND
  because view 1 includes EVERY group (applied or not — `tunnelid.go:165`)
  and registers tunnel presence with no src/dst check (`tunnelid.go:73,120`),
  **Defect B is NOT fixed by this design at all — it is document-only,
  entirely** (Codex r2 F1). Concrete proof (verified): `set groups g
  interfaces gr-0/0/0 unit 0 tunnel mode gre` + `set apply-groups g` + `set
  interfaces wg29715 unit 0 tunnel mode wireguard` — `gr-0/0/0.0` and
  `wg29715.0` both fold to 44687; view 1 registers the incomplete-GRE
  phantom even though it is APPLIED, the builder drops it (`tunnels.go:61`),
  and the union still false-REJECTS. Views 2/3 correctly exclude it, but
  view 1's union with them cannot un-register what view 1 added. So the
  earlier r2 claim "Defect B fixed for applied-group cases" was WRONG.
  Defect B's phantom false-reject (any config — main, applied group, or
  un-applied group — with an incomplete non-WG tunnel that folds onto a
  real ref) is accepted as a documented limitation (Path 4 for B), backed
  by the runtime belt. Fixing it would require narrowing view 1, which
  provably re-opens a false-ACCEPT (above) — strictly worse.
- **O2 — RESOLVED: NO double-`CompileConfig`.** Reading back
  `buildTunnelEndpointSnapshots` is WRONG for two independent reasons the
  reviewers proved: (a) `CompileConfig*` call the gate FIRST
  (`compiler.go:115-119`, `:176-180`) → calling them from the gate
  **recurses to stack overflow** (AGY F2 Critical, Codex F1); (b) the
  builder's `usedIDs` belt (`tunnels.go:100-105`) has ALREADY DROPPED one
  of the colliding pair, so the gate would see only one ref and Defect A
  would STILL false-accept (Codex F1 High). The gate must enumerate
  candidate names BEFORE any `usedIDs` drop, via a recursion-free path
  (§4).
- **O3 — RESOLVED: yes, factor an SSOT emitter, config-pure.** The emitter
  lives in `pkg/config` (no import cycle — `pkg/dataplane/userspace`
  already imports `pkg/config`). It returns the **configured** candidate
  endpoint-name set from a typed `*config.Config`; it does NOT see runtime
  `InterfaceSnapshot` rows (those don't exist at commit). The builder
  consumes the emitter and THEN intersects with runtime ifaces + applies
  `usedIDs` (AGY F4, Codex F4). The emitter is the SSOT for NAME emission
  only; runtime filtering stays in the builder. Mandatory: the builder is
  refactored to call the emitter (not a parallel copy) + a differential
  parity test guards drift (the #1910 r2-r6 drift class).
- **O4 — RESOLVED: Defect B is document-only, entirely** (corrected after
  Codex r2 F1). Because view 1 stays unchanged (required to fix Defect A
  without re-opening a false-accept, see O1), the incomplete-non-WG phantom
  false-reject persists for ALL cases — main config, applied group, AND
  un-applied group. Fixing it is mutually exclusive with the Defect-A fix
  under the pre-expansion-union design. The residual requires an incomplete
  non-WG tunnel whose unit-ref folds onto a real emitted ref (1/65535 per
  pair) — a rare, operator-visible-at-runtime (`slog.Error` belt) condition.
  Accepted + documented; the remediation is the same "rename one interface"
  the error already prints.

---

## 4. Recommended approach (RECONCILED with r1 three-way review)

**Path 1 for Defect A** (the High false accept) via a recursion-free,
pre-`usedIDs` three-view union; **Defect B is document-only, entirely**
(view 1 stays unchanged, so the incomplete-non-WG phantom persists — fixing
it is mutually exclusive with the Defect-A fix, see §3.5-O1/O4). Concrete,
reviewer-corrected shape:

### 4.1 SSOT emitter (config-pure, pre-`usedIDs`, returns Name+Tunnel)

Add a `pkg/config` emitter that, given a typed, already-expanded
`*config.Config`, returns the exact set of CONFIGURED tunnel endpoints the
builder would emit — each as a `{Name string, Tunnel *config.TunnelConfig}`
pair (Codex r2 F2: the builder needs the matching `*TunnelConfig` to
populate snapshot fields at `tunnels.go:106-129`, so a names-only return is
insufficient). The emitter applies the same non-WG src/dst gate (drop if
src or dst empty, `tunnels.go:61`), the same WG single-lowest-unit pick
(`tunnels.go:148-170`), and the same `%s.%d` canonical formatting. It does
**NOT** apply the `usedIDs` collision drop and does **NOT** consult runtime
`InterfaceSnapshot` rows (AGY F4, Codex F4 — those don't exist at commit).

Note: the leading-zero / overflow / last-wins unit canonicalization is
already resolved by `compileInterfaces` when it builds the int-keyed
`Units` map, so the emitter inherits it for free and does NOT re-implement
the AST-level logic the gate's view-1 collector carries.

`buildTunnelEndpointSnapshots` is refactored to call the emitter for its
`{Name, Tunnel}` set, then intersect with runtime `ifaceByName`, then apply
`usedIDs`. One emission truth; runtime filtering + drop stay in the builder.
The gate (views 2/3) uses only the `Name` field of the emitter output. A
differential parity test (`tunnelid_test.go`) asserts the emitter's
`{Name,Tunnel}` set == the builder's configured set (pre runtime-intersect,
pre `usedIDs`) over a tunnel-config corpus (kills the #1910 r2-r6 drift
class).

### 4.2 Gate computes a recursion-free three-view union

`validateTunnelEndpointIDCollisionAST` builds:

- **View 1 — pre-expansion presence union (UNCHANGED).** Exactly today's
  `collectTunnelEndpointNamesAST` over `interfaces` ∪ every `groups` block.
  Preserves the #1873 un-applied cross-node symmetry guarantee
  (`TestTunnelEndpointIDCollisionAcrossGroupsIsSymmetric`). Keeps its
  Defect-B over-registration (accepted residual).
- **View 2 — post-expansion node0 emitted names.** `tree.Clone()` →
  `ExpandGroupsWithVars({node:node0})` → `compileInterfaces` (the
  gate-free interfaces sub-compiler, `compiler_interfaces.go:25`, which does
  NOT call the collision gate) into a throwaway `InterfacesConfig` →
  `EmitTunnelEndpointNames`. **Never calls `CompileConfig*`** → no recursion
  (AGY F2, Codex F1).
- **View 3 — post-expansion node1 emitted names.** Same, with
  `{node:node1}`.

Union = V1 ∪ V2 ∪ V3. Reject (strict) / warn (lenient) on any fold
collision in the union. The fold and severity split are unchanged.

### 4.3 Per-node expansion errors are NON-FATAL (Claude SMR F2, Codex F3, AGY F1)

If `ExpandGroupsWithVars({node:nodeN})` fails (e.g. config defines only
`groups node0` and references `${node}`, so the node1 expansion hits
`undefined group "node1"` — `ast_groups.go:163-167`), that node's view
contributes the **empty set** to the union; it MUST NOT become the gate's
verdict. Rationale: the existing generic `CompileConfig` already falls back
to node0 for undefined `${node}` (`compiler.go:127-134`,
`TestCompileConfigForNodeBackwardCompat`), and an undefined peer group is a
separate, already-handled condition on the real per-node compile path —
the collision gate must not turn it into a spurious commit failure for a
config valid on the local node. View 1 still covers any collision in the
un-expandable group (presence union), so dropping the failed node's view
loses no real coverage.

This keeps the verdict a pure function of the candidate config (both nodes
compute identical V1∪V2∪V3 and apply identical error-to-empty-set
handling), so HA symmetry holds (Codex Info F5: confirmed no node0/node1
divergence under this construction).

---

## 5. Blast radius

- `pkg/config/tunnelid.go` — gate gains views 2/3 (clone+expand+`compileInterfaces`+emitter
  per node, non-fatal on expansion error) + the new `EmitTunnelEndpointNames`
  SSOT emitter. View 1 collector UNCHANGED. ~120 LOC.
- `pkg/dataplane/userspace/tunnels.go` — `buildTunnelEndpointSnapshots`
  refactored to source its configured-name set from `EmitTunnelEndpointNames`,
  then intersect runtime ifaces + apply `usedIDs` (no change to the emitted
  snapshot rows — parity-tested).
- `pkg/config/tunnelid_test.go` — existing 13 tests are the regression
  contract (all stay green); ADD: wildcard-false-accept rejects (strict) /
  warns (lenient) / symmetric across nodes; un-applied-`${node}`-group does
  NOT spuriously fail (Finding-2 regression); emitter↔builder differential
  parity. All existing folds (`824`, `14730`, `17799`, `50477`) stay frozen.
- No wire/protocol change. No HA sync-protocol change (`StableTunnelEndpointID`
  MUST stay byte-frozen, #1873).
- Commit-path only (not hot-path). Two extra clone+expand+`compileInterfaces`
  passes per commit/commit-check; `Clone()` is a deep copy
  (`ast.go:113-140`, Codex F-cost) so the candidate is never mutated.

---

## 6. Test plan

1. **Regression (must stay green):** all 13 existing `tunnelid_test.go`
   tests, including the frozen-fold pins and the group-symmetry test.
2. **Defect A:** the §1.1 three-line wildcard config must now FAIL strict
   commit with a `wg78.0`/`wg1408.0` + `824` + `collision` + `rename`
   error; must WARN (not error) on the lenient path.
3. **Defect A symmetry:** the wildcard config must reject identically under
   `CompileConfigForNode(tree, 0)` and `CompileConfigForNode(tree, 1)`.
4. **Defect B (document-only — pin CURRENT behavior):** a half-configured
   non-WG tunnel (no src/dst) whose unit-ref folds onto a real emitted ref
   STILL rejects (the accepted residual; view 1 unchanged). This test pins
   the limitation so a future reader knows it is intentional, not a bug;
   the doc comment + `slog.Error` belt are the operator's recourse. A
   COMPLETE GRE that genuinely collides must of course still reject.
5. **No false positives:** the existing non-colliding multi-tunnel config
   stays clean; a WG wildcard group applied to a single interface (no
   second colliding ref) compiles clean.
6. **SSOT parity:** a differential test asserting `EmitTunnelEndpointNames(cfg)`
   equals the builder's configured-name set (before runtime-iface intersect
   + `usedIDs`) for a corpus of tunnel configs (the anti-drift guard, O3).
7. **No-recursion regression:** a test that the gate on a wildcard/multi-node
   config returns in bounded time (guards against the Finding-2 recursion
   if a future edit reintroduces a `CompileConfig*` call from the gate).
8. **Non-fatal peer-group:** `groups node0 ... ; apply-groups "${node}"`
   with NO `groups node1` must COMMIT cleanly (view 3 contributes empty,
   not an error) — the Finding-2/Codex-F3/AGY-F1 regression.
9. `make test` for `pkg/config` + `pkg/dataplane/userspace`.

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
| r1 | PLAN-NEEDS-REVISION | PLAN-NEEDS-REVISION | PLAN-NEEDS-REVISION |
| r2 | PLAN-READY | PLAN-NEEDS-REVISION (2 precision bugs) | PLAN-READY |
| r3 | **PLAN-READY** | **PLAN-READY** | **PLAN-READY** |

**CONVERGED at r3** — all three reviewers PLAN-READY on the final revision.
Awaiting manual approval via `/engineer 1914`.

### r2 → r3 correction (Codex r2)

Codex r2 confirmed the r2 design core (recursion-free path, error-handling,
boundary, O1 symmetry, Defect-A fix) but caught two precision bugs in the
plan TEXT, both verified against the code:

- **Defect B is document-only, ENTIRELY** (not "fixed for applied-group
  cases"). View 1 includes every group with no src/dst check, so an APPLIED
  incomplete GRE (`gr-0/0/0.0`/`wg29715.0` both fold 44687) still
  false-rejects. r3 §3.5-O1/O4 + §4 + §6.4 corrected; §6.4 now pins the
  residual as intentional.
- **SSOT emitter returns `{Name, *TunnelConfig}`** (not bare names) — the
  builder needs the TunnelConfig to populate snapshot fields. r3 §4.1.

### r1 convergence summary

All three reviewers independently converged on the same core defects in r1
(strong signal the diagnosis was right and the recommended fix was wrong):

- **Recursion + pre-drop enumeration (Codex F1 High, AGY F2 Critical):**
  the gate cannot reuse `CompileConfig*`/`buildTunnelEndpointSnapshots` —
  recursion + the `usedIDs` belt already dropped one collider. r2 §4.1/4.2
  fix: config-pure pre-`usedIDs` emitter + gate-free `compileInterfaces`.
- **O1 crux (all three):** view 1 cannot be narrowed without re-opening a
  false-accept (split-supply + un-applied nested-apply-groups, both with
  proven shapes). r2 §3.5-O1 + §4.2 fix: view 1 stays presence-only;
  Defect-B residual documented.
- **Peer-group expansion error (SMR F2, Codex F3, AGY F1):** undefined
  `${node}` group must not fail the gate. r2 §4.3 fix: error→empty-set.
- **Emitter is config-pure, not snapshot-identical (Codex F4, AGY F4):**
  builder intersects runtime ifaces after the emitter. r2 §4.1 states the
  boundary.
