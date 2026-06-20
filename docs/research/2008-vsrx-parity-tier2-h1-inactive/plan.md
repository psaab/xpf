# #2008 H1 — `inactive:` statement support (deactivate without delete)

**Status:** DRAFT v1 (draft-fanout, not yet reviewed)
**Base:** origin/master (`c4e7c77cd9a0801ba290b24ae3302e78d6864058`)
**Issue:** #2008 — vSRX config parity audit. This plan scopes ONLY **H1**
(`inactive:` statement marker), the highest-severity silent-drop gap and the
designated first `/research` target. Other Tier-2 items (H6 login-class RBAC,
M5 application-id app_id plumbing, M1 persist-groups-inheritance, M6 stateful
ALG transforms) are explicitly out of scope — see §10. `/research` only — no
production code in this branch.

---

## 1. Issue framing

Junos lets an operator **deactivate** any configuration node without deleting
it by prefixing the statement with `inactive:`:

```
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                inactive: address 192.168.50.210/24;   # leaf deactivated
            }
        }
    }
}
security {
    policies {
        from-zone trust to-zone untrust {
            inactive: policy long-ass-ssh {            # whole block deactivated
                ...
            }
        }
    }
}
```

The semantics are: **the node is parsed and retained verbatim in the
configuration database (so `show configuration` displays it, it survives commit
and reboot, and `activate` can re-enable it), but it is excluded from
compilation/application — the firewall behaves as if the statement were
absent.** It is the config-management equivalent of commenting code out: the
intent is preserved and reversible, but inert.

### What xpf does today (the bug)

`inactive:` lexes as a single identifier token because `:` is an identifier
character (`pkg/config/lexer.go:241-249`, `isIdentChar` includes `':'`). The
parser therefore produces a node whose **first key is the literal string
`"inactive:"`**:

- `inactive: address 192.168.50.210/24;`
  → `Node{Keys: ["inactive:", "address", "192.168.50.210/24"], IsLeaf: true}`
- `inactive: policy long-ass-ssh { ... }`
  → `Node{Keys: ["inactive:", "policy", "long-ass-ssh"], Children: [...]}`

Every compiler walk and the schema-validation walk key off `Keys[0]`
(`FindChild`/`FindChildren` in `ast.go:78-96` compare `child.Keys[0] == name`;
direct `range node.Children` switches compare `m.Name()` which is `Keys[0]`;
`schema_walk.go:226` does `keyword := node.Keys[0]`). Since no consumer matches
`Keys[0] == "inactive:"`, **the node is silently skipped**: not compiled, not
schema-validated, not flagged. The operator's "deactivate this" intent is lost
in the WRONG direction in some cases (a deactivated `address` is correctly
absent, but a deactivated `policy` is *also* absent — which happens to match
Junos here only because the surrounding container still compiles; the danger is
the inverse and the silent-no-error part).

Worse failure modes than "happens to match":
- `inactive:` on a node that the compiler would otherwise REQUIRE (e.g.
  `inactive: address` on the *only* address of a needed interface) silently
  drops it with no commit warning — operator thinks the address is merely
  deactivated and re-activatable, but `activate` has nothing defined to find it
  by key (the key is mangled).
- Round-trip is **broken on the display side**: `show configuration` re-emits
  the node via `ast_format.go` `QuotedKeyPath()`, which would print
  `inactive: address 192.168.50.210/24;` correctly *by accident* (the literal
  `inactive:` is just the first key) — but `set`/`delete`/`activate` path
  matching, JSON/XML rendering, group-merge key matching, and config-compare
  all treat `inactive:` as part of the node identity, which is wrong.

The reference `vsrx.conf` uses `inactive:` **10 times** across 7 distinct
subsystems (interface address, security policy, system services dns-proxy,
static route next-hop, syslog stream, syslog profile, security address-set,
forwarding-options leaf, traceoptions block, more), so this is not a corner
case — it is a pervasive operator idiom the audit config exercises broadly.

---

## 2. Honest scope / value

**Value:** HIGH for correctness/parity, MEDIUM-LOW for runtime performance
(this is a control-plane / config-grammar feature; zero packet-path impact).
The audit ranks H1 as the highest-severity silent-drop and the strongest first
`/research` target precisely because (a) it appears 10× in the reference
config, (b) the current behavior is a *silent* divergence from Junos with no
commit error, and (c) it is a foundational config-management primitive that
operators rely on for safe, reversible changes (deactivate-then-re-activate is
the Junos idiom for "try without committing to deletion").

**Cost:** MEDIUM. The marker itself is trivial, but it is **cross-cutting**:
it interacts with the parser, the AST node model, group expansion, flat-set
parsing, ~15 compiler files, the schema-validation walk, all 5 display
serializers (text/inheritance/set/JSON/XML), config-compare, and the
`activate`/`deactivate` CLI verbs (which do not exist yet). The audit's own
one-line sketch ("~40-80 LOC, 10-15 compiler funcs; group-expansion
interaction risk") understates the display and CLI-verb surface.

> If reviewers conclude the perf gain/scope is too small to justify the churn,
> PLAN-KILL is acceptable. (For H1 the framing is correctness-not-perf: the
> kill criterion is "the centralized-strip design does not actually keep the 15
> compilers untouched, OR the CLI `activate`/`deactivate` verbs balloon this
> past one reviewable PR" — see §11.)

---

## 3. What's already shipped (do not re-do)

The #2008 audit baseline predates several Tier-1 landings. Confirmed on this
base:
- **H11 (`any-ipv4`/`any-ipv6`)** is DONE: `normalizePolicyAddrToken` in
  `compiler_security.go:205` already maps `any-ipv4 → 0.0.0.0/0` and
  `any-ipv6 → ::/0`. Not part of H1.
- The AST `Node` struct (`ast.go:10-36`) already carries non-identity metadata
  fields (`Annotation`, `InheritedFrom`) that survive `cloneNodes`
  (`ast.go:123-140`) and JSON marshal — establishing the exact pattern an
  `Inactive bool` field would follow.
- **Persistence is JSON of the `Node` struct**, NOT text re-parse:
  `db.go:190` `json.MarshalIndent(tree, ...)` and `db.go:179`
  `json.Unmarshal(data, tree)`. This is the single most important shipped fact
  for H1 — it means a new struct field round-trips through the config DB
  automatically (see §6/§7), and the text Format() path is display-only.

There is **no existing `inactive:`/`activate`/`deactivate`/`protect` handling
anywhere** in `pkg/config`, `pkg/cli`, `pkg/cmdtree`, or `pkg/configstore`
(grep-verified). This is net-new.

---

## 4. Concrete design

The design has one load-bearing decision (the **parse model**) and two
dependent decisions (where to strip for compilation; whether to ship the CLI
verbs). Multiple viable paths are presented in §4.1; the rest of §4 assumes the
**recommended** path (Path A — node flag + centralized strip).

### 4.1 PATH OPTIONS — parse model

**Path A (RECOMMENDED): `Inactive bool` flag on `Node`, stripped from Keys.**
The parser detects a leading `inactive:` token in `parseKeys`, sets
`node.Inactive = true`, and removes `"inactive:"` from `Keys`. The node's
identity (`Keys`) becomes the *real* statement (`["address", "192.168.50.210/24"]`),
so all existing key matching — FindChild, group-merge, schema walk, set/delete
navigation — works UNCHANGED on the real keys. A single centralized
`stripInactiveNodes` pass on the cloned tree (inside `compileConfigWithOpts`,
just after `tree.Clone()` at `compiler.go:171`) prunes inactive subtrees before
ExpandGroups + compile, so **none of the 15 compiler files change**. The
display serializers re-emit the `inactive:` prefix from the flag.
- Pros: zero compiler-file churn; key matching stays correct; matches the
  `Annotation`/`InheritedFrom` precedent; JSON round-trip is automatic.
- Cons: every display serializer (5 of them) + config-compare must learn to
  re-emit the prefix from the flag (miss one → asymmetric display, but never a
  semantic loss because the flag persists). Flat-set parsing needs care
  (`set ... inactive ...` is NOT how Junos models it — see §4.4).

**Path B: keep `inactive:` as `Keys[0]` (token-in-place), teach consumers.**
Leave the parse output as-is and add `inactive:` recognition to FindChild,
FindChildren, the schema walk, group-merge, and each compiler switch.
- Pros: no parser change; display is already correct by accident.
- Cons: must touch EVERY consumer (the 15 compiler files + schema walk +
  ast.go matchers + group-merge) — exactly the churn Path A avoids; high risk
  of missing a walk (silent re-introduction of the bug for that subsystem);
  `activate`/`deactivate` would have to rewrite `Keys[0]`. Strongly dispreferred.

**Path C: strip-at-parse (drop inactive nodes entirely during parse).**
Discard inactive nodes at parse time so they never enter the tree.
- Pros: trivial compiler/display story.
- Cons: **breaks the core semantic** — the node must be RETAINED for
  `show configuration`, persistence, and `activate`. This is not Junos
  `inactive:`; it is delete-on-parse. Rejected.

> Recommendation: **Path A.** It localizes the change to (1) parser, (2) one
> AST field + clone/JSON, (3) one centralized strip pass, (4) the display
> serializers, and (5) the optional CLI verbs — and keeps the 15 compilers and
> the schema walk untouched, which is the entire value proposition of the
> design.

### 4.2 Parser change (Path A)

In `parser.go` `parseStatement`/`parseKeys` (lines 96-167): after collecting
keys, detect `keys[0] == "inactive:"` (and tolerate `"inactive"` followed by a
bare `:` token only if a future lexer change splits it — currently it is one
token). Strip the marker and set a flag carried into the returned `Node`.
Cleanest: have `parseStatement` peek the first key, set
`node.Inactive = true`, and slice `keys = keys[1:]`. Guard the
`len(keys)==0 after strip` case (a lone `inactive:` with nothing after is a
parse error — add a `ParseError`).

> Junos also supports `protect:` (prevents modification) and the `apply-flags
> omit` marker. **Out of scope** — H1 is `inactive:` only. The parser hook
> should be written so a sibling `protect:` flag is a mechanical addition
> later, not a redesign.

### 4.3 AST field + persistence

Add to `Node` (`ast.go`):
```go
// Inactive marks a node deactivated via Junos `inactive:`. The node is
// retained in the tree (display, persistence, activate/deactivate) but
// excluded from compilation/application. JSON-tagged omitempty so existing
// persisted configs and the on-disk format are unchanged for active nodes.
Inactive bool `json:",omitempty"`
```
Wire it into `cloneNodes` (`ast.go:129-137`) alongside `Annotation`/
`InheritedFrom`. **No db.go change needed** — `json.MarshalIndent`/`Unmarshal`
pick up the field automatically; `omitempty` keeps active-node output
byte-identical, so existing active.json/candidate.json/rollback slots are
unaffected (an old DB has no `Inactive` key → unmarshals to `false` → active,
correct).

### 4.4 Flat-set / `set` and `activate`/`deactivate` grammar

Junos does NOT model deactivation as `set ... inactive`. It is a separate verb:
`deactivate <path>` sets the flag; `activate <path>` clears it. Two sub-options:

- **4.4-i (RECOMMENDED for H1 core): parse-only round-trip, defer the verbs.**
  Support reading `inactive:` from a loaded/parsed config (hierarchical and the
  `load set` flat form if any), persist+display it, and exclude it from
  compile. Do NOT add `activate`/`deactivate` CLI verbs in the first PR. This
  is the minimal shippable increment that closes the silent-drop and makes the
  reference config compile faithfully. Operators set it by `load`-ing config
  text containing `inactive:`.
- **4.4-ii: full verbs.** Add `activate`/`deactivate` to cmdtree + the config
  set/delete path (`configstore` candidate mutation that flips `Node.Inactive`
  via `findNodeWithParent`), with tab completion. Larger; can be increment 2.

> The flat-set lexer treats `inactive:` as just another token; if a `load set`
> stream ever contains `set ... inactive: ...` it must be handled, but the
> common authoring path is `deactivate <path>` (verb) and the common
> load path is hierarchical text. Increment 1 = 4.4-i.

### 4.5 Centralized compile-time strip (Path A)

Add `stripInactiveNodes(tree *ConfigTree)` to `pkg/config` (e.g. `ast.go` or a
new `inactive.go`) that recursively removes any node with `Inactive == true`
from a tree's children. Call it inside `compileConfigWithOpts`
(`compiler.go:171`, on the already-cloned tree) and inside
`compileConfigForNodeWithOpts`. **Ordering vs ExpandGroups is a real design
question** — see §5 and Q1: strip BEFORE ExpandGroups so an
`inactive: apply-groups foo` correctly suppresses the inheritance, and so an
inactive node inside a `groups {}` body is pruned consistently.

The schema-validation walk (`schema_walk.go`) runs on an expanded tree in
`schemaValidateExpandedTreeForNode` (`store.go:526`). Because strip happens
inside the compile entry points but schema-validate is a SEPARATE pre-compile
gate (`store.go:471`), **schema-validate must ALSO strip first** (or share the
same pruned tree). Decision: factor a `tree.WithoutInactive()` clone-and-prune
helper and apply it at both the compile entry and the schema-validate entry, so
a deactivated typed leaf with a deliberately-invalid value does not fail
commit (Junos accepts deactivated garbage — the whole point of deactivate is to
park work-in-progress). This is a subtle correctness requirement, not optional.

### 4.6 Display serializers re-emit the prefix (Path A)

`ast_format.go`: `formatNodes`, `formatNodesInheritance`, `formatSetNodes`,
`formatXMLNodes`/`formatXMLLeaf`, `nodesToJSON`, and the compare path
(`formatPrefixed`, `diffNodes`/`nodesEqual`) must emit `inactive:` when
`n.Inactive`. For text: prefix the line with `inactive: ` before
`QuotedKeyPath()`. For set form: Junos shows `deactivate <path>` lines after
the `set` lines rather than an inline token — decide display fidelity in Q5.
For JSON/XML: add an attribute/marker (Junos XML uses `inactive="inactive"` on
the element). `nodesEqual` must treat differing `Inactive` as a difference so
`activate`/`deactivate` shows in `show | compare`.

---

## 5. Hidden invariants this must not break

- **Dual-AST (hierarchical vs flat-set):** the compiler handles BOTH node
  shapes (CLAUDE.md). `inactive:` must be recognized in the hierarchical shape
  (token at `Keys[0]`) and must not corrupt flat-set token grouping. Path A's
  strip-at-parse-into-flag normalizes both shapes to the same `Inactive` flag,
  which is the safe invariant. Tests MUST use `ParseSetCommand()`+`SetPath()`
  for the flat form, never `NewParser()` on multi-line set text (CLAUDE.md
  gotcha).
- **Group expansion ordering (HIGHEST RISK):** `ExpandGroups` merges group
  bodies keyed on `Keys[0]` (`ast_groups.go` `mergeNodes`/`hasMatchingLeaf`).
  If strip runs AFTER expansion, an `inactive: apply-groups` is meaningless
  (already expanded). If a group body itself contains `inactive:` nodes, those
  must be pruned too. Strip BEFORE expand (§4.5) is the proposed invariant;
  Q1 must confirm Junos semantics (does deactivating an `apply-groups`
  statement deactivate the inherited config? Yes in Junos).
- **HA / failover ordering:** config sync (`Store.SyncApply`) compiles the
  peer-synced tree with `CompileConfigForNodeLenient`. The strip pass MUST run
  on BOTH nodes identically so the two cluster members compile the same active
  set — otherwise a deactivated policy is live on one node and dead on the
  other (split-brain firewall posture). Centralizing strip in
  `compileConfigForNodeWithOpts` (shared by both nodes) preserves this. The
  persisted tree synced between nodes carries the `Inactive` flag via JSON, so
  both sides see the same flag. **No new control-socket request, no per-packet
  or per-session work** — this is compile-time only, so the control-socket
  contention and HA-watchdog logging rules (CLAUDE.md) are not engaged.
- **Boot-class / fail-closed (#1960):** `Store.Load` compiles the persisted
  active config with the lenient path. A config that previously compiled must
  still compile; adding strip can only REMOVE nodes from the compiled set, so
  it cannot turn a compilable config into a non-compilable one — but it CAN
  change the *active behavior* of a config on upgrade if the old build was
  silently dropping `inactive:` nodes anyway (it was — same net effect). Verify
  the boot-class classifier (compileFailed-first) is unaffected: strip never
  introduces a compile error. **Subtle:** a config where the OLD build kept a
  mangled `["inactive:", ...]` node and the NEW build strips it produces the
  SAME compiled output (both exclude it), so no behavior change on upgrade —
  confirm in a test.
- **Hot-path allocation:** none. Strip is a one-time compile-time tree walk.
  No Rust/dataplane change. No byte-order surface (this is text/JSON config,
  not a `__be32` map field).
- **`omitempty` / on-disk compatibility:** active nodes must serialize
  identically to today (no new `"Inactive": false` noise) — `omitempty`
  guarantees this; assert byte-identical JSON for an all-active tree in a test.

---

## 6. Public API preservation

- `Node` struct gains a field — additive, backward compatible. Existing callers
  constructing `Node{Keys: ...}` get `Inactive: false` (active), unchanged.
- `CompileConfig*` signatures unchanged.
- `ConfigTree.Format()`/`FormatSet()`/`FormatJSON()`/`FormatXML()` outputs
  change ONLY for trees that contain inactive nodes (which today render the
  mangled `inactive:`-as-first-key form anyway). Golden-file tests for existing
  active configs must remain byte-identical.
- DB on-disk format: backward+forward compatible via `omitempty` (old reader
  ignores unknown future keys is N/A — this is the same build; an old DB has no
  `Inactive` key → `false`). No envelope/version bump required.
- gRPC/REST config endpoints surface `Format*` output — same compatibility.

---

## 7. Risk table

| Risk | Severity | Likelihood | Mitigation |
|---|---|---|---|
| A display serializer (one of 5 + compare) forgets the prefix → `show config` drops `inactive:` on round-trip | HIGH (operator can't see deactivation) | MEDIUM | Single shared `nodePrefix(n)` helper used by all serializers; golden round-trip test parse→Format→parse for every reference-config inactive site |
| Strip runs in wrong order vs ExpandGroups → `inactive: apply-groups` not honored, or group-internal inactive leaks | HIGH (wrong active posture) | MEDIUM | Strip BEFORE expand at the single compile entry; explicit test with group + inactive interaction; confirm Junos semantics (Q1) |
| Schema-validate does NOT strip → deactivated invalid leaf fails commit (Junos accepts it) | MEDIUM (false commit reject) | MEDIUM-HIGH | Apply the same `WithoutInactive()` prune at the schema-validate entry (`store.go:471`); test a deactivated leaf with deliberately-bad value commits clean |
| HA: strip differs between nodes → split-brain active set | HIGH (security posture divergence) | LOW | Centralize in `compileConfigForNodeWithOpts` shared by both nodes; flag synced via JSON; `make test-failover` after change; test both-node compile equality |
| Upgrade behavior change (old build dropped mangled node, new build strips) | LOW (net-identical exclusion) | LOW | Test old-mangled-form vs new-flag-form compile to identical `*Config` |
| Lone `inactive:` with no following statement → parser panic / empty Keys | MEDIUM (commit crash) | LOW | Guarded parse error; fuzz/unit test `inactive: ;` and `inactive:` at EOF |
| `activate`/`deactivate` CLI verbs balloon scope past one PR | MEDIUM (scope) | MEDIUM | Increment 1 = parse/persist/display/strip only (§4.4-i); verbs are increment 2 |
| Flat-set `load set` containing `inactive:` mishandled | LOW | LOW | Increment 1 covers hierarchical load; add flat-set test; document |

Risk classes: **correctness** (display drop, strip-order, schema-validate,
upgrade, parser panic), **HA/failover** (split-brain), **scope** (CLI verbs),
**compatibility** (on-disk JSON — mitigated by omitempty).

---

## 8. Test plan

**Unit / Go tests (primary — this is a control-plane feature):**
1. Parser: hierarchical `inactive: address ...` and `inactive: policy { }`
   produce `Inactive=true` + clean `Keys`; lone `inactive:` errors.
2. Round-trip: parse→`Format()`→parse yields identical tree (flag preserved)
   for every inactive site in `vsrx.conf`; same for FormatSet/JSON/XML.
3. Compile strip: a config with an `inactive:` policy compiles to a `*Config`
   with that policy ABSENT; the active sibling present. Assert against the
   active-only equivalent config (identical `*Config`).
4. Group interaction: `inactive: apply-groups g` suppresses g's inheritance;
   inactive node inside `groups {}` body is pruned. (Q1-gated.)
5. Schema-validate: a deactivated typed leaf with an invalid value commits
   clean (no false reject); the active sibling with the same bad value rejects.
6. On-disk: all-active tree marshals byte-identical to today (omitempty).
   Inactive flag survives WriteActive→ReadActive.
7. Upgrade equivalence: old-mangled `["inactive:",...]` node and new-flag node
   compile to identical `*Config`.
8. Dual-AST: flat-set path (`ParseSetCommand`+`SetPath`) for any flat form.
9. HA: both-node compile (`CompileConfigForNode` n0 vs n1) excludes the same
   inactive nodes.

**Live / lab validation:**
- **Does NOT require the loss cluster for the core (increment 1)** — it is
  pure config-grammar, fully covered by Go tests + a `commit` on the standalone
  VM showing the deactivated stanza absent from `show security policies` /
  `show configuration` (with `inactive:` displayed).
- **`make test-failover` IS required IF the change touches the node-aware
  compile path** (it does, via `compileConfigForNodeWithOpts`) — run it once to
  confirm no HA regression, even though no failover behavior changes. Per
  CLAUDE.md, any change touching cluster/sync/failover code MUST pass
  `make test-failover` before commit.
- Multi-increment: increment 1 (parse/persist/display/strip) is lab-light;
  increment 2 (`activate`/`deactivate` CLI verbs + cmdtree completion) is
  CLI-surface and validated on the standalone VM, not the cluster.

---

## 9. Documentation to update (part of the contract)

- `docs/config-schema.md` — note `inactive:` as a universal node modifier and
  the strip-before-compile contract.
- `docs/feature-gaps.md` — move `inactive:` from gap to supported.
- Module doc near `pkg/config` (parser/AST) describing the `Inactive` flag and
  the centralized strip invariant (where it runs, ordering vs ExpandGroups).

---

## 10. Out of scope (explicitly)

- **H6** login-class RBAC, **M5** application-id `app_id` plumbing, **M1**
  persist-groups-inheritance, **M6** stateful ALG transforms — separate Tier-2
  items, each needs its own `/research`. Do NOT plan them here.
- `protect:` and `apply-flags omit` markers (siblings of `inactive:`) — note
  the parser hook should make them mechanical later; not implemented here.
- `activate`/`deactivate` CLI verbs are increment 2 (§4.4-ii), not increment 1.
- The cross-cutting "accepted-but-unenforced commit-warning lint" the audit
  recommends — separate work.
- Any dataplane/Rust change — H1 has none.

---

## 11. Open questions (for adversarial review)

1. **Strip vs ExpandGroups ordering:** confirm Junos semantics — does
   `inactive: apply-groups foo` deactivate the *inherited* config? (Believed
   yes.) And must an inactive node inside a `groups {}` body be pruned before
   or after the group is referenced elsewhere? This determines whether strip
   runs before or after expand, and whether it must run on group bodies too.
2. **Schema-validate strip:** is it definitely correct that a deactivated leaf
   with an invalid value should commit clean (Junos parks WIP)? Or does Junos
   still syntax-validate deactivated leaves? If the latter, we must strip for
   the *compiler* but NOT for syntax validation — a different split than §4.5.
3. **CLI verb scope:** should increment 1 ship parse/persist/display/strip ONLY
   (no `activate`/`deactivate` verbs), or are the verbs table-stakes for the
   feature to be useful (operators can't set `inactive:` without `load`)? This
   decides one-PR vs two-increment.
4. **Display fidelity for `show | display set`:** Junos emits `deactivate
   <path>` lines (not an inline `inactive:` token) in set-format output. Do we
   match that, or emit an inline marker? Affects `formatSetNodes` and any
   tooling that round-trips set output.
5. **Path A vs Path B:** is the centralized-strip claim ("15 compilers
   untouched") actually airtight, or are there compiler walks that read
   `Keys[0] == "inactive:"`-adjacent structure (e.g. a walk that counts
   children before strip, or a pre-expand AST gate like
   `validateTunnelEndpointIDCollisionAST` at `compiler.go:163` which runs on the
   PRE-expansion / pre-strip tree)? The tunnel-id collision gate in particular
   runs before strip — does it need to ignore inactive tunnel definitions?
6. **JSON/XML attribute form:** what exact representation should JSON and Junos
   XML use for inactive (`inactive="inactive"` attribute in XML; what in JSON)?
   Must not collide with existing keys.
7. **`nodesEqual` / compare semantics:** should `show | compare` show a pure
   activate/deactivate (no content change) as a diff? (Junos does.) Confirm the
   `Inactive` field participates in equality.

---

## 12. Claude self-SMR (hostile)

**Strongest objection:** The plan's entire value proposition is "Path A keeps
the 15 compilers and the schema walk untouched via one centralized strip." If
that claim is even slightly false — e.g. a pre-expansion AST gate
(`validateTunnelEndpointIDCollisionAST` runs on the pre-strip tree,
`compiler.go:163`), or a compiler that inspects sibling structure in a way
that strip perturbs — then Path A degrades toward Path B's whack-a-mole and the
"40-80 LOC" estimate is wrong. Q5 is therefore not a nicety; it is the
load-bearing question. Second objection: the **display surface is wider than
the audit's one-liner** (5 serializers + compare + the JSON/XML attribute
question + the set-form `deactivate` fidelity), and a single missed serializer
silently drops the operator's deactivation from `show configuration` — a
correctness regression dressed as a cosmetic one. Third: without the
`activate`/`deactivate` verbs (increment 1), the feature is only reachable via
`load`, which an adversary will reasonably call "half a feature."

**Counter to my own objections:** (1) Even if a pre-expand gate needs an
inactive-aware tweak, that is ONE additional site, not 15 — Path A still wins
decisively over Path B; Q5 converts the risk into a checklist item. (2) The
display risk is fully mitigated by a single shared `nodePrefix`/`nodeAttr`
helper + an exhaustive parse→Format→parse golden test over every reference-
config inactive site — a missed serializer fails that test, it cannot ship
silently. (3) The `load`-only reachability is a legitimate but bounded scope
call: increment 1 closes the *silent-drop correctness bug* (the actual #2008 H1
defect — config that should be inert is faithfully inert and visible), and the
verbs are a clean, independently-shippable increment 2.

**Disposition: LIKELY-DEFER-MULTI-INCREMENT.**
- **Increment 1 (shippable first PR):** parser flag + `Node.Inactive` +
  clone/JSON + centralized `stripInactiveNodes` (compile + schema-validate) +
  all display serializers + `nodesEqual` + docs + the Go test matrix in §8 +
  one `make test-failover` pass. This is one reviewable PR that fully closes
  the H1 silent-drop, and is the recommended path.
- **Increment 2 (separate PR):** `activate`/`deactivate` CLI verbs in cmdtree +
  configstore candidate mutation + tab completion.

It is NOT a single-PR feature primarily because of the CLI-verb surface and the
display fidelity questions (Q3/Q4); cramming the verbs into increment 1 risks
an unreviewable diff. It is NOT lab-bound (core is Go-test-validated;
`make test-failover` is a no-regression gate, not a discovery tool). PLAN-KILL
is on the table ONLY if Q5 reveals Path A cannot keep the compilers untouched
(then re-scope or reconsider value vs churn).

**recommendedPath:** Path A (node-flag + centralized strip), increment 1 first.
