# #2002 — decompose `pkg/config` parser/AST into `pkg/config/ast/`

**Status:** PLAN-KILLED (converged 2026-06-19 — AGY PLAN-KILL-CONFIRMED +
Claude SMR confirmed against reproduced build/grep evidence; Codex review
ran but its result infra-dropped). No code written, no production source
touched, no PR opened.

**Recommendation: PLAN-KILL** (close as won't-fix / tracked-decision),
with a clearly-scoped *increment-1 fallback* if the campaign owner wants a
partial win. Rationale in §1 and §10.

**Branch:** `research/2002-2004-import-cycles`. Supersedes/consolidates the
earlier `research/2002-config-ast-import-cycle` plan (same conclusion;
this revision adds reproduced build evidence).

---

## 1. TL;DR / verdict

- **Is the cycle real?** The codebase **compiles cleanly today** (`go build
  ./pkg/config/` → OK). There is **no cycle in the current flat layout.**
  The cycle is *created by* the move the issue asks for — it does not exist
  until you cross the package boundary.
- **Does the literal move create a cycle?** **Yes, guaranteed.** Reproduced
  on this branch (see §4): `ast_edit.go` (a file slated to move into
  `pkg/config/ast/`) reads `setSchema`/`schemaNode`, which are unexported
  and live in `schema.go` (stays in `pkg/config`). Meanwhile `schema_walk.go`
  + 15 other config files consume the AST `*Node`/`*ConfigTree` types (would
  move to `ast/`). To compile, `ast/` would `import config` (for `setSchema`)
  and `config` would `import config/ast` (for `Node`) → **`config → ast →
  config` import cycle, not allowed.**
- **Churn vs benefit.** Breaking the cycle requires non-mechanical surgery
  (interface injection or a duplicated grouping-schema projection) plus a
  `config.*` type-alias surface for **~97 external occurrences** (93 in
  `configstore` alone) and **16 in-package consumer files**. The benefit is
  **zero**: control-plane only, no perf/correctness/behavior gain, no single
  file over the 2000-LOC audit threshold today.
- **Why kill (not just defer).** The cycle is the codebase *signaling* that
  the AST and the config-mode schema are one cohesive module — exactly the
  conclusion #1891 already reached for the schema half when it
  **deliberately refused a sub-package** ("NOT a subpackage, because
  `setSchema` is unexported and consumed in-package"). #2002 asks to do for
  the AST half what #1891 rejected for the schema half, for no payoff. The
  issue's stated premise ("behavior-preserving code motion only … keep the
  move mechanical") is **false as written** — the move is not mechanical.

---

## 2. Issue framing

`#2002` (refactor-backlog, agy-review-013 Part II.1, peer to #1986–#1990)
asks to decompose the flat parser/AST family into `pkg/config/ast/`:

```
pkg/config/ast/
  ast.go      # core config-tree node structures
  lexer.go    # lexical analyzer
  parser.go   # recursive-descent parser
  format.go   # pretty printer / serialization
  edit.go     # AST mutable-transaction helpers (+ groups.go)
```

Target files + LOC (verified on this branch):
`ast.go` (365), `parser.go` (175), `lexer.go` (258), `ast_format.go` (527),
`ast_edit.go` (386), `ast_groups.go` (300) = **2011 LOC across 6 files**.
The issue says: *"Behavior-preserving code motion only … Keep the move
mechanical; no semantic changes."*

That premise is wrong. #2002 is **not** the same as the in-package #1699
split (which kept `package config` — zero import-graph change; see
`docs/pr/1699-config-ast-schema-split/plan.md`). #2002 crosses a **package
boundary**, and the boundary as drawn cannot compile.

## 3. Honest scope / value

Pure structural/modularity refactor of the control-plane config layer.
Touches `commit`-time and tab-completion-time code — **not** the packet hot
path, dataplane, allocation behavior, or HA/failover/boot decision logic.
**There is no runtime performance dimension at all.** Value is entirely
module-boundary hygiene + LOC-audit cosmetics. The audit pressure is weak:
2011 LOC *collectively*, but every one of the six files is individually well
under 2000.

Against that mild value: a real, permanent cost (cycle-break surgery +
alias surface + ~250-site/16-file blast radius, §4.5). **If reviewers
conclude the scope is too small to justify the churn, PLAN-KILL is the
intended outcome.** This refactor has zero perf gain, so the bar is purely
"does the boundary improvement justify the cost." It does not.

## 4. The cycle — verified with build evidence

### 4.1 Baseline (no cycle today)

```
$ go build ./pkg/config/      # on this branch, go1.24.9
CONFIG_BUILD_OK
```

The current flat `package config` compiles. **No cycle exists today.** The
issue describes a *would-be-introduced* cycle, not a present build failure.

### 4.2 The back-edge, located

`ast_edit.go` (slated to move) uses package-private schema symbols:

```
pkg/config/ast_edit.go:135:  schema := setSchema
pkg/config/ast_edit.go:142:  var childSchema *schemaNode
pkg/config/ast_edit.go:301:  return deletePath(&t.Children, path, setSchema, 0)
pkg/config/ast_edit.go:304:  func deletePath(... schema *schemaNode, i int) error
```

`setSchema`/`schemaNode` are defined in `schema.go` (`type schemaNode
struct` @ :34, `var setSchema = &schemaNode{...}` @ :104) — **unexported,
package-private**, consumed in-package by `schema_complete.go` /
`schema_walk.go`. #1891 deliberately kept them in `package config`.

### 4.3 The forward-edge, located

`schema_walk.go` (stays in `pkg/config`) consumes the AST types:

```
pkg/config/schema_walk.go:55:   func SchemaValidate(tree *ConfigTree, cfg *Config) error
pkg/config/schema_walk.go:152:  func collectSchemaRefs(tree *ConfigTree) *schemaRefs
pkg/config/schema_walk.go:157:  var collectCoS func(node *Node)
```

…plus 28 `Node`/`ConfigTree` references in that file and 16 other config
files (compiler aspects, freetext.go, tunnelid.go).

### 4.4 The cycle, reproduced

I performed a throwaway move (then fully `git restore`d) on this branch:
created `pkg/config/ast/`, moved `ast.go` + `ast_edit.go` into it with a
`package ast` clause, left the schema and the AST-consuming format file in
`config`. Build output:

```
# github.com/psaab/xpf/pkg/config/ast
pkg/config/ast/ast_edit.go:135:12: undefined: setSchema     ← ast needs config
pkg/config/ast/ast_edit.go:142:20: undefined: schemaNode
# github.com/psaab/xpf/pkg/config
pkg/config/ast_format.go:13:10: undefined: ConfigTree       ← config needs ast
pkg/config/ast_format.go:49:58: undefined: Node
```

`ast/` has unresolved references *into* `config` (`setSchema`,
`schemaNode`); `config/` has unresolved references *into* `ast` (`Node`,
`ConfigTree`). Resolving both requires mutual imports → **`import cycle not
allowed`**. The "undefined" errors are the cycle's fingerprint. Worktree
restored to clean (`go build ./pkg/config/` → RESTORED_OK).

### 4.5 Blast radius (measured)

- **External `config.*` references** that an alias surface must preserve:
  `pkg/configstore` **93**, `pkg/dataplane/userspace` 2, `pkg/daemon` 1,
  `pkg/eventengine` 1 (total **~97**, dominated by configstore).
- **In-package consumers** of `Node`/`ConfigTree` outside the 6 moved
  files: **16 non-test files** (every compiler aspect + freetext + tunnelid
  + schema_walk).
- **The single back-edge** is `ast_edit.go → setSchema/schemaNode`. The
  other **five files have no back-edge** (verified: zero
  `setSchema`/`schemaNode`/`compileX` references in lexer/parser/ast/
  ast_format/ast_groups; `isIdentChar`/`quoteKey` live in lexer.go and move
  with them). This is what makes a partial increment-1 possible (§10).

## 5. Design options (if pursued despite the kill recommendation)

Three cycle-free shapes exist; all preserve the public API via `config.*`
aliases. Recommended-if-pursued is **Option C**.

### Option A — leaf-primitives sub-package, schema-dependent edit stays

Move only the five back-edge-free files to `pkg/config/ast/`; leave
`ast_edit.go`'s `SetPath`/`DeletePath` in `pkg/config`.
**Pro:** smallest surgery; matches "mechanical motion" for 5/6 files.
**Con:** splits the edit family across two packages (worse cohesion than
today); forces exporting several previously-private nav helpers, permanently
enlarging the public AST API.

### Option B — schema interface injection (dependency inversion)

Keep all six files in `ast/`; break the back-edge by defining a
`SchemaLookup` interface in `ast/` that `SetPath`/`DeletePath` accept, with
`config` adapting `*schemaNode` to it.
**Pro:** cohesive; AST becomes genuinely schema-agnostic.
**Con:** changes the `SetPath`/`DeletePath` signature; interface-dispatch on
the grouping loop is a behavioral-parity risk (`childSchema == nil` /
`childSchema.children == nil` branches at ast_edit.go:151/:196/:244 are
load-bearing for the dual-AST contract).

### Option C — full sub-package + concrete `GroupSchema` projection (best-if-pursued)

Move all six files; have `SetPath`/`DeletePath` take a concrete
`ast.GroupSchema` (fields `Args`, `Children`, `Wildcard`, `Multi`,
`CompoundKey` — the only schema fields `SetPath` reads). `config` builds a
one-time pure projection of `setSchema` and passes it in.
**Pro:** cohesive; no interface-dispatch risk (plain field reads, same as
today); projection is property-testable to be field-identical.
**Con:** a *second* representation of the grouping schema that must stay in
sync (mechanical, test-guarded), plus an `init()`-ordering hazard (the
projection must be built *after* `schema.go`'s `init()` wires the `groups`
wildcard children).

### Option D — do nothing / PLAN-KILL (recommended)

Decline the move. See §10.

## 6. Public API preservation (all non-kill options)

- **Type aliases** in `pkg/config`: `ConfigTree`, `Node`, `ParseError`,
  `Token`, `TokenType`, `Lexer`, `Parser` (`type X = ast.X` — identical
  types; method sets + struct literals + `*config.Node`↔`*ast.Node`
  interoperate, so external callers don't change).
- **Function re-exports**: `var NewParser = ast.NewParser`,
  `ParseSetCommand`, `NewLexer`, `FormatCompare`, plus any `Token*`
  constants referenced externally.
- **Open verification item:** enumerate the exact exported AST symbols each
  of the 4 external packages references and confirm the alias set is
  complete (a missing alias is a compile break caught by `go build ./...`).

## 7. Hidden invariants that must survive

Control-plane code, so no hot-path/byte-order invariants — but:

- **Dual-AST contract (issue calls it out).** Flat `set … family inet dhcp`
  must produce the same tree shape as hierarchical `family inet { dhcp; }`.
  `SetPath`'s grouping (args/children/compoundKey/multi/wildcard) makes this
  work. Options B/C re-plumb how `SetPath` reads the schema → must preserve
  byte-identical tree shapes. `dual_ast_differential_test.go` guards this and
  must stay green. **Highest-risk invariant.**
- **`children == nil` replace-vs-container decision** (ast_edit.go:196): the
  projection (C) / adapter (B) must reproduce `children == nil` vs non-nil
  exactly (incl. explicit `children: nil` e.g. `apply-groups`).
- **Wildcard + compoundKey grouping** (ast_edit.go:186/:247): `family inet6`
  compound-key folding + wildcard-as-sibling must be bit-identical.
- **`init()` ordering** (Option C): the `groups` wildcard children are wired
  in `schema.go`'s `init()`; an eager projection must build after it.
- **Two-SSOT doctrine (#1319):** completion / validation / grouping must keep
  reading the *same* schema; Option C's projection must be proven
  non-divergent or the doctrine is violated.
- **NOT implicated:** HA/failover ordering, `computeBootClass`, hot-path
  allocation, byte-order, RETH/VRRP timing — none touch this package.

## 8. Risk table

| Class | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| Correctness | Dual-AST tree-shape regression from re-plumbing `SetPath`/`DeletePath` (Opt B/C) | Medium | High (silent config mis-grouping → wrong compiled policy) | Keep `dual_ast_differential_test.go` green; add property test `GroupSchema ≡ setSchema` grouping fields; byte-compare `Format`/`FormatSet` round-trips on full corpus |
| Correctness | Missing alias/re-export → external compile break | Low | Low (caught by `go build ./...`) | Enumerate external symbols first; CI build gate |
| Build/graph | A second hidden back-edge found mid-impl | Low | Medium | Pre-grep done (only `ast_edit.go`→`setSchema`); re-run `go list -deps` after motion |
| Maintainability | `GroupSchema` projection drifts from `setSchema` (Opt C) | Medium | Medium | Differential test fails build on drift; document the dual-write |
| Maintainability | Exporting private nav helpers (Opt A) enlarges public API permanently | Medium (A only) | Low | Prefer Opt C |
| Scope/process | Refactor balloons past "mechanical motion" | High | Low (process) | This plan flags it; reviewers decide go/kill |

**No Performance row** — there is no hot path.

## 9. Test plan & validation environment

- **Unit/package tests are the entire validation surface.** `go test
  ./pkg/config/...` green — especially `dual_ast_differential_test.go`,
  `parser_ast_test.go`, the `schema_validate_*` family, the round-trip
  `Format`/`FormatSet` tests.
- **Full-build gate:** `go build ./...` proves the alias surface is complete.
- **Differential equivalence (new, Opt B/C):** property test that the
  projection/adapter's grouping decisions are identical to `setSchema` over
  the whole schema tree, plus a corpus round-trip (parse → `FormatSet` →
  re-parse via `SetPath` → `Format`, byte-compare against today).
- **NO loss-cluster lab run.** This change is invisible to the
  dataplane/HA/VRRP/session-sync/boot path; `make test-failover` would only
  re-prove unrelated subsystems and must NOT gate this. (Cheapest optional
  sanity: one `cluster-deploy` + `commit`/`rollback`/`show | display set` —
  but unit tests cover it more precisely.)

## 10. Disposition: PLAN-KILL (with a tracked increment-1 fallback)

**Recommended: PLAN-KILL.** Close #2002 as won't-fix / tracked-decision.
Evidence:

1. **The issue's premise is false.** "Behavior-preserving mechanical code
   motion" is impossible — the literal layout is a guaranteed import cycle
   (§4, reproduced).
2. **Zero payoff.** No perf, no correctness, no behavior change; no single
   file over the 2000-LOC audit threshold; the only gain is LOC-audit
   cosmetics on a collective 2011 LOC already split by concern.
3. **The cycle is a correct signal.** It says the AST and the config-mode
   schema are one module. #1891 already reached this for the schema half and
   refused a sub-package. #2002 asks to invert that decision for no benefit.
4. **Permanent cost.** Every cycle-free option adds standing maintenance
   surface (alias layer + either a split edit family, a changed contract-
   critical signature, or a duplicated grouping projection) to break a cycle
   whose existence is evidence the boundary is wrong.

**Acceptable fallback IF the campaign owner still wants a partial win:**
increment-1 only — move the **five back-edge-free files** (`lexer.go`,
`parser.go`, `ast.go`, `ast_format.go`, `ast_groups.go`) to
`pkg/config/ast/` with full `config.*` type-alias preservation, leaving
`ast_edit.go` in `pkg/config` (permanently, or for a separately-approved
increment 2). This is cycle-free by construction (verified §4.5), needs no
`SetPath` signature change, and delivers most of the boundary value at
minimal risk. **Increment 2** (`ast_edit.go` via Option C) is the
contentious part and should be a separate go/no-go — and on the evidence
here, is itself a kill candidate.

**NOT defer-for-lab:** no dataplane/HA exposure; validation is unit tests +
`go build ./...` only.

## 11. Out of scope

- Any change to the schema grammar SSOT (`setSchema` contents, typed-leaf
  validation, completion). Motion only.
- `pkg/cmdtree` (the operational tree — separate SSOT).
- Splitting `compiler_*.go` or the schema aspect files (#1986–#1990 domain).
- Any dataplane/HA/FRR/networkd code.
- Performance work (there is none here).

## 12. Open questions for plan-review (≥5)

1. **Is the cohesion win real, or trading one boundary problem for another?**
   Option A splits the edit family; Option C duplicates the grouping schema.
   Does either improve the codebase, or does the cycle prove AST+schema are
   one module that should stay in `package config` (as #1891 concluded for
   the schema half)? Should the disposition be PLAN-KILL on those grounds?
2. **Is the external alias surface complete and stable?** Exact symbols
   referenced by configstore (93!) / daemon / dataplane-userspace /
   eventengine — any where an alias is insufficient (a const block, a method
   needing re-implementation)?
3. **Does any external caller invoke `tree.SetPath(...)` directly** (vs only
   through configstore)? If so, Options B/C's signature change leaks past the
   boundary and needs a compat wrapper.
4. **`init()` ordering for the projection (Opt C):** can it be built eagerly
   after `schema.go`'s `init()`, or must it be lazy (and if lazy, is there a
   concurrent-`commit` hazard)?
5. **Is the differential test strong enough** to catch a grouping drift that
   breaks the dual-AST contract (compoundKey folding, explicit `children:
   nil`, wildcard-as-sibling at ast_edit.go:247)?
6. **Increment boundary:** is the 5-file increment-1 worth shipping on its
   own, or is a half-extracted AST (edit family still in `config`) worse than
   the status quo?

---

## Claude self-SMR (hostile)

**Strongest objection to my own plan:** the import cycle is not an accident
of file layout — it is the codebase telling us the AST and the config-mode
schema are a single cohesive module. #1891 already reached this exact
conclusion for the schema half and deliberately refused a sub-package. #2002
asks to do for the AST half what #1891 rejected for the schema half, and the
only way to compile is to (A) split the edit family across two packages
(worse cohesion), (B) change the signature of the single most
contract-critical config function and add interface-dispatch parity risk, or
(C) introduce a duplicate grouping-schema representation that must be kept in
sync forever. All three add permanent maintenance surface to break a cycle
whose existence is itself evidence the boundary is wrong — for **zero**
payoff (no perf, no correctness, no behavior; no file over the LOC
threshold).

**Counter-argument (why not instantly kill):** a genuinely schema-agnostic
AST data model is a legitimately cleaner abstraction, and Option C's
projection is small, pure, and test-guarded; the 5-file increment-1 is
low-risk and a real (if small) legibility gain. That is real but weak
relative to the churn and the standing #1891 precedent.

**Disposition: PLAN-KILL**, with the 5-file increment-1 as the only
defensible partial if the owner wants motion. The issue should at minimum be
amended on GitHub to record that the literal layout is a guaranteed import
cycle and is not mechanical motion.
