# #1548 conntrack: harden legacy_dataplane_canary against alias / import-rename / dot-import bypasses

**Status:** DRAFT v1 — pending adversarial plan review

## Issue framing

PR #1532 shipped `pkg/conntrack/legacy_dataplane_canary_test.go` as the
#1451 retirement fence against re-introducing `dataplane.DataPlane`
into `pkg/conntrack/` production code. AGY's adversarial review of
#1532 (`adversarial-review-mpktubut-ogkp1e`) listed five categories of
bypass that the original implementation missed. Issue #1548 asks for
those to be closed.

**Important honest reading of the current state**: the canary in
master HEAD already contains a "Pass-2 catch-all selector sweep" that
walks every `*ast.SelectorExpr` in production files and flags any
literal `dataplane.DataPlane` selector regardless of compound /
generic shape. That pass landed as part of #1532 (round-N revisions
during the AGY iteration). What this means in practice:

| AGY-flagged category | Current state |
|----------------------|---------------|
| 1. Compound types `[]T`, `map[K]T`, `chan T`, `func(T)` | **CAUGHT** by pass-2 — the selector token is still in the AST |
| 2a. Generic type-param constraint `[T dataplane.DataPlane]` | **CAUGHT** by pass-2 |
| 2b. Generic instantiation `Generic[dataplane.DataPlane]` | **CAUGHT** by pass-2 |
| 3a. Type-alias DECLARATION `type DPAlias = dataplane.DataPlane` | **CAUGHT** by pass-2 (the RHS spells the selector) |
| 3b. Transitive use `var x DPAlias` after alias decl | **NOT CAUGHT** — bare `*ast.Ident` |
| 4. Import rename `import dp "...pkg/dataplane"; var x dp.DataPlane` | **NOT CAUGHT** — selector reads `dp.DataPlane` |
| 5a. Dot import `import . "...pkg/dataplane"; var x DataPlane` | **NOT CAUGHT** — bare `*ast.Ident` |
| 5b. Anonymous struct field | Already CAUGHT in #1532 (structural pass recurses into fields) |
| 5c. External package wrapping the type | **NOT CAUGHT** without cross-package go/types |

So #1548's actual scope is narrower than the issue body literally
reads: categories 1, 2, 3a, 5b are already closed. The remaining real
gaps are **transitive alias use, import rename, dot import** (and
external-package wrappers, which require true `go/types` import
resolution).

## Honest scope/value framing

**LOC**: ~80-130 net lines of test code (no production change).

**Value window**: The canary's value extends from now until the
eBPF retirement deletes `pkg/dataplane/`'s `DataPlane` interface
entirely. The retirement is gated by:

- **#1528** — DPDK source deletion (OPEN; DPDK manager is already
  gone but the package skeleton remains).
- **#1476** — eBPF retirement (OPEN; the umbrella ticket for
  deleting `pkg/dataplane/*.go` legacy types).

Neither has shipped. Per the project's #1451 decomposition,
`#1519/#1520/#1521` still need to finish before #1476 can land. The
canary is load-bearing until then — but if reviewers conclude the
remaining gaps (alias transitive use + import rename + dot import)
are too small a risk to justify churn while #1476 is "months away
anyway", **PLAN-KILL is an acceptable verdict.** The current
`#1532` canary already catches the most common reintroduction
mode; this PR only catches deliberate evasion.

**If reviewers conclude the perf gain is too small to justify the
churn, PLAN-KILL is an acceptable verdict.** Here "perf gain" reads
as "regression-fence completeness".

## What's already shipped

PR #1532 (merged as `d237ccebb`) introduced:

- `findLegacyDataPlaneOffenders` walker with two passes:
  - Pass 1: structural walker for func/struct/interface shapes
    with precise diagnostics.
  - Pass 2: catch-all `*ast.SelectorExpr` sweep flagging ANY
    literal `dataplane.DataPlane` selector in the file.
- `isLegacyDataPlaneType` for structural matcher: direct,
  `*T`, `...T`, `(T)`, `[N]T`. Slice/map/chan/func deliberately
  NOT matched here (caught by pass-2 instead).
- `TestLegacyDataPlaneTypeMatcher` (synthetic AST matcher unit test).
- `TestProductionWalkerCatchesCanaryShapes` (parser.ParseFile-driven
  end-to-end test for func/struct/interface shapes).
- `TestProductionWalkerIgnoresUnrelatedTypes` (negative control:
  `dataplane.SessionStore`, `dataplane.Telemetry` etc must not fire).
- `TestProductionWalkerCatchAllSweepClosesAGYBypasses` (catch-all
  sweep coverage for package-level var, local var, closure, composite
  literal, type definition, AND all four compound shapes).

## Concrete design

### Phase 1: import-rename support (real value)

Add a pre-pass that walks `file.Imports` and builds a per-file map
`packageAlias[string]bool` of identifiers that refer to the
`pkg/dataplane` package. The map is keyed by the local name actually
used in selectors:

```go
// dataplanePackageAliases returns the set of identifier names that,
// in this file, refer to github.com/psaab/xpf/pkg/dataplane. The
// default unaliased name "dataplane" is included when the import is
// present without rename. Dot imports map to the sentinel "" so the
// dot-import sweep below can recognise them.
func dataplanePackageAliases(file *ast.File) map[string]bool {
    const dpPath = `"github.com/psaab/xpf/pkg/dataplane"`
    aliases := map[string]bool{}
    for _, imp := range file.Imports {
        if imp.Path == nil || imp.Path.Value != dpPath {
            continue
        }
        switch {
        case imp.Name == nil:
            aliases["dataplane"] = true        // unaliased
        case imp.Name.Name == ".":
            aliases[""] = true                 // dot import sentinel
        case imp.Name.Name == "_":
            // blank import — no identifier ever produced
        default:
            aliases[imp.Name.Name] = true      // renamed
        }
    }
    return aliases
}
```

Both passes then consult that map instead of comparing to the
literal string `"dataplane"`:

- Pass 1: `isLegacyDataPlaneType` becomes
  `isLegacyDataPlaneType(expr, aliases)` and checks
  `aliases[pkg.Name]` for the `*ast.SelectorExpr` arm.
- Pass 2: catch-all sweep checks `aliases[pkg.Name]`.

This closes **category 4** cleanly and is the highest-value piece of
this PR. It does NOT require `go/types` — purely AST + file.Imports.

### Phase 2: dot-import support

When `aliases[""]` is true (dot import present), additionally walk
bare `*ast.Ident` references. Any `*ast.Ident` whose `.Name ==
"DataPlane"` and which is NOT the declared name of a local
type/var/func is an offender.

To minimize false positives we deliberately scope this narrowly:

- Skip identifiers that appear as a `name` in `*ast.AssignStmt.Lhs`,
  `*ast.ValueSpec.Names`, `*ast.TypeSpec.Name`, `*ast.FuncDecl.Name`,
  `*ast.FuncType.Params/Results.Field.Names` — these are declarations,
  not references.
- Only fire when a dot-import of `pkg/dataplane` is present in the
  same file (so the test file `type DataPlane = int` precedent in
  `TestProductionWalkerIgnoresUnrelatedTypes` continues to pass — no
  dot import there).

This is the trickiest piece. If the false-positive risk is too high,
a defensible Phase 2 fallback is: **detect the dot-import import-spec
itself and emit an offender immediately**, without trying to find
each use. That single-line "you dot-imported pkg/dataplane into
pkg/conntrack" diagnostic is enough to block reintroduction since
the user would have to delete the dot-import to silence the canary.

### Phase 3: transitive alias use

`type DPAlias = dataplane.DataPlane` is already caught — the RHS
selector fires pass-2. What's NOT caught is *downstream* `var x
DPAlias` after the alias declaration.

Two design options:

- **Option A (precise, heavy):** load the package with
  `golang.org/x/tools/go/packages` + `go/types` resolution, then
  walk type-checked expressions. Catches alias chains, external
  wrappers, and EVERY substitute name correctly.
- **Option B (simple, scoped):** while walking the file, collect
  the names of any type-spec whose RHS resolves (via the same
  matcher) to `dataplane.DataPlane`. Then a second `*ast.Ident`
  sweep flags any reference to one of those names.

Option B handles the common case (alias declared and used in the
same package) without adding a new dependency. Option A handles
cross-package aliases too, but adds `go/types` (already in stdlib;
no new dep) AND requires building a `*token.FileSet`/loader with
proper package path resolution which is heavy for a canary test.

**Plan: Option B as primary**, with explicit documentation that
cross-package aliases (alias declared in another package, then
imported into pkg/conntrack) are still deferred — they fall under
the "external-package wrapper" gap already listed in the canary
godoc. Promote to Option A only if Codex/Gemini flag the cross-file
gap as material.

### Test plan additions

Add to `TestProductionWalkerCatchAllSweepClosesAGYBypasses` (or a
sibling `TestProductionWalkerClosesAliasAndImportRenameBypasses`):

1. **Import rename catch**: `import dp "github.com/psaab/xpf/pkg/dataplane"; type S struct { F dp.DataPlane }` — must fire.
2. **Import rename + alias**: same with `var x dp.DataPlane` — must fire.
3. **Dot import direct decl**: `import . "github.com/psaab/xpf/pkg/dataplane"` alone — must fire (Phase 2 fallback diagnostic).
4. **Dot import use**: `import . "github.com/psaab/xpf/pkg/dataplane"; var x DataPlane` — must fire.
5. **Transitive alias use**: `type DPAlias = dataplane.DataPlane; var x DPAlias` — must fire (Phase 3 Option B).
6. **Transitive defined-type use**: `type DPDefined dataplane.DataPlane; var x DPDefined` — must fire.

And **negative-control extensions** to `TestProductionWalkerIgnoresUnrelatedTypes`:

- `import dp "github.com/psaab/xpf/pkg/dataplane"; type S struct { F dp.SessionStore }` must NOT fire.
- `type DataPlane = int; var d DataPlane` (already present) must NOT fire (no dot-import sentinel).
- `import context "context"; func F(ctx context.Context)` must NOT fire (irrelevant rename).

## Public API preservation

There is no public API. Both `findLegacyDataPlaneOffenders` and
`isLegacyDataPlaneType` are unexported, defined in a `_test.go` file,
and tested only from sibling `_test.go` files in the same package.
The matcher signature change (add `aliases map[string]bool` arg) is
internal.

## Hidden invariants the change must preserve

1. **No false positives on master**: the canary must continue to
   pass on the current `pkg/conntrack/` production tree. The
   negative-control test must continue to pass.
2. **Diagnostics still attributable**: pass-1 structural messages
   still name the function / field / method holding the offending
   type. Adding aliases doesn't change that — only widens the set
   of selectors that count.
3. **Test-file exclusion preserved**: `_test.go` files still skipped.
4. **No new dependencies**: stay within `go/ast`, `go/parser`,
   `go/token`, `os`, `path/filepath`, `strings`, `testing`. No
   `go/types` and no `x/tools/go/packages`.
5. **No production code touched**: this is a pure test file edit.

## Risk assessment

| Class | Risk | Notes |
|-------|------|-------|
| Behavioral regression | **LOW** | Test-only edits; no runtime path touched. |
| False positives | **MEDIUM** | Dot-import scan + Option-B alias scan could flag legitimate `DataPlane`/`DPAlias`-named locals if the heuristic is wrong. Mitigated by narrow scope (only fire when relevant import present) + explicit negative tests. |
| Maintenance / churn cost | **MEDIUM** | More walker logic to maintain just before #1476 deletes the whole type. PLAN-KILL candidate. |
| Architectural mismatch (#961 / #946 Phase 2 dead-end) | **LOW** | The design is purely additive to the existing canary; no new abstraction. |

## Test plan

- [ ] `go test ./pkg/conntrack/ -count=1 -race` — green
- [ ] `go test ./pkg/conntrack/ -count=1 -run TestProductionWalker -v` — all subtests green
- [ ] 5x flake check on `TestConntrackHasNoLegacyDataPlaneDependency`
- [ ] `go vet ./pkg/conntrack/...` — clean
- [ ] Full Go suite: `go test ./...` — 30 packages pass
- [ ] **Negative case verified**: hand-flip an `import dp "...pkg/dataplane"; var _ dp.DataPlane` into a production file; canary must fire. Revert.
- [ ] **Negative case verified**: hand-flip a `type DPAlias = dataplane.DataPlane; var _ DPAlias` into a production file; canary must fire. Revert.

**Smoke**: this is a pure test-file PR. Per the
`docs-only-skip-smoke` scope tag (and per `docs/engineering-style.md`
§8), no dataplane bring-up or per-class CoS smoke is required. The
AWAITING-SMOKE marker will declare scope `docs-only-skip-smoke` so
the smoke runner skips it.

## Out of scope (explicitly)

- **Cross-package alias resolution**: e.g. another package
  declares `type Foo = dataplane.DataPlane` and pkg/conntrack
  imports `Foo`. Catching this would require `go/types` or
  `x/tools/go/packages` loaders. Documented as a deferred bypass
  in the canary godoc.
- **External wrapper types**: same as above — a foreign package
  defines `type Wrapper struct { _ dataplane.DataPlane }` and
  pkg/conntrack imports `Wrapper`. Still deferred.
- **Replicating the hardening across sibling canaries**
  (#1516 grpcapi, #1517 cli, #1518 cluster). Those have their
  own canary files (or will when #1516-#1518 land); they replicate
  whatever pattern this PR establishes via separate PRs.

## Open questions for adversarial review

1. **Is the value > churn given #1528/#1476 will eliminate the
   entire `pkg/dataplane.DataPlane` interface anyway?**
   PLAN-KILL candidate. Estimate of timeline: #1476 is gated by
   #1519/#1520/#1521 (per #1451 decomposition); #1520 was
   in-flight as of master HEAD. If #1476 lands in the next
   2-3 weeks, hardening a regression fence against deliberate
   evasion is busywork. If it slips to months, the fence is
   load-bearing.

2. **Should this use `go/types` instead of `go/ast`?** More correct
   (catches cross-package wrappers + transitive alias chains
   correctly) but adds loader complexity, requires building a
   proper `go/packages` config, and runs slower as a unit test.
   The plan picks pure-AST as the right trade — quote a counter-
   example if `go/types` is the right call.

3. **How should dot imports be handled — declaration-level fire
   (Phase 2 fallback) or full identifier sweep?**
   Declaration-level fire is robust (zero false positives, single
   diagnostic). Full identifier sweep catches more but risks
   false positives on identifiers named `DataPlane` that aren't
   in fact references to the imported one. Plan picks the safer
   fallback — argue for the alternative if the fallback is too
   weak.

4. **Option-B alias scan vs Option-A go/types resolution.** Is
   the same-file-only alias detection a load-bearing distinction,
   or do we need cross-file? `pkg/conntrack` is a small package;
   the same-file scope is probably enough. Counter-argument
   welcome.

5. **Should this PR also replicate the hardening across the
   sibling #1451 canaries (#1516 grpcapi, #1517 cli, #1518
   cluster)?** Plan says no — those have / will have their own
   canary files and can copy this pattern. Coupling them risks
   a multi-package PR that's harder to review. If reviewers think
   the duplication risk (developer adds bypass to grpcapi while
   we're hardening conntrack) outweighs the coupling cost, we
   could fold them.

6. **Cross-file declarations**: `pkg/conntrack` has multiple
   production files. If file A declares `type DPAlias =
   dataplane.DataPlane` and file B uses `var x DPAlias`, the
   per-file Option-B scan misses file B. Should the alias scan
   span all files in the package, or is per-file enough since
   file A still fires?

7. **Hostile-developer model**: who is the threat? An honest
   refactor that re-introduces `dataplane.DataPlane` will spell
   the literal `dataplane.DataPlane` and trip the existing pass-2.
   The deferred bypasses only matter against a developer who is
   *deliberately* evading the canary. Is that a realistic threat
   in this codebase? If not, **PLAN-KILL** is the right call.

## Verdict expectations

PLAN-READY / PLAN-NEEDS-MINOR / PLAN-NEEDS-MAJOR / PLAN-KILL all
acceptable. **PLAN-KILL on "value < churn given #1476 imminent"
is explicitly acceptable.** The skill instruction set this PR is
running under permits AGY to PLAN-KILL on that rationale.
