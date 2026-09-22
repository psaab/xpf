# Serial gate + floor gate — two-phase plan (#10496 + #10497)

Lane: `fix/10496-serial-gate-floor` in worktree `10496-serial-gate`.
Base: `21df4afd8` (rebased onto `origin/master`; pre-rebase `b71c52d60` was 11 behind,
including the #10487 merge — this base was verified at 0/0 against `origin/master`
before this plan commit).
Round: plan only. No production code in this round.

## STEP-0 dispositions (both live, neither fixed)

| Issue | State | Live on rebased HEAD? | Prior fix? |
|---|---|---|---|
| #10496 serial aggregate aborts before Rust | OPEN | YES — `Makefile:99` still `test: test-go test-rust` with first-failure semantics (`:96-98`); `test-go` still red via the uncached leg (`:271`) | None — merged-PR search for 10496/10497 empty; `git log` on `Makefile`/`structs.go`/`structs_6937_test.go` shows no fix |
| #10497 live calibration reddens Go gate, floor unenforced | OPEN | YES — `TestStructMetricIsTypesNotFields6937` FAILS: `CompileResult (32 fields, 21 types) flags` vs floor 20; `Tag()` consumers still exactly 2 (calibration test + `structaudit/main.go:63`); `StructWatchFloor` enforced nowhere | None — #10487 touched `pkg/refactoraudit/` but only the accepted-entry lifecycle (`accepted_live_test.go`); it does not reference `StructWatchFloor` (verified by tree-wide grep) |

RED baseline (scoped proof, rebased HEAD, isolated caches):

    GOCACHE=/dev/shm/gocache-10496 GOTMPDIR=/dev/shm \
      go test ./pkg/refactoraudit/ -run TestStructMetricIsTypesNotFields6937 -count=1 -v
    structs_6937_test.go:95: CompileResult (32 fields, 21 types) flags; it is the
      just-UNDER calibration point for a floor of 20
    --- FAIL: TestStructMetricIsTypesNotFields6937 (3.40s)

Only the CompileResult assertion fails; Engine (just-over) and xpfCollector
(false-positive guard) assertions pass. Numbers match the assignment's 32f/21t vs 20.

## Shared mechanism (both phases read this once)

Default `make test` walks a three-deep chain: the serial aggregate (`test: test-go
test-rust`, `Makefile:99`) → `test-go`'s uncached `pkg/refactoraudit` leg
(`Makefile:271`, rationale `:249-270`, #6626: the touched-file gate shells out to a
script outside the `go test` cache inputs, so the package MUST run `-count=1`) →
the #6937 calibration, which scans the LIVE `pkg/` tree (`structs_6937_test.go:65`)
and asserts CompileResult sits just under `StructWatchFloor = 20`. CompileResult
drifted to 21 distinct types, so the Go leg is red, so serial Make aborts, so
`test-rust` (`:362-367`, the only runtime forwarding-path coverage after the
#1373/#1476 eBPF retirement) never runs. Phase 1 breaks the middle arrow (reach
Rust despite red Go); Phase 2 removes the redness's live-drift cause.

Floor/mirror map (blast-radius reference):

- `StructWatchFloor = 20` / `StructRefactorFloor = 40` (`structs.go:76-79`).
- Mirrored by `AUDIT_STRUCT_FLOOR=20` (`scripts/refactoring-audit-lib.sh:106`);
  constant VALUES pinned by `TestStructFloorsMatchShellConstants6937`. The
  `>=` comparison OPERATOR is pinned by nothing — see Phase 2 hidden invariants.
- `Tag()` (`structs.go:91-99`, `>=`): its two actual Go consumers are the
  calibration test (`structs_6937_test.go:90,94,109`) and
  `structaudit/main.go:63`. The shell generator
  (`scripts/refactoring-audit-structs.sh`, via the `audit-structs` target)
  invokes the scanner; the shell library's `AUDIT_STRUCT_*` assignments are
  the separate threshold-value mirror.
- `pkg/refactoraudit`: 14 test files, 47 `Test` funcs. File sizes: `Makefile`
  1481 lines, `structs.go` 200, `structs_6937_test.go` 210, `lib.sh` 149.

## #10504 overlap + merge-sequencing note (scope guard, not scope)

#10504 (RED-SUITE, OPEN) covers the same symptom area from the Rust side: 183
release-suite failures on a fixture-MAC precondition, vacuous survivors, AND —
in its Acceptance — "refactoraudit calibration fixed so the Make gate reaches
Rust". That last clause overlaps this lane's outcomes exactly. Distinct scopes:
#10504 owns descriptor/fixture/MAC + Rust cells; this lane owns the Makefile
aggregate + the Go calibration/floor. Sequencing: **this lane lands first**;
#10504 rebases and treats gate-reach as downstream verification, and MUST NOT
implement its own calibration or Makefile-aggregate fix (that would collide).
Collision check is DM-to-parent only. No #10504 work in this lane.

## Risk-class definitions (shared by both phases)

- **R1 gate-signal correctness** — the gate still fails when it must, passes when
  it must; no silent all-clear, no false red.
- **R2 compatibility** — existing target names, docs, shell/Go mirrors, hooks,
  and contributor workflows keep working.
- **R3 operational cost** — suite time, caching, contributor friction.
- **R4 scope & schedule** — creep into adjacent issues (#10504, #10487, #4006),
  review load, rebase risk.

---

## Phase 1 — #10496: default `make test` reaches `test-rust`

Status: **DRAFT v1** (plan round; no code).

### Issue framing

`test: test-go test-rust` with default serial Make stops at the first failing
prerequisite. `test-go` is red (Phase 2's subject), so `test-rust` never runs —
exactly when the aggregate signal matters most. #4006 is the adjacent
non-owner: it ADDED Rust to the aggregate (omission fix); this issue is the
serial BLOCKAGE fix.

### Honest scope / value

Value if shipped: the default gate covers the only runtime forwarding path even
while the Go leg is red, and still fails overall. Tempered by a verified
finding: **no in-repo CI invokes bare `make test`** — `.github/` contains only
`instructions/` (no `workflows/`; the close-keyword lint runs via the Makefile
`selftest`/`install-git-hooks` path, not Actions). So Phase 1's value is
contributor-local ergonomics plus whatever external CI calls bare `make test`
(unverified — see OQ-1). If the answer to OQ-1 is "nothing", Phase 1 shrinks to
a contributor-convenience change and the parent may PLAN-KILL it.

### Shipped context

#4006 (Rust joined the aggregate; comment `:90-98`), #1373/#1476 (eBPF
retirement — Rust is the only runtime path, raising the stakes), #9052 (the
NOT-EXAMINED announcement + `test-root` split: `test` must stay unprivileged),
#9590 (tree-wide `go vet` inside `test-go`), #2114 (race gate), #6626
(uncached leg — owned by Phase 2's half, untouched here).

### Concrete design (recommended: failure-capturing serial recipe)

Convert the `test:` prerequisites into a recipe that runs BOTH legs
unconditionally and exits nonzero if either failed:

```make
test:
	@status=0; \
	$(MAKE) test-go || status=$$?; \
	$(MAKE) test-rust || status=$$?; \
	echo ""; \
	echo "make test: NOT EXAMINED by this run — the XDP shim's behavioural"; \
	echo "  coverage (pkg/dataplane/userspace/fragment_disposition_7494_test.go)"; \
	echo "  SKIPS unprivileged. It is the ONLY behavioural coverage of the shim's"; \
	echo "  control flow, and the #1864 verifier gate does not substitute: two"; \
	echo "  distinct WRONG fixes both pass it. Run 'sudo make test-root' (#9052)."; \
	exit $$status
```

plus a comment update at the `test:` target documenting the continue-on-failure
aggregate semantics (the issue's acceptance explicitly requires documenting
them). The announcement block moves INSIDE the recipe before `exit` so it still
prints when a leg fails (today it prints only when both pass — a behavior
change to call out in review, but it matches the announcement's intent: the
shim is never examined by this target either way).

Alternatives considered and rejected: (a) "just run `make -k test`" — changes
no default, so it is documentation, not a fix; (b) parallel legs (`-j`) — new
failure modes (interleaved output, load) for no asked benefit; the aggregate
stays serial; (c) splitting CI jobs — there is no in-repo CI to split (see
OQ-1); out of scope.

### API preservation

Target names `test`, `test-go`, `test-rust` unchanged; both legs still directly
runnable; `test-root` untouched. Exit contract: 0 iff both legs green (identical
to today when green; differs ONLY in the red-Go case, where Rust now also runs
and the exit stays nonzero).

### Hidden invariants (do not break)

1. The announcement must print on ALL paths (it is the #9052 remedy for the
   #7766 shape — a gate that implies coverage it lacks).
2. Do not touch the `test-race-dp` `-run '...'` single-quoted spellings:
   `pkg/daemon`'s and `pkg/cluster`'s canary tests PARSE those recipe lines.
3. Do not touch the uncached leg (`:271`) or narrow it with `-run` (#6626 +
   #6743 r2-N3); Go-leg redness belongs to Phase 2.
4. `test` must stay unprivileged — no `test-root` merge (#9052).
5. The recipe must be robust under Make's per-line shell semantics: single
   logical line, explicit `|| status=$$?` capture, no bare failing command.

### Risk table

| Class | Risk | Mitigation |
|---|---|---|
| R1 | Buggy status capture yields a false all-clear (the #4006 nightmare inverted) | Keep the capture trivial (`status` + trailing `exit`); recipe-canary test (below) asserts both legs + nonzero exit |
| R2 | Contributors/scripts parsing `make test` output see Rust output after Go failure | Intended and documented at the target; no promised output contract exists |
| R3 | Red-Go runs now ALSO pay the full Rust suite (~minutes) instead of aborting early | Intended (signal over speed); contributors iterating on Go can still call `make test-go` directly |
| R4 | Design review re-litigates `-k` vs recipe vs CI split | OQ-1/OQ-2 answered in plan review BEFORE implementation |

### Test plan (against the red baseline)

Baseline today: `make test` aborts after red `test-go`; no cargo invocation.

1. `make -n test` shows both `$(MAKE) test-go` and `$(MAKE) test-rust` legs.
2. Red-path (live, post-implementation): with the calibration still red,
   `make test` runs the `test-rust` leg (cargo invocation visible in output),
   prints the announcement, and exits nonzero. Full run costs minutes; that is
   the point of the change and is accepted once.
3. Green-path E2E (`make test` fully green) is BLOCKED until Phase 2 un-reds
   the Go leg — recorded as a sequencing note, not attempted here. No test or
   fixture is modified to simulate green.
4. (Design choice for review:) a Makefile-recipe canary test in the
   `TestRaceGateCoversTheConcurrencyBinders` style — a Go test parsing the
   `test:` recipe asserting both legs run with failure capture. Cheap,
   convention-matching; adds one more parser-canary to maintain.

### Out of scope

Fixing the Go-leg redness (Phase 2); CI workflow changes (none exist in-repo);
`test-root` merge; parallel legs; touching any `pkg/` code.

### Open questions (Phase 1)

- **OQ-1 (PLAN-KILL candidate): what invokes bare `make test`?** Verified: no
  in-repo workflow. If parent confirms no external CI either and rare
  contributor use, Phase 1's value may not carry its review/maintenance cost —
  kill it or shrink to a comment-only change.
- **OQ-2: recipe-capture vs document-only?** If OQ-1's answer is "contributors
  only", is documenting "`make test-go; make test-rust`" enough? The issue's
  acceptance demands reaching Rust; document-only would need an acceptance
  rewrite, not a quiet downgrade.
- **OQ-3: should the recipe-canary test (item 4) ship?** It matches repo
  convention but adds parser-canary load. Alternatively verify by the one
  expensive live run only.

---

## Phase 2 — #10497: decouple the calibration from live drift (floor stays advisory)

Status: **DRAFT v1** (plan round; no code).

### Issue framing

Two confirmed halves: (1) `StructWatchFloor` is advisory — `Tag()` has exactly
two consumers (calibration test + heatmap generator) and nothing fails when an
arbitrary struct crosses 20 types; (2) the calibration scans the LIVE tree, so
any unrelated field addition to CompileResult/Engine/xpfCollector can tip it —
and the implied remediation (drop to 20) still tags under `>=`.

### Honest scope / value

Value if shipped: the Go leg stops reddening from unrelated struct drift, and
contributors are decoupled from CompileResult's field count. Tempered by the
verified census: **27 structs currently sit at/above the floors** (10
[REFACTOR], 17 [WATCH]). That kills "just enforce the floor" as a small change:
a hard gate on all structs is a 27-row red on day one and needs grandfathering
to be shippable (see option A below and OQ-4). The recommended design therefore
keeps the floor advisory and fixes the LIVE-COUPLING half — the half that reds
unrelated contributors' runs.

### Shipped context

#6937 (the types-not-fields metric choice + the nested-struct counting trap in
`normalizeFieldType`), #6232/#7253 (the shell lib as single source of truth for
audit scope), #6626 (why the package runs `-count=1` — the touched-file gate,
INDEPENDENT of this phase, so the uncached leg stays), #6743 r2-N3 (no `-run`
narrowing of that leg), #10487 (accepted-entry lifecycle for FILE-modularity
entries — verified distinct: no `StructWatchFloor` reference; reuse of its
grandfathering pattern is possible but not assumed), #10495 (adjacent docs
correction on the same base).

### Concrete design (recommended: B1 — TempDir fixture canaries)

`GoStructs(root, audited)` takes a root path, so the calibration can scan
fixtures instead of the live tree. Ship the fixtures as **Go source string
literals written to `t.TempDir()`** (precedent: `TestRustScannerSeesPubInPathStructs6937`
in the SAME file writes `x.rs` to a TempDir):

- `over.go`: a struct with exactly 21 distinct field types (just over the
  floor, mirroring Engine's role) and fewer fields than `under.go` — asserts
  `Tag() != ""`.
- `under.go`: a struct with exactly 19 distinct field types and more fields
  than `over.go` (just under the floor, mirroring CompileResult's role) —
  asserts `Tag() == ""`, plus the inversion property so the test still
  demonstrates WHY types are measured.
- `aggregate.go`: a struct with more fields than `over.go` (the largest
  aggregate / false-positive role) but fewer than 20 distinct types — asserts
  `Tag() == ""`.

Why TempDir literals and NOT `testdata/*.go` files: `AUDIT_SKIP_RE` excludes
only `target/`/`vendor/` — committed fixture files under `pkg/` WOULD be
scanned by the live generator, and the just-over fixture would pollute
`audit-structs` output with a permanent [WATCH] row. TempDir fixtures leave
zero tree residue and touch neither the generator nor the skip RE.

Options considered:

- **A (enforce the floor as a real gate):** new test failing on any
  non-grandfathered struct ≥ 20 types. Honest cost: 27 grandfather rows on day
  one + an accepted-struct mechanism (new file or #10487-pattern reuse) + the
  `>=` semantics decision (OQ-5). Recommend: NOT in this phase; possible
  Phase 2b / separate issue if the team wants a real gate.
- **C (re-baseline CompileResult as OVER):** rejected — destroys the just-under
  calibration point, likely collapses the inversion story, and stays
  live-coupled (the next drift re-reds).
- **D (the `>=` → `>` question):** NOT decided here — see OQ-5. Any operator
  change must update Go `Tag()` and add explicit boundary coverage; the shell
  generator delegates classification to that Go method, while the shell library
  mirrors threshold VALUES only.

### API preservation

Under B1: `StructRow`, `GoStructs`, `Tag()`, both floor constants, and the
shell mirror are UNCHANGED — only the calibration test's data source changes
(live `pkg/` scan → TempDir fixtures). No generator, artifact, or docs change.
Under option A or D (not recommended here), the changed surface would be
explicitly listed in a follow-up plan.

### Hidden invariants (do not break)

1. The shell/Go floor VALUE mirror + `TestStructFloorsMatchShellConstants6937`
   stays green (B1 does not touch values — trivially preserved).
2. The `>=` OPERATOR is pinned by NOTHING (the pin test covers constants
   only). B1 does not touch it; any future operator change must update
   `Tag()` and add boundary coverage for the exact-floor case. The shell
   generator delegates classification to `Tag()`; its shell library only
   mirrors the floor values.
3. The uncached leg (`Makefile:271`, full-package `-count=1`, no `-run`) stays
   as-is: it exists for the touched-file gate, not for this test (#6626).
4. `normalizeFieldType`'s nested-struct collapse (the #6937 trap) must keep
   classifying fixture sources identically — fixtures exercise it, not bypass
   it (include one nested anonymous struct in a fixture).
5. `AUDIT_SKIP_RE` stays the single source of truth for exclusions
   (#6232/#7253); B1 adds no exclusion and no committed fixture file.
6. The inversion property (`under.Fields > over.Fields && over.Types >
   under.Types`) is what makes the test a metric justification rather than a
   threshold assertion — the fixtures MUST preserve it.

### Risk table

| Class | Risk | Mitigation |
|---|---|---|
| R1 | Fixtures drift from reality: the metric rots while the test stays green (calibration becomes vacuous) | Fixtures pin counts EXACTLY (not just inequalities) so metric-code changes still bite; negative controls (below) prove the test can fail |
| R2 | Reviewers expect the live CompileResult/Engine story; fixture names must carry the mapping | Name fixtures + comments after their live counterparts; keep a comment citing the live structs' current counts as of this plan |
| R3 | None material — TempDir fixtures are milliseconds; the package's ~10.7s uncached cost is unchanged | No mitigation needed |
| R4 | OQ-4/OQ-5 answers could redirect to enforcement (A) or operator fix (D), invalidating B1 | Plan review settles OQ-4/OQ-5 BEFORE implementation; B1 is small enough to abandon cheaply |

### Test plan (against the red baseline)

Baseline today: `TestStructMetricIsTypesNotFields6937` FAILS on live
CompileResult (32f/21t).

1. Post-B1: `go test -count=1 ./pkg/refactoraudit/` is GREEN (with isolated
   caches per lane convention) — the live CompileResult drift no longer
   reaches the test. The other 46 tests in the package are unaffected
   (asserted by the full-package run, not by assumption).
2. Negative controls (prove the test still bites — run, then revert): (a) add
   one distinct-typed field to the `under` fixture → it reaches the floor and
   MUST fail; (b) remove distinct types from the `over` fixture until it is
   below the floor (21 → 19 if the just-over fixture is 21) → it MUST fail.
   Neither control touches production code or committed fixtures permanently.
3. `TestStructFloorsMatchShellConstants6937` still passes (untouched, but in
   the same file — the full-package run covers it).
4. `audit-structs` output byte-identical before/after (B1 adds no committed
   file under an audited root) — verified by diffing generator output.
5. Full `make test-go` green is the downstream expectation but is NOT run in
   this lane's implementation round (project-wide validation is the parent's;
   siblings edit concurrently).

### Out of scope

Enforcing the floor on all structs (option A — needs grandfathering; candidate
Phase 2b); changing floor VALUES; changing the `>=` operator (OQ-5 —
separate Go/operator-boundary decision); #10504's Rust/fixture work; generator
or artifact changes; touching the Makefile.

### Open questions (Phase 2)

- **OQ-4 (PLAN-KILL/redirect candidate): fixture-canaries (B1) vs real
  enforcement (A)?** If the team wants the floor to actually gate, B1 is the
  wrong fix — it makes the advisory floor quieter without enforcing anything.
  Kill B1 and plan A with 27 grandfather rows instead. If the floor is meant
  to stay advisory, B1 is right-sized.
- **OQ-5: is `>=` at 20 intended, or an off-by-one for `>`?** The issue notes
  the implied fix (drop to exactly 20) still tags. If `>` was intended, the
  minimal fix is the Go operator plus explicit boundary coverage; the shell
  library only mirrors floor values and changes only if a value changes. This
  may PLAN-KILL B1 (or combine: D first, B1 after). Needs an owner who knows
  the #6937 intent, not a guess.
- **OQ-6: should the xpfCollector false-positive guard stay live?** It guards
  the GENERATOR's top row ("if the tree's largest aggregate flags, the gate
  will be ignored") — fixture-izing it loses the live early warning. Options:
  keep one live assertion (xpfCollector unflagged) alongside fixtures, or go
  fully hermetic. Keeping one live leg reintroduces a (narrow, named) drift
  coupling — say so explicitly if chosen.

---

## Inter-phase dependency ruling (explicit)

**Phase 2 does NOT need Phase 1 merged first.** The mechanisms are independent
(Makefile aggregate vs Go calibration), the files are disjoint (`Makefile` vs
`pkg/refactoraudit/*_test.go`), and neither design assumes the other's
presence. Recommended sequence is Phase 1 → Phase 2 ONLY because Phase 1
restores the Rust signal fastest while the Go leg is still red; Phase 1's
full-green E2E verification additionally needs Phase 2's un-red to exist.
Either order merges cleanly. Per lane instructions both phases ride this ONE
branch serially (plan round now; implementation in a later round after
parent-run plan review).

## Verification appendix (plan-round evidence)
- `git rev-list --left-right --count 21df4afd8...origin/master` → `0 0`
  (rebased base before this plan commit).
- `gh pr list --state merged --search 10496/10497` → empty; `git log` on the
  three evidence paths → no fix commit.
- `make` aggregate: `Makefile:99`; uncached leg: `:271` (drifted from the
  issue's `:248-252` — re-grounded post-rebase); `test-rust`: `:362-367`.
- Floor: `structs.go:77`; `Tag()`: `:91-99`; calibration: `structs_6937_test.go:63-120`.
- Tree-wide `.Tag()` consumers: calibration test + `structaudit/main.go:63` only.
- Tree-wide `StructWatchFloor` consumers: `structs.go`, `structs_6937_test.go`,
  shell mirror in `scripts/refactoring-audit-lib.sh:106` — #10487's
  `accepted_live_test.go` absent (distinct scope).
- `.github/` contains only `instructions/` — no `workflows/` (OQ-1's premise).
- Live census: 10 [REFACTOR] + 17 [WATCH] = 27 structs ≥ floors (OQ-4's premise).
