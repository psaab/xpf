# Serial gate + floor gate — two-phase plan (#10496 + #10497)

Lane: `fix/10496-serial-gate-floor` in worktree `10496-serial-gate`.
Base: `21df4afd8` (rebased onto `origin/master`; v1 plan commit
`7212dc9f2`; this base was verified 0/0 against `origin/master` before the v1
commit; `origin/master` re-fetched for v2 with no new commits behind).
Round: DRAFT v2 — parent-adjudicated fold of round-1 reviews (A: Phase1-MINOR /
Phase2-MAJOR; B: Phase1-MAJOR / Phase2-MAJOR; no kills). Plan only; no
production code in this round.

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
(false-positive guard) assertions pass. Live re-ground for v2: Engine is now
27 fields / 22 types (doc `structs.go:43` says 25f/20t — drifted, still flags),
CompileResult 32f/21t, xpfCollector 443f/11t (types stable at the documented 11).

## Shared mechanism (both phases read this once)

Default `make test` walks a three-deep chain: the serial aggregate
(`test: test-go test-rust`, `Makefile:99`) → `test-go`'s uncached `pkg/refactoraudit` leg
(`Makefile:271`, rationale `:249-270`, #6626: the touched-file gate shells out to a
script outside the `go test` cache inputs, so the package MUST run `-count=1`) →
the #6937 calibration, which scans the LIVE `pkg/` tree
(`structs_6937_test.go:65`) and expects CompileResult to sit just under
`StructWatchFloor = 20`. CompileResult drifted to 21 distinct types, so the Go
leg is red, so serial Make aborts, so
`test-rust` (`:362-367`, the only runtime forwarding-path coverage after the
#1373/#1476 eBPF retirement) never runs. Phase 1 breaks the middle arrow (reach
Rust despite red Go); Phase 2 removes the redness's live-drift cause.

Floor/mirror map (blast-radius reference):

- `StructWatchFloor = 20` / `StructRefactorFloor = 40` (`structs.go:76-79`).
- Mirrored by `AUDIT_STRUCT_FLOOR=20` (`scripts/refactoring-audit-lib.sh:106`);
  constant VALUES pinned by `TestStructFloorsMatchShellConstants6937`. The `>=`
  OPERATOR is intended (v2 OQ-5: calibrated from the measured distribution,
  `structs.go:37-44`) and is pinned by the new exact-20 fixture (Phase 2),
  not by the pin test (values only).
- `Tag()` (`structs.go:91-100`, `>=`): its two actual Go consumers are the
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
Review finding (v2, recorded not implemented): prose scheduling is
enforcement-weak — the parent should add an explicit blocked-by/dependency note
on #10504 itself. Collision check is DM-to-parent only; no #10504 work is in
this lane.

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

Status: **DRAFT v2** (adjudicated fold; round-1 A: Phase1-MINOR /
Phase2-MAJOR; B: Phase1-MAJOR / Phase2-MAJOR; no kill).

### Issue framing

`test: test-go test-rust` with default serial Make stops at the first failing
prerequisite. `test-go` is red (Phase 2's subject), so `test-rust` never runs —
exactly when the aggregate signal matters most. #4006 is the adjacent
non-owner: it ADDED Rust to the aggregate (omission fix); this issue is the
serial BLOCKAGE fix.

### Honest scope / value

Value if shipped: the default gate covers the only runtime forwarding path even
while the Go leg is red, and still fails overall. **OQ-1 CLOSED (v2, no kill):**
no in-repo automation invokes bare `make test` (verified: no in-repo workflows;
the mutation driver calls legs directly, `scripts/mutate.sh:100,102`), but
humans DO — `make test` is the documented always-gate
(`docs/engineering-style.md:481`: "always — Go and Rust"; plus `CLAUDE.md:95`,
`README.md:241`) with observed lane-log hits of the exact breakage
(`docs/log/9814.md:270`, `docs/log/9522.md:56-58`). So
v1 UNDER-SOLD this as "contributor-local ergonomics": it is always-gate
restoration of a documented merge criterion. Kill bar raised accordingly.

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
The target comment should use wording such as:

```make
# Run both serial legs even when the first fails; fail if either leg fails.
```

It MUST NOT contain the literal `test-go:` (with colon); the hidden invariant
below explains the parser-canary anchor.

Documented behavior deltas (v2 review notes, all negligible-or-intended): (i)
`-j` serialization — prereqs parallelize under `make -j` today; the recipe
serializes unconditionally (kinder under load; Rust is `--test-threads=1`
anyway); (ii) exit code — red-Go yields make's own exit 2 today
(`docs/log/9814.md:270`); the recipe yields the leg's code (e.g. 1). Nothing
parses specific codes (rc is a boolean signal,
`docs/engineering-style.md:1740-1742`).

Alternatives considered and rejected: (a) "just run `make -k test`" — changes
no default, so it is documentation, not a fix (note: pre-fix `-k` runs both
legs but SKIPS the announcement; post-fix it always prints); (b) parallel legs
(`-j`) — new failure modes (interleaved output, load) for no asked benefit;
the aggregate stays serial; (c) splitting CI jobs — there is no in-repo CI to
split (OQ-1 CLOSED); out of scope.

### API preservation

Target names `test`, `test-go`, `test-rust` unchanged; both legs still directly
runnable; `test-root` untouched. Exit contract: 0 iff both legs green (identical
to today when green; differs ONLY in the red-Go case, where Rust now also runs
and the exit stays nonzero; the nonzero VALUE changes from make's 2 to the
leg's code — boolean contract unchanged).

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
6. The new `test:` comment MUST NOT contain the literal `test-go:` (with
   colon): `TestMakefileRunsAuditPackageUncached` anchors on the FIRST
   `strings.Index(mk, "test-go:")` (`audit_canary_test.go:604`) and truncates
   at the first blank line (`:610`) — an earlier hit shifts the anchor into
   the `test:` block, which lacks `./pkg/refactoraudit/`, failing the guard.
   (The race canaries anchor per-line `HasPrefix` and are immune.)

### Risk table

| Class | Risk | Mitigation |
|---|---|---|
| R1 | Buggy status capture yields a false all-clear (the #4006 nightmare inverted) | Keep the capture trivial (`status` + trailing `exit`); shipped canary (test item 4, exact spec) asserts anchor + both legs with per-leg `||` + trailing exit |
| R2 | Contributors/scripts parsing `make test` output see Rust output after Go failure | Intended and documented at the target; no promised output contract exists |
| R3 | Red-Go runs now ALSO pay the full Rust suite (~minutes) instead of aborting early; post-Phase-1/pre-Phase-2 window pays a Rust suite that is ITSELF red per #10504 (183 fixture-MAC failures) — honest signal, contributor-friction spike | Intended (signal over speed); contributors iterating on Go can still call `make test-go` directly |
| R4 | Design review re-litigates `-k` vs recipe vs CI split | OQ-1/OQ-2 CLOSED in v2 (recipe required); no longer open |

### Test plan (against the red baseline)

Baseline today: `make test` aborts after red `test-go`; no cargo invocation.

1. `make -n test | grep` for both `$(MAKE) test-go` and `$(MAKE) test-rust`
   spellings (FAILS pre-fix: prereq form has no `$(MAKE)` lines). `-n` purity
   note (v2): the one-logical-line recipe contains `$(MAKE)`, which re-invokes
   with `-n` propagated, so sub-make leaves print-only — but the announcement
   echos print for real. Verify at implementation; item 1 proves spelling,
   item 2 proves runtime behavior.
2. Red-path (live, post-implementation): with the calibration still red,
   `make test` runs the `test-rust` leg, prints the announcement, and exits
   nonzero. Discriminators are test-PHASE evidence — assert `test result`
   summary lines in the output — NOT mere cargo-invocation visibility and NOT
   the exit code: `test-rust` is ITSELF red at base (#10504), so invocation
   alone cannot distinguish check-only from test-phase reach, and nonzero exit
   holds BOTH pre and post. If Phase 2 lands first (2→1 order), the red
   baseline is gone: run `make GO=false test` (a command-line override with
   no tracked-file mutation) to force the Go leg red, verify the Rust
   test-phase evidence, then rerun without the override. Full run costs
   minutes; that is the point of the change and is accepted once.
3. Green-path E2E (`make test` fully green) needs tree-wide Go green
   (`test-go` is `./...`; other packages carry standing reds, e.g.
   `docs/log/9919.md:122-131`) — Phase 2 removes only THIS lane's known red.
   Owner (v2, named once for both phases): the second-landing implementation
   PR runs full-green `make test` once, or the parent records it as an
   explicit merge-gate step. No test or fixture is modified to simulate green.
4. SHIP the canary (v2: OQ-3 closed as ship-with-exact-spec — a revert to
   prereqs fails SILENTLY in the #4006 shape, so the live run proves behavior
   once and only the canary prevents revert): new file
   `pkg/docsref/make_aggregate_10496_test.go` (own file in a repo-wide-property
   test package — NOT `pkg/refactoraudit`, preserving the inter-phase
   file-disjointness claim; reuses `docsref`'s `repoRoot(t)` pattern), which
   reads the Makefile from the repo root and asserts, recipe-lines-only
   (skip `#` comments and blank lines, property-not-spelling per
   `audit_canary_test.go:588-603`): line-anchored `^test:` target (line-start
   anchor — prefix hazard vs `test-go`/`test-rust`/`test-root`/`test-race-dp`,
   the same lesson as the pin test's `structs_6937_test.go:41-42` comment);
   the target line carries NO prerequisites; two TAB-indented recipe lines
   matching `$(MAKE) test-go` / `$(MAKE) test-rust`, EACH with `||`
   (a bare leg without capture swallows failure — without `set -e` the next
   command overwrites `$?`, the R1 false all-clear); trailing `exit $$status`
   AFTER both legs. Include a broken-snippet self-test (prereq-form snippet
   MUST fail the canary — naive contains-checks pass pre-fix) plus a
   zero-denominator control (fail if the `^test:` block is not found).
5. Re-run the three existing Makefile parser-canaries (uncached
   `TestMakefileRunsAuditPackageUncached` + the two race-gate coverage
   canaries) — cheap, guards the file Phase 1 edits.

### Out of scope

Fixing the Go-leg redness (Phase 2); CI workflow changes (none exist in-repo);
`test-root` merge; parallel legs. `pkg/` changes are limited to the single new
canary file in `pkg/docsref` (test item 4) — no production code, no
`pkg/refactoraudit` edits (disjointness preserved).

### Open questions (Phase 1 — all CLOSED in v2)

- **OQ-1 CLOSED (no kill): what invokes bare `make test`?** No in-repo
  automation (verified: no in-repo workflows; mutation driver calls legs directly).
  Humans do per the merge criterion (`docs/engineering-style.md:481`,
  `CLAUDE.md:95`, `README.md:241`) with observed lane-log breakage
  (`docs/log/9814.md:270`, `docs/log/9522.md:56-58`). Value = always-gate
  restoration; kill bar raised; no kill. (External-CI confirmation left to
  parent as non-blocking: even "none" no longer kills given the always-gate.)
- **OQ-2 CLOSED: recipe-capture REQUIRED.** Document-only needs an acceptance
  rewrite (the issue REQUIRES reaching Rust), doc rewrites (CLAUDE.md/README
  already promise "both"), and recreates the #7766 shape
  (remember-the-second-command gate).
- **OQ-3 CLOSED: SHIP the canary with the exact spec in test item 4.**
  Revert-to-prereqs fails silently (#4006 shape); the live run proves once,
  the canary prevents revert. Spec exactness is part of READY.

---

## Phase 2 — #10497: decouple the calibration from live drift (floor stays advisory)

Status: **DRAFT v2** (adjudicated fold; round-1 A: Phase1-MINOR /
Phase2-MAJOR; B: Phase1-MAJOR / Phase2-MAJOR; no kill).

### Issue framing

Two confirmed halves: (1) `StructWatchFloor` is advisory — `Tag()` has exactly
two consumers (calibration test + heatmap generator) and nothing fails when an
arbitrary struct crosses 20 types; (2) the calibration scans the LIVE tree, so
any unrelated field addition to CompileResult/Engine/xpfCollector can tip it.
(v2 OQ-5: the floor is INCLUSIVE by calibration — "drop to 20" was never the
remediation; the correct remediation of 21t is drop to ≤19.)

### Honest scope / value

Value if shipped: the Go leg stops reddening from unrelated struct drift, and
contributors are decoupled from CompileResult's field count. Tempered by the
verified census: **27 structs currently sit at/above the floors** (10
[REFACTOR], 17 [WATCH]; v2 caveat per P2-F6: the committed artifact lists 21
and omits CompileResult, proving it stale — live N ≥ 22, so 27 is plausible
but MUST be recounted live at implementation; it is OQ-4's load-bearing
premise). That kills "just enforce the floor" as a small change: a hard gate
on all structs is a ~27-row red on day one and needs grandfathering to be
shippable (see option A below and OQ-4). The recommended design therefore
keeps the floor advisory and fixes the LIVE-COUPLING half — the half that reds
unrelated contributors' runs.

### Shipped context

#6937 (the types-not-fields metric choice + the nested-struct counting trap in
`normalizeFieldType`), #6232/#7253 (the shell lib as single source of truth for
audit scope; `audit-structs` explicitly non-gating — `Makefile:442`: "NOTHING
IN `make test` FAILS ON WHAT THIS TARGET REPORTS" — floors are heatmap
thresholds by design, `structs.go:37-40`), #6626 (why the package runs
`-count=1` — the touched-file gate, INDEPENDENT of this phase, so the uncached
leg stays), #6743 r2-N3 (no `-run` narrowing of that leg), #10487
(accepted-entry lifecycle for FILE-modularity entries — verified distinct: no
`StructWatchFloor` reference; its mechanism is file-LOC-specific, so struct
enforcement would need a NEW mechanism — see Phase 2b), #10495 (adjacent docs
correction on the same base).

### Concrete design (recommended: B1 — TempDir fixture canaries)

`GoStructs(root, audited)` takes a root path, so the calibration can scan
fixtures instead of the live tree. Ship the fixtures as **Go source string
literals written to `t.TempDir()`** (precedent: `TestRustScannerSeesPubInPathStructs6937`
in the SAME file writes `x.rs` to a TempDir). Every fixture pins counts with
`==` assertions (`DistinctTypes==N`, `Fields==M`) — inequalities alone let
symmetric metric drift pass silently (v2: M1/P2-F3). Budgets (v2 exact spec):

- `over.go`: exactly 21 distinct types / 25 fields (just over the floor,
  mirroring Engine's documented 25-field role at a safely-flagging count) —
  asserts `DistinctTypes==21`, `Fields==25`, `Tag()=="[WATCH]"`.
- `under.go`: exactly 19 distinct types / 32 fields (just under the floor,
  mirroring CompileResult's role) — asserts `DistinctTypes==19`,
  `Fields==32`, `Tag()==""`, plus the inversion property
  `under.Fields > over.Fields && over.DistinctTypes > under.DistinctTypes`
  so the test still demonstrates WHY types are measured.
- `boundary.go`: exactly 20 distinct types / 24 fields (the INCLUSIVE-floor
  pin, v2 OQ-5 / M2 / P2-F4) — asserts `DistinctTypes==20`, `Fields==24`,
  `Tag()=="[WATCH]"`. The 19/21 pair is operator-agnostic (passes under both
  `>=` and `>`); this fixture is the ONLY pin of the documented inclusive
  semantics, and it is load-bearing: live Engine already drifted to 22t, so
  the live test NO LONGER exercises the exact-20 boundary at all.
- `aggregate.go`: exactly 11 distinct types / 120 fields (mirroring
  xpfCollector's 11-type / hundreds-of-fields shape at a cheap count) —
  asserts `DistinctTypes==11`, `Fields==120`, `Tag()==""`, plus the
  field-dominance analogue of the live force-condition
  (`aggregate.Fields > over.Fields`, cf. `structs_6937_test.go:115-119`; v2 m1).

The nested anonymous struct (hidden invariant 4) lives in `under.go` and counts
as 1 field + 1 `struct{...}` type token per `normalizeFieldType`
(`structs.go:116-126`) — already inside the 19t/32f budget above (v2 m2). The
PRIMARY collapse guard stays `TestGoCounterCollapsesAnonymousNestedStructs6937`
(`:201-208`, `Fields==4`/`DistinctTypes==2`); the fixture inclusion is
defense-in-depth, not the pin.

Why TempDir literals and NOT committed files (v2 P2-F5 premise corrected):
`AUDIT_SKIP_RE` excludes `target/`, `vendor/`, `zz_generated`, `_bpfel/_bpfeb`,
`.pb.go`, `_grpc.pb.go`, **`_test.go` (`:46`)**, `tests*.rs` variants,
`_KILLED/_WITHDRAWN`, findings, and `.lock` (`lib.sh:42-52`) — v1's "only
`target/`/`vendor/`" was FALSE. Consequences: committed `testdata/*.go` under
`pkg/` would STILL pollute the generator (no exclusion matches) — so "NOT
`testdata` stands on the corrected reason — while a committed source file named
`*_test.go` would be generator-clean, this calibration's accept-all scanner
would still read its declarations. TempDir is therefore sufficient, not
necessary; it stays the choice on same-file precedent + zero tree residue.
The calibration is fully hermetic per OQ-6 (below): no live leg remains, and
the test consequently also runs outside git checkouts (today `repoRoot6937`
`:15-22` Skipf's there — vacuous green; B1 removes that hole too).

Options considered:

- **A (enforce the floor as a real gate):** DECIDED-OUT of this phase (v2
  OQ-4: B1 stays advisory). Would be a NEW fourth gate — the documented three
  gates cover FILE-LOC only (`docs/refactoring-audit.md:98-102`) — against the
  repo grain (advisory heatmaps + narrow touched-file gates, #7253/#10487),
  with ~27 grandfather rows (recount at implementation) plus a NEW mechanism
  (#10487's is file-LOC-specific: newline counts, path-only identity;
  structs need path+name identity + `DistinctTypes` violations + boundary/readd tests).
  A future transition gate MUST compare merge-base versus working-tree rows per
  struct and fail only crossings 19→20 and 39→40 (with explicit path+name
  identity); a tree-global `Tag()!=empty` assertion would immediately fail on
  the existing ≥20 population and would not implement the intended
  “only reds when the invariant is newly violated” behavior. Becomes separate
  **Phase 2b** issue IF the team wants a real gate; needs a named product
  decider.
- **C (re-baseline CompileResult as OVER):** rejected — destroys the just-under
  calibration point, likely collapses the inversion story, and stays
  live-coupled (the next drift re-reds).
- **D (the `>=` → `>` question):** CLOSED — no operator change (v2 OQ-5:
  `>=` is INTENDED per `structs.go:37-44` + `:89-90` "at or above" + artifact
  `Engine@20 [WATCH]` + the Engine-must-flag test leg). The `boundary.go`
  fixture above is the permanent inclusive-semantics pin.

### API preservation

Under B1: `StructRow`, `GoStructs`, `Tag()`, both floor constants, and the
shell mirror are UNCHANGED — only the calibration test's data source changes
(live `pkg/` scan → TempDir fixtures). No generator, artifact, or docs change.
Option A now lives in Phase 2b (separate issue, separate surface); option D is
closed with no change.

### Hidden invariants (do not break)

1. The shell/Go floor VALUE mirror + `TestStructFloorsMatchShellConstants6937`
   stays green (B1 does not touch values — trivially preserved).
2. The `>=` OPERATOR was pinned by NOTHING at v1 (the pin test covers
   constants only) — v2 pins it with the permanent `boundary.go` exact-20
   fixture asserting `[WATCH]`. Any future operator change must update `Tag()`
   and that fixture together. The shell generator delegates classification to
   `Tag()`; its shell library only mirrors the floor values.
3. The uncached leg (`Makefile:271`, full-package `-count=1`, no `-run`) stays
   as-is: it exists for the touched-file gate, not for this test (#6626).
4. `normalizeFieldType`'s nested-struct collapse (the #6937 trap) is exercised
   by the nested anonymous struct in `under.go` (1 field + 1 `struct{...}`
   token, inside the 19t/32f budget) — fixtures exercise it, not bypass it.
5. `AUDIT_SKIP_RE` stays the single source of truth for exclusions
   (#6232/#7253); B1 adds no exclusion and no committed fixture file.
6. The inversion property — `under.Fields > over.Fields` and
   `over.DistinctTypes > under.DistinctTypes` — makes the test a metric
   justification rather than a threshold assertion; the fixtures MUST preserve
   it.

### Risk table

| Class | Risk | Mitigation |
|---|---|---|
| R1 | Fixtures drift from reality: the metric rots while the test stays green (calibration becomes vacuous) | Fixtures pin counts with `==` (types AND fields per fixture, incl. the exact-20 boundary) so metric-code changes still bite; negative controls (below) prove the test can fail |
| R2 | Reviewers expect the live CompileResult/Engine story; fixture names must carry the mapping | Name fixtures + comments after their live counterparts; comment cites live counts as of v2 (Engine 27f/22t, CompileResult 32f/21t, xpfCollector 443f/11t) |
| R3 | None material — TempDir fixtures are milliseconds; the package's ~10.7s uncached cost is unchanged | No mitigation needed |
| R4 | OQ-4/OQ-5 answers could redirect to enforcement (A) or operator fix (D), invalidating B1 | CLOSED in v2 (B1 advisory + Phase 2b split; `>=` intended) — no longer open |

### Test plan (against the red baseline)

Baseline today: `TestStructMetricIsTypesNotFields6937` FAILS on live
CompileResult (32f/21t).

1. At implementation START, record the full
   `go test -count=1 ./pkg/refactoraudit/` fail list (v2 P2-F7 — STEP-0 ran
   single-`-run` only), then re-verify the 47-test / 14-file counts (siblings add tests).
   Done = calibration green + fail-set ⊆ baseline-minus-calibration. Post-B1
   expectation: package GREEN (isolated caches per lane convention) — the
   live CompileResult drift no longer reaches the test.
2. Negative controls (prove the test still bites — run, then revert): (a) add
   one distinct-typed field to the `under` fixture → 19+1=20 MUST fail (valid
   now that OQ-5 closed `>=` as intended — this transient control is also
   committed permanently as `boundary.go`); (b) remove distinct types from the
   `over` fixture to 19 → MUST fail, necessarily DUAL-tripping both the
   `Tag()` assertion AND the inversion check (19>19 false — say so; v2 P2-F8).
   Neither control touches production code or committed fixtures permanently.
   Each committed pin must be red-on-revert (delete any single `==`
   assertion → a one-field fixture mutation passes silently).
3. `TestStructFloorsMatchShellConstants6937` still passes (untouched, but in
   the same file — the full-package run covers it).
4. `audit-structs` output byte-identical before/after (B1 adds no committed
   file under an audited root) — `sha256sum` the generator output at base vs
   post-change in the implementation PR (v2 P2-F8 baseline spec).
5. Full-green `make test` ownership: named once in Phase 1 test item 3 (the
   second-landing PR or an explicit parent merge-gate step) — not re-deferred
   here.

### Out of scope

Enforcing the floor on all structs (separate Phase 2b issue per OQ-4 — needs a
named decider + live recount + new grandfather mechanism); changing floor
VALUES; changing the `>=` operator (CLOSED per OQ-5 — intended); #10504's
Rust/fixture work; generator or artifact changes; touching the Makefile.

### Open questions (Phase 2 — all CLOSED/DECIDED in v2)

- **OQ-4 CLOSED: B1 advisory stays advisory; enforcement-A becomes separate
  Phase 2b.** Floors are heatmap thresholds by design (`structs.go:37-40`;
  `audit-structs` explicitly non-gating, `Makefile:442`, #7253); the three
  documented gates cover FILE-LOC only (`docs/refactoring-audit.md:98-102`).
  A real struct gate is a NEW feature (new gate + ~27 grandfather rows +
  new mechanism), not a restoration — needs a named product decider on the
  Phase 2b issue.
- **OQ-5 CLOSED: `>=` at 20 is INTENDED, not off-by-one.**
  `structs.go:37-44` ("Thresholds are chosen from the measured distribution …
  `>= 20` selects 16 … Engine 25 fields 20 types FLAGS (just over)"), `:89-90`
  ("at or above"), the committed artifact's `Engine@20 [WATCH]`
  (`docs/refactoring-audit-structs.txt:21`), and the Engine-must-flag test leg
  (historical Engine sat exactly at 20 when calibrated — this is not a claim
  about current live counts: v2 re-grounded Engine is 27f/22t). The
  implementation MUST recount live rows before any future gate decision; under
  `>` the historical just-over point collapses. No operator change; correct
  remediation of 21t is drop to ≤19; the permanent `boundary.go` exact-20
  fixture pins the inclusive semantics. This CLOSED the last PLAN-KILL path
  against B1.
- **OQ-6 DECIDED: FULLY HERMETIC** (parent adjudication; overrules review-B's
  keep-one-live lean). All four fixtures hermetic; no live leg remains: the
  live leg IS the defect class being removed, and keeping one live leg keeps
  the live `pkg/` scan + git-checkout dependency with it. Retained drift
  signal: the `audit-structs` artifact diff (`Makefile:482-496` — stale
  artifact is review-visible human warning). Explicit acceptance: automated
  live credibility-monitoring of the generator's top row is LOST (if the
  tree's largest aggregate flags in future, no test reds) — accepted because
  the artifact diff preserves human reviewability and the coupling class is
  worse than the warning loss.

---

## Inter-phase dependency ruling (explicit)

**Phase 2 does NOT need Phase 1 merged first.** The mechanisms are independent
(Makefile aggregate vs Go calibration), the files are disjoint (`Makefile` +
new `pkg/docsref` canary file vs `pkg/refactoraudit/*_test.go` — the canary's
own-file-outside-`pkg/refactoraudit` placement is what KEEPS this claim true),
and neither design assumes the other's presence. Recommended IMPLEMENTATION
order (v2 wording fix: this is branch-internal order, not merge order — both
phases ride this ONE branch serially) is Phase 1 → Phase 2 ONLY because Phase
1 restores the Rust signal fastest while the Go leg is still red; Phase 1's
full-green E2E verification additionally needs tree-wide Go green (Phase 2
removes only this lane's known red). Either order implements cleanly. (Plan
round now; implementation in a later round after parent-run plan review;
v2 goes to delta re-review next.)

## Verification appendix (plan-round evidence)
- `git rev-list --left-right --count 21df4afd8...origin/master` → `0 0`
  (rebased base before the v1 plan commit; re-fetched for v2, no drift).
- `gh pr list --state merged --search 10496/10497` → empty; `git log` on the
  three evidence paths → no fix commit.
- `make` aggregate: `Makefile:99`; uncached leg: `:271` (drifted from the
  issue's `:248-252` — re-grounded post-rebase); `test-rust`: `:362-367`.
- Floor: `structs.go:77`; `Tag()`: `:91-100`; calibration:
  `structs_6937_test.go:63-120`; `>=` calibration prose: `structs.go:37-44`.
- Tree-wide `.Tag()` consumers: calibration test + `structaudit/main.go:63` only.
- Tree-wide `StructWatchFloor` consumers: `structs.go`, `structs_6937_test.go`,
  shell mirror in `scripts/refactoring-audit-lib.sh:106` — #10487's
  `accepted_live_test.go` absent (distinct scope).
- `.github/` contains only `instructions/` — no `workflows/` (OQ-1's premise).
- Live census: 10 [REFACTOR] + 17 [WATCH] = 27 structs ≥ floors (OQ-4's premise;
  recount live at implementation — committed artifact lists 21 and omits
  CompileResult, proving staleness).
- v2 live trio: Engine 27f/22t (doc: 25f/20t — drifted, still flags),
  CompileResult 32f/21t (the red), xpfCollector 443f/11t (unflagged).
- Full-package re-run (v2, `GOCACHE=/dev/shm/gocache-10496`,
  `GOTMPDIR=/dev/shm`, `go test ./pkg/refactoraudit/ -count=1`) exited 1 only
  at `TestStructMetricIsTypesNotFields6937` (32f/21t vs 20); the package's
  other tests passed, with only the known advisory global-artifact freshness
  report.
- v2 closes: OQ-1 (always-gate `docs/engineering-style.md:481`), OQ-5
  (`>=` intended), OQ-6 (fully hermetic), OQ-4 (B1 + Phase 2b); canary home
  `pkg/docsref` (repo-wide-property tests + `repoRoot(t)` precedent).
