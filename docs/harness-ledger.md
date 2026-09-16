# The harness result ledger

*Refs #8302. Implements steps 3 and 5 of the harness design: one result
envelope per gate run, a tracked ledger, and a band comparator over it.*

The tree does not lack measurement harnesses — it has more than anyone runs.
What it lacked was a **record**: a run's result went to an artifacts directory,
got read once by a human, and was gone. Nothing the next run could be compared
against, and nothing that distinguished a regression from a flake except
running it again.

This document describes what a gate run now records, why the verdict is a
string, and how to read the comparison.

## Contents

| Path | What it is |
|---|---|
| `test/incus/harness-result.sh` | the adapter table, the emitter, and the run wrapper |
| `test/results/ledger.d/` | the tracked ledger — one `<run_id>.json` shard per gate run |
| `test/incus/ledger_compare.py` | the band comparator and `ledger-lint` |
| `test/incus/harness-result-selftest.sh` | hermetic cells for the adapters, the emitter and the wrapper |
| `test/incus/ledger_compare_test.py` | hermetic cells for the comparator |
| `test/incus/harness-ledger-mutation-selftest.sh` | the mutation gate over both |

Everything here is hermetic. No cluster, no lock, no network, seconds to run.

## Why the verdict is a string

The single most load-bearing fact about this layer is that **the tree's own
tools already disagree about what `exit 1` means**, and the disagreement is not
cosmetic:

| Tool | exit 0 | exit 1 | exit 2 |
|---|---|---|---|
| `newflow_ceiling_analyze.py` | `VALID` | **`INVALID` — the run did not measure what it claims to** | `INCONCLUSIVE` |
| `mouse_latency_aggregate.py` | `PASS` | **`FAIL` — measured, and the gate is violated** | `INSUFFICIENT-DATA` |
| `iperf-throughput-lib.sh` | — | *(no void state at all: "no measurement" is emitted as a FAIL)* | — |
| `run-selftests.sh` | pass | fail | *(77 = a leg SKIPped)* |

So `exit 1` means "did not measure" in one tool and "this is a regression" in
another, and the direction of a mis-file is expensive both ways: a void read as
a regression burns a bisect, a regression read as a void is ignored.
`mouse_latency_aggregate.py`'s own docstring records that this already shipped
once — C175-HC-029, a real latency FAIL painted green.

A loop layer that shells out and reads exit codes therefore **must not invent a
convention and hope the tools converge on it.** The verdict travels as one of
three STRINGS in the row — `PASS`, `FAIL`, `VOID` — and each source gets an
explicit row in an adapter table that is itself exercised by cells.

### The adapter table

| Source | → PASS | → FAIL | → VOID |
|---|---|---|---|
| the 12 smoke gates (`pass()`/`fail()`, `ha-smoke` or `smoke-cells`) | `failed == 0` (+ anchored figure for `ha-smoke` PASS) | `failed > 0` | no summary line; `passed + failed == 0`; summary says 0 failed but the process exited non-zero; `ha-smoke` PASS with no figure |
| `newflow_ceiling_analyze.py` | `verdict=VALID` | *(never — it reports a rate, not a gate)* | `INVALID`, `INCONCLUSIVE`, no JSON document, VALID without the headline metric |
| `mouse_latency_aggregate.py` | `verdict=PASS` | `verdict=FAIL` | `INSUFFICIENT-DATA`, no verdict line, a verdict without a ratio |
| `run-selftests.sh` | `failed=0` | `failed>0` | no summary; `passed + failed == 0` (it swept an empty set) |
| `iperf-throughput-lib.sh` | `PASS …` | `FAIL … too low` | **`FAIL … no measurement at all` / `… unparseable`** |

That last row is the table earning its keep. `iperf-throughput-lib.sh` has no
void state to express, so it files a non-measurement as a regression; the
adapter recovers the third state from the text.

### Two adapters cover the twelve smoke gates

The eight destructive HA smokes plus `test-connectivity.sh`,
`test-wire-properties.sh`, `persistent-nat-failover.sh` and
`dhcp-lease-failover.sh` carry byte-identical `pass()`/`fail()` definitions
and all end with a `<n> passed, <n> failed` summary. **The adapters match the
numeric tail, never the label prefix** — the prefixes differ (`Failover test:`,
`HA crash test:`, `Double failover test:`, `Stress failover:`,
`Chained crash test:`, `Restart connectivity:`, and a bare `Results:` on two
of them), so a prefix-anchored adapter silently covers six of eight while
looking complete. Nor is it anchored at end of line: `test-connectivity.sh`
continues `, <n> skipped` after the pair.

The summary parse is shared; the headline is not (#9922 F-155). The five smokes
that emit an iperf3 throughput cell keep `ha-smoke`, whose PASS headline is
FIXED to `throughput_gbps` and whose figure comes ONLY from a `PASS`/`FAIL`
cell line (floor/threshold prose used to become a banded measurement). The
seven that emit cells only take `smoke-cells`, whose headline is FIXED to
cells_passed. A Makefile↔script cross-check asserts each gate's adapter
matches whether its script calls `iperf_throughput_verdict`, so a mis-mapping
reds instead of silently switching headline families.

Both prefix mistakes are mutation cells, and the selftest's census does not
invent its fixtures — it **extracts the real `echo` line from each of the
twelve scripts** (the LAST one for `dhcp-lease-failover.sh`, which carries an
early-exit echo plus the canonical final) and renders it. It also asserts that
the *discovered* set of gates carrying the shape **equals** the declared set,
so a thirteenth gate added later cannot accumulate uncovered.

## What a row records

```json
{"schema":1,"ts":"2026-09-02T18:04:11Z","gate":"test-failover",
 "env":"loss-userspace-cluster","verdict":"PASS","void_reason":"",
 "headline_metric":"throughput_gbps","headline_direction":"higher-better",
 "metrics":{"cells_passed":21,"cells_failed":0,"throughput_gbps":23.1},
 "build_git_sha":"1a56c19dc…","build_exe_sha256":"…","running_exe_sha256":"…",
 "exe_check":"MATCH","duration_s":412,"artifacts":null,"adapter":"ha-smoke",
 "node":"loss:xpf-userspace-fw0","node_peer":"loss:xpf-userspace-fw1",
 "running_exe_sha256_peer":"…","exe_scope":"both"}
```

### Provenance: which build actually produced the measurement

Recording the checkout's HEAD alone is **not enough**. The checkout is
routinely a different tree from what is running on the node — that is precisely
the failure `deploy-lib.sh` already dies on (#2176, *"the node is running STALE
code"*). Three fields, because two of them are different kinds of value:

* `build_git_sha` — provenance of the *tree*, with a `-dirty` suffix when it
  has uncommitted changes, because a dirty tree's sha does not identify a
  binary and saying so is the point. The ledger file itself is excluded from
  that test: it is the emitter's own output, so counting it would pin every row
  to `-dirty` forever — including rows from a pristine checkout — and a flag
  that is always on carries no information;
* `build_exe_sha256` — sha256 of the locally built `xpfd` from that tree;
* `running_exe_sha256` — sha256 of the **live process image** on the node.

The readback is not a new mechanism. `deploy_verify_running_xpfd` already did
`sha256sum /proc/$PID/exe`; that inline block was **extracted** into
`deploy_running_xpfd_sha256()` so there is exactly one running-exe readback in
the tree. A second implementation would be free to disagree with this one about
which process it read, and the whole value of the readback is that it is the
authority on what is executing.

`exe_check` is the comparable, and it has **four** values so "we could not
check" is not spelled the same as "checked and fine":

| Value | Meaning |
|---|---|
| `MATCH` | the node is running the build under test |
| `MISMATCH` | the node is running some other build — #2176's stale-code condition |
| `UNAVAILABLE` | the readback did not happen (no MainPID, no local binary, incus unreachable) |
| `NOT-APPLICABLE` | a hermetic gate; there is no deployed binary to check |

**The emitter refuses a non-VOID verdict carrying `MISMATCH` or `UNAVAILABLE`.**
A measurement of a binary nobody can name is not a result. The rule lives in
the emitter rather than in each caller so a future caller cannot forget it.

### The attestation covers BOTH nodes, and says so when it cannot (#9044)

The readback used to read **node 0 only**, on the stated ground that "both
nodes carry the same build after a `cluster-deploy`, so one readback is the
attribution point for the run". That is a property of one way of *invoking*
the deploy, not of the system. `Makefile`'s `NODE ?= all` is a plain override
and `cluster-setup.sh deploy [0|1|all]` accepts the scope, so

```
make cluster-deploy NODE=0
make test-failover
```

is two ordinary lines. The failure is **asymmetric**, and only one direction is
dangerous:

| Deploy scope | fw0 | fw1 | Old row |
|---|---|---|---|
| `NODE=1` | old build | new build | `MISMATCH` → **VOID**. Fails safe. |
| `NODE=0` | new build | old build | **clean `MATCH`** — for a gate that failed over onto the unattested node. |

An HA smoke **fails over by definition**, so the node a single-node attestation
skips is the node the result depends on. Both nodes are now read back:

* `node_peer` / `running_exe_sha256_peer` — the peer half, so what fw1 was
  running at the time of the run is recoverable rather than lost;
* `exe_scope` — `both`, `local-only`, or `n/a` (hermetic). This is the fact the
  row previously **could not express at all**: "I attested one of the two nodes
  this gate used".

A peer running a **different** build makes the row `MISMATCH` → VOID, by the
same #2176 rule as a local mismatch. A peer that is **unreadable** does *not*:
`test-ha-crash`, `test-chained-crash` and `test-double-failover` force-stop a
node and may legitimately leave it down when the gate ends, so voiding there
would red exactly the gates whose job is to kill a node — the same mistake the
exit-status rule below refuses to make. That case records `exe_scope=local-only`
instead, which a reader can tell apart from a whole-cluster `MATCH`.

Both new fields are **additive**: `REQUIRED_KEYS` is unchanged, so every row
already emitted still lints. An old row carries neither key, which is exactly
the state it was emitted in — a single-node attestation with no way to say so.

### The row's verdict and the gate's exit status are separate

An unattributable run records a **VOID row** and leaves the gate's own exit
status **unchanged**. `make test-failover` exits exactly as it did before: 0
when the smoke passed, 1 when a cell failed. Reddening the mandatory HA gate
because `./xpfd` was never built in this worktree would be a loop layer
breaking the gate it exists to measure.

The one deliberate change is in the safe direction: a gate that **exits 0
without reaching its summary** now exits 2. That state was previously
indistinguishable from a clean run to anything reading only the tail.

### What the emitter refuses

It writes **no row** (exit 2) for: a verdict outside the three; a `VOID` with an
empty reason; a `PASS`/`FAIL` carrying one; an unknown or missing `exe_check`;
`MISMATCH`/`UNAVAILABLE` on a non-VOID verdict; an empty metrics map on a
`PASS`/`FAIL`; a headline metric absent from the row's own metrics; a
non-numeric metric value; an empty gate or env.

A gate that cannot say which of the three it is writes nothing, and an absent
row is visibly absent to the comparator — whereas a defaulted row is not.

## Reading a comparison

```
make harness-compare GATE=test-failover [ENV=loss-userspace-cluster]
```

| Outcome | Meaning |
|---|---|
| `REGRESSION` | the headline is outside the band of the last K green runs, in the bad direction |
| `WITHIN-BAND` | inside it |
| `IMPROVED` | outside it in the good direction — recorded, not celebrated |
| `NO-BASELINE` | fewer than K green rows exist. **Not a PASS.** |
| `VOID` | the newest row is VOID; nothing was measured |
| `LEDGER-CORRUPT` | a line does not parse or violates the row contract |

Exit status deliberately mirrors `mouse_latency_aggregate.py` — the one tool in
the tree that got this right — and not `newflow_ceiling_analyze.py`, whose
`exit 1` means the opposite: **0** = within band / improved and green, **1** =
regression, or the newest row is a FAIL, **2** = undetermined (VOID,
NO-BASELINE, LEDGER-CORRUPT). Act on the `outcome` string; the integer exists
because a shell caller needs one.

### The band

A robust interval over the last `K = 3` **green** runs at the **same env**
carrying the **same headline metric**:

```
median ± max(3.0 · 1.4826 · MAD, 0.05 · |median|)
```

Median/MAD rather than mean/stddev so that one bad run inside the baseline
cannot widen the band enough to hide the next one. The relative floor exists
because a perfectly repeatable gate would otherwise get a zero-width band and
report `REGRESSION` on ordinary jitter — and it is deliberately small, because
a band that is too wide is the decay mode with no symptom.

Three rules carry the design:

1. **VOID rows never enter the band and never satisfy the K floor.** A void is
   not a data point.
2. **`NO-BASELINE` is not `PASS`.** "We have no grounds to judge this" and
   "this is fine" are different answers, and collapsing them is how a loop
   stops being able to say anything.
3. **Fewer than three green rows is `NO-BASELINE`, full stop.** Two points have
   no dispersion, and a band drawn through them is a number wearing the shape
   of evidence.

Rows from another env, another gate, a `FAIL` run, or a run whose headline
metric was something else do not enter the baseline.

### Flake or regression, without re-running blindly

Every row carries invariant metrics beside its headline. When the headline
leaves the band, each invariant that has a baseline of its own is banded too:

| Situation | Signal |
|---|---|
| headline moved, every invariant held | `flake-candidate` — re-run **this** gate |
| headline moved, some invariant moved too | `regression-candidate` — the move came with a behaviour change |
| headline moved, no invariant has a baseline | `undetermined` |

The third is deliberately not folded into the first: "every invariant held" and
"there were no invariants to check" are the same sentence only if you do not
look.

## The ledger: one file per run

`test/results/ledger.d/<run_id>.json` is git-tracked, one shard per gate run;
bulk artifacts stay untracked behind the `/artifacts/` gitignore line (#8323).

It was a single appended `ledger.jsonl` until #8346. Dozens of lanes run gates
in parallel here, so every one of them appending to one tracked file conflicted
on ordinary operation. Every row is a real record, so those conflicts were
always union-resolvable — which is exactly the problem: a hand resolve on a
data file, on every rebase, is where a row gets dropped by accident.

**One file per run removes the decision rather than adding a rule to remember
under merge pressure.** Two writers never touch the same path, because `run_id`
is unique per run and already in the row. No merge driver is involved at all —
the repo no longer has a `.gitattributes` at all, because that one rule was the
only thing in it.

That last point is not incidental. The `merge=union` rule that used to sit
there was **disarmed for months without anyone noticing**: this repo's
`.git/config` defined a custom driver *named* `union` whose command was the
shell no-op `true` (#8348, residue of the rejected PR #1582). A custom driver
shadows git's built-in, so every `merge=union` path silently resolved to
"ours" — exit 0, no conflict, nothing in the merge summary, and `git check-attr`
reporting `merge: union` throughout. Three real gate records were lost that way.
A rule whose driver can be disarmed from a file nobody reads does not belong in
the path of a data file.

### The filename is the identity

A shard is named for the `run_id` it contains, and `lint_shard_names` enforces
that. It is what makes concurrent writes conflict-free, and it is what lets the
merge guard read the run-id set straight off a **git tree** — `git ls-tree
--name-only <rev> test/results/ledger.d/` — with no parsing at all, so a shard
whose *content* was damaged still contributes its id.

### What each check can and cannot see

Stated plainly, because an overstated claim about a detector is how the #8348
gap stayed invisible for months — it stops the next person looking.

| Check | Sees | Does NOT see |
|---|---|---|
| `ledger-lint` (`--lint`) | a malformed row, a committed conflict marker, a hand-edited row that violates the emitter's contract, a shard whose filename disagrees with its `run_id`, an **empty** ledger | **a row that is simply GONE.** A deleted shard leaves a well-formed, internally consistent, perfectly lint-clean directory |
| `ledger-merge-completeness` (`--lint-merge`, #8349) | a merge result missing any `run_id` present in **either parent** — a set check, so a drop-one-add-one is caught where a count would not be | anything about a non-merge commit; it is a no-op on a linear HEAD and says so |

Neither substitutes for the other, and `--lint-merge` is the one that can see a
loss. It reads **both layouts at every revision** — the legacy `ledger.jsonl`
*and* the shard directory — because a parent commit from before #8346 has no
`ledger.d/` at all: a source reading only the new layout would return the empty
set for that parent and pass vacuously, loudest on the migration's own merge.

Both legs run under `make selftest`. `--lint` **fails on a zero-row ledger**:
an empty directory is the new empty ledger, and linting nothing and reporting
success is the swept-nothing pass.

## Mutation cells, and why they are not optional

**A comparator with a broken band is indistinguishable from a healthy one on
every green run, and a loop is green almost all the time by construction.**
Reading the code does not separate them either — every mutation below is a
plausible-looking line.

`make test-harness-ledger-lib` runs `harness-ledger-mutation-selftest.sh`,
which removes one guard at a time and asserts the cell suite goes RED:

| Cell | What it removes |
|---|---|
| `band-over-void-rows` | the VOID/FAIL exclusion from the baseline |
| `no-baseline-collapsed-into-pass` | "we cannot judge this" reported as "this is fine" |
| `no-baseline-exits-zero` | the exit-status half of the same collapse |
| `k-floor-below-three` | the K ≥ 3 floor |
| `band-widened-by-floor` / `band-widened-by-z` | band width — a 48% throughput regression fits inside |
| `band-comparison-inverted` | the direction of the band test |
| `env-filter-dropped` | the same-env restriction |
| `corrupt-line-skipped` | the refusal on a damaged ledger line |
| `empty-ledger-lints-clean` | the empty-set FAIL in `ledger-lint` |
| `empty-invariant-set-reads-as-flake` | "no invariant had a baseline" vs "every invariant held" |
| `ha-adapter-anchored-on-a-label-prefix` | numeric-tail matching (covers 6 of 8) |
| `ha-adapter-anchored-at-end-of-line` | tolerance of `test-connectivity.sh`'s trailing field |
| `missing-summary-scored-as-a-pass` | the VOID for a smoke that died before its summary |
| `void-without-a-reason-accepted` | the "a VOID must say why" refusal |
| `unnameable-binary-accepted` | the #2176 refusal |
| `row-void-degrades-the-gate-exit-status` | the row/gate separation |
| `non-numeric-metric-accepted` | the numeric-metric contract |

Three properties of the runner itself matter as much as the cells:

* **A positive control runs first.** The unmutated copies must be GREEN. A
  runner whose gate always reds would score every mutation as killed and report
  a perfect sweep of an inverted world.
* **A mutation that did not apply is a VOID, not a kill and not an escape.**
  "The measurement did not happen" is a third state here too.
* **Zero cells is a failure, not a clean sweep.**

An ESCAPED mutation is the report: it says the guard has no power, and a guard
with no power is worse than none, because its green is quoted as evidence. When
this gate was first run, `env-filter-dropped` escaped — the fixture put the
wrong-env row where the last-K window never reached it. The guard was real; the
cell could not see it. That is the class of defect nothing but a mutation
finds.

## Adding a gate

Three lines:

1. a Makefile recipe that runs it through `harness-result.sh run`;
2. an `--adapter` naming its verdict vocabulary (add a row to the table in
   `harness-result.sh` if it speaks a new one, with cells in
   `harness-result-selftest.sh`);
3. an `--env` label so its runs are only compared against runs of the same
   thing.

Step 1 is also what the reachability census (`make harness-census`, added
alongside this as design step 2) requires: a runnable harness must be invoked
by a Makefile recipe or declared in `test/incus/HARNESSES.unreached` with a
reason. A gate wired through `harness-result.sh run` satisfies it by
construction — `harness-result.sh` itself classifies **reached** because those
recipes invoke it — so the two layers do not need separate registration.

## Falsifiability summary

| Component | If the property is FALSE | If the measurement did not happen | On an empty set |
|---|---|---|---|
| adapters | `FAIL` with the metric that moved | `VOID` plus a reason | no summary line → `VOID`, never a pass |
| `harness_result_emit` | n/a — an emitter, not a gate | refuses (exit 2) and writes **no row** | refuses an empty metrics map on a PASS/FAIL |
| `ledger_compare` | `REGRESSION` with the value, the band, K, and the build sha | `VOID` or `NO-BASELINE` — never `WITHIN-BAND` | zero matching rows → `NO-BASELINE` |
| `ledger-lint` | names the first bad line or the mis-named shard | n/a | **FAIL** on a zero-row ledger (an empty `ledger.d/`) |
| `ledger-merge-completeness` | names every `run_id` the merge dropped, and which parent had it | n/a — a pure git read | a non-merge HEAD reports "nothing to check", never "clean" |
| mutation gate | reports the ESCAPED mutation by name | a cell whose mutation did not apply is a VOID and a failure | zero cells is a FAIL |
