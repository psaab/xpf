#!/usr/bin/env python3
"""Compare the newest gate run against a band over the last K green runs.

Reads ``test/results/ledger.d/`` (written by ``test/incus/harness-result.sh``)
and answers ONE question about one gate at one env: is the newest headline
metric inside the distribution of the runs we already trust?

Storage: one file per run (#8346)
---------------------------------
The ledger is a DIRECTORY of ``<run_id>.json`` shards, not one appended file.
Dozens of lanes run gates concurrently here, and every one of them appending to
a single tracked file made a merge conflict on ordinary operation. Every row is
a real record, so those conflicts were always union-resolvable -- which is
precisely the problem: a hand resolve on a data file, on every rebase, is where
a row gets dropped by accident, and one did.

One file per run removes the decision instead of adding a rule to remember
under merge pressure: two writers never touch the same path, because ``run_id``
is already unique per run and already in the row. No merge driver is involved
at all, which matters because this repo's ``.git/config`` shadowed git's
built-in ``union`` driver with a no-op for months (#8348) and silently dropped
three real rows.

A legacy single-file ``ledger.jsonl`` is still READ wherever one is named --
:func:`load_ledger_text` accepts either -- because history is full of them and
:func:`run_ids_at_rev` has to see across the migration. Nothing WRITES one.

Why a band and not "compare against the previous run"
-----------------------------------------------------
A single prior value cannot tell a regression from a flake, so a comparator
built on it either cries wolf or is tuned until it says nothing. The band is a
robust interval over the last ``MIN_BASELINE_RUNS`` **green** runs at the same
env; a run outside it is reported, a run inside it is not, and the number of
runs that went into the band is printed so a thin baseline is visible rather
than implied.

Three rules carry the whole design, and each one is a mutation cell in
``ledger_compare_test.py`` because a comparator with a broken band is
INDISTINGUISHABLE from a healthy one on every green run -- and a loop is green
almost all the time by construction:

1. **VOID rows never enter the band.** A void is not a data point. It is the
   record of a run that did not measure what it claims to, and letting one into
   a baseline is the direct generalisation of the failure
   ``newflow_ceiling_analyze.py`` documents at length -- a missing input
   degrading into a value that then skips the gate reading it.
2. **``NO-BASELINE`` is not ``PASS``.** "We have no grounds to judge this" and
   "this is fine" are different answers. Collapsing them is how a loop stops
   being able to say anything, and it is the collapse that a green history
   hides best.
3. **Fewer than K green rows is NO-BASELINE, full stop.** K is 3. Two points
   have no dispersion to speak of and a band drawn through them is a number
   with the shape of evidence.

Drift is IN scope, beside the rolling window rather than inside it (#9922
F-088). The rolling band judges each step against the last K greens and so
absorbs a slow decay one step at a time; the pinned baseline (the FIRST K
greens) judges the newest run against genesis and the result carries the
cumulative displacement plus a drift flag. Drift is reported, not failed:
attribution needs a human.

Flake vs. regression without re-running blindly
-----------------------------------------------
Every row carries invariant metrics beside its headline. When the headline
leaves the band, each invariant that has its own baseline is banded too:

* headline moved, every invariant held        -> ``flake-candidate``
* headline moved, some invariant moved too    -> ``regression-candidate``
* headline moved, NO invariant has a baseline -> ``undetermined``

The third is deliberately not folded into the first. "Every invariant held" and
"there were no invariants to check" are the same sentence only if you do not
look, and the empty set is exactly where a check fails to a value
indistinguishable from healthy.

Falsifiability of this module
-----------------------------
If the property is FALSE (the metric really regressed): ``REGRESSION``, with
the value, the band, the K that produced it, and the build sha of the newest
row and of the baseline.
If the measurement did not happen: ``VOID`` (the newest row is void) or
``NO-BASELINE`` (too few greens). Never ``WITHIN-BAND``.
On an empty set (no rows for this gate/env at all): ``NO-BASELINE``, never a
pass.
If the ledger itself is damaged (an unparseable line, a committed conflict
marker): ``LEDGER-CORRUPT`` naming the first bad line -- never a silent skip,
because a skipped row does not count toward K while looking like it does.

Exit status
-----------
Deliberately mirrors ``mouse_latency_aggregate.py``, the one tool in the tree
that got this right, and NOT ``newflow_ceiling_analyze.py``, whose exit 1 means
the opposite:

    0  WITHIN-BAND or IMPROVED, and the newest row is a PASS
    1  REGRESSION, or the newest row is a FAIL -- measured, and bad
    2  VOID / NO-BASELINE / LEDGER-CORRUPT -- undetermined, NOT a pass

The verdict a caller should act on is the ``outcome`` STRING, not this integer;
the integer exists because a shell caller needs one and defaulting it would
repeat the confusion this whole layer was built to end.
"""

from __future__ import annotations

import argparse
import json
import re

import statistics
import sys
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

#: Green runs required before a REGRESSION may be claimed at all. Below this the
#: answer is NO-BASELINE. Three is the floor, not a target: two points have no
#: dispersion and a band through them is a number wearing the shape of evidence.
MIN_BASELINE_RUNS = 3

#: Half-width of the band, in robust standard deviations. 1.4826 * MAD is the
#: consistency constant that makes the median absolute deviation an estimator of
#: sigma for normal data; the median/MAD pair is used rather than mean/stddev so
#: that ONE bad run inside the baseline cannot widen the band enough to hide the
#: next one.
BAND_Z = 3.0

#: Minimum half-width as a fraction of |median|, applied when the baseline is
#: tighter than this. Without it a perfectly repeatable gate gets a zero-width
#: band and every run after it reports REGRESSION on ordinary jitter. With it
#: too large, a real regression fits inside the band and is never reported --
#: which is why "widen the band" is one of the required mutation cells.
BAND_REL_FLOOR = 0.05

VERDICTS = ("PASS", "FAIL", "VOID")
EXE_CHECKS = ("MATCH", "MISMATCH", "UNAVAILABLE", "NOT-APPLICABLE")
REQUIRED_KEYS = (
    "schema",
    "run_id",
    "ts",
    "gate",
    "env",
    "verdict",
    "void_reason",
    "headline_metric",
    "headline_direction",
    "metrics",
    "build_git_sha",
    "exe_check",
)

# Outcomes.
REGRESSION = "REGRESSION"
WITHIN_BAND = "WITHIN-BAND"
IMPROVED = "IMPROVED"
NO_BASELINE = "NO-BASELINE"
VOID = "VOID"
LEDGER_CORRUPT = "LEDGER-CORRUPT"


class LedgerError(Exception):
    """The ledger could not be read as a ledger. Never a comparison result."""


# ---------------------------------------------------------------------------
# Storage: a directory of <run_id>.json shards, or a legacy single .jsonl
# ---------------------------------------------------------------------------

#: Directory name under test/results/ holding one JSON object per run.
LEDGER_DIR_NAME = "ledger.d"

#: The pre-#8346 single-file ledger. Never written any more; still read, because
#: every merge parent from before the migration has one and the merge-
#: completeness guard must see across that boundary.
LEGACY_LEDGER_NAME = "ledger.jsonl"


def default_ledger_path() -> str:
    """The repo's ledger: the shard directory, or the legacy file if that is
    all this checkout has."""
    import pathlib

    results = pathlib.Path(__file__).resolve().parents[2] / "test" / "results"
    shards = results / LEDGER_DIR_NAME
    if shards.is_dir():
        return str(shards)
    legacy = results / LEGACY_LEDGER_NAME
    if legacy.exists():
        return str(legacy)
    return str(shards)


def shard_paths(directory: str) -> List[str]:
    """Every shard in a ledger directory, in a deterministic order.

    Sorted so two runs of the comparator over one directory read the rows in
    the same order. Order does not change a verdict -- :func:`compare` sorts by
    the ``ts`` FIELD -- but a non-deterministic read order would make a
    difference between two runs impossible to attribute.
    """
    import pathlib

    d = pathlib.Path(directory)
    if not d.is_dir():
        return []
    return [str(p) for p in sorted(d.glob("*.json"))]


def load_ledger_text(path: str) -> str:
    """Read a ledger -- a shard DIRECTORY or a legacy single file -- as JSONL.

    Returning text rather than rows is deliberate. Every check below
    (:func:`lint_ledger`, :func:`parse_ledger`, :func:`run_ids`) was written
    against JSONL text and is exercised by cells against JSONL text; making the
    storage change produce the SAME text keeps the storage change from touching
    the band arithmetic at all. ``ledger_compare_test.py`` pins that as an
    equivalence rather than asserting it here: the band over the sharded rows
    must equal the band over the same rows as one file.

    Each shard is emitted as ONE line, so a hand-edited pretty-printed shard is
    re-compacted rather than producing a stream of unparseable fragments. A
    shard that does not parse is passed through verbatim so the linter reports
    it by name instead of this function swallowing it.

    A missing path returns "" -- the caller decides whether "no ledger" is a
    read error or the empty-ledger FAIL, and those are different answers.
    """
    import pathlib

    p = pathlib.Path(path)
    if p.is_dir():
        out = []
        for shard in shard_paths(path):
            raw = pathlib.Path(shard).read_text(encoding="utf-8").strip()
            if not raw:
                continue
            try:
                out.append(json.dumps(json.loads(raw), separators=(",", ":"), ensure_ascii=False))
            except ValueError:
                # Not parseable: hand it to the linter as-is, flattened so it
                # stays one "line" and is reported once rather than N times.
                out.append(raw.replace("\n", " "))
        return "\n".join(out)
    if p.exists():
        return p.read_text(encoding="utf-8")
    return ""


def lint_shard_names(directory: str) -> List[str]:
    """Each shard's FILENAME must equal the ``run_id`` it contains.

    Under one-file-per-run the filename IS the identity: it is what makes two
    concurrent writers conflict-free, and it is what
    :func:`run_ids_at_rev` reads out of a git tree WITHOUT parsing the file. A
    shard whose name and payload disagree breaks both properties silently --
    the tree-level run-id set would name a run the file does not describe.

    Empty on a legacy single-file ledger: there are no filenames to check, and
    reporting a problem for a layout that has none would make the legacy path
    permanently red.
    """
    import pathlib

    problems: List[str] = []
    if not pathlib.Path(directory).is_dir():
        return problems
    for shard in shard_paths(directory):
        name = pathlib.Path(shard).stem
        try:
            row = json.loads(pathlib.Path(shard).read_text(encoding="utf-8"))
        except ValueError as exc:
            problems.append(f"{shard}: not parseable as JSON ({exc})")
            continue
        if not isinstance(row, dict):
            problems.append(f"{shard}: not a JSON object")
            continue
        if row.get("run_id") != name:
            problems.append(
                f"{shard}: filename says run_id {name!r} but the row says "
                f"{row.get('run_id')!r} — the filename IS the identity under "
                "one-file-per-run"
            )
    return problems


# ---------------------------------------------------------------------------
# Parsing and linting
# ---------------------------------------------------------------------------


def lint_row(row: object, lineno: int) -> List[str]:
    """Return the list of contract violations in one row (empty == clean).

    This is the SAME contract ``harness_result_emit`` enforces at write time.
    Checking it again at read time is not redundant: the ledger is a tracked
    file that a merge, a hand edit, or a committed conflict marker can damage
    after the emitter is done with it.
    """
    errs: List[str] = []
    if not isinstance(row, dict):
        return [f"line {lineno}: not a JSON object"]
    for k in REQUIRED_KEYS:
        if k not in row:
            errs.append(f"line {lineno}: missing required key {k!r}")
    if errs:
        return errs
    verdict = row["verdict"]
    if verdict not in VERDICTS:
        errs.append(f"line {lineno}: verdict {verdict!r} is not one of {VERDICTS}")
    if row["exe_check"] not in EXE_CHECKS:
        errs.append(f"line {lineno}: exe_check {row['exe_check']!r} is not one of {EXE_CHECKS}")
    reason = row.get("void_reason") or ""
    if verdict == "VOID" and not reason:
        errs.append(f"line {lineno}: VOID row with an empty void_reason")
    if verdict in ("PASS", "FAIL") and reason:
        errs.append(f"line {lineno}: {verdict} row carries a void_reason {reason!r}")
    if verdict in ("PASS", "FAIL") and row["exe_check"] in ("MISMATCH", "UNAVAILABLE"):
        errs.append(
            f"line {lineno}: {verdict} row with exe_check={row['exe_check']} — a "
            "measurement of a binary that cannot be named is a VOID (#2176)"
        )
    metrics = row.get("metrics")
    if not isinstance(metrics, dict):
        errs.append(f"line {lineno}: metrics is not an object")
        return errs
    for k, v in metrics.items():
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            errs.append(f"line {lineno}: metric {k!r} has non-numeric value {v!r}")
    if verdict in ("PASS", "FAIL"):
        if not metrics:
            errs.append(f"line {lineno}: {verdict} row with an empty metrics map")
        headline = row.get("headline_metric") or ""
        if headline not in metrics:
            errs.append(
                f"line {lineno}: headline_metric {headline!r} is absent from the row's "
                f"own metrics {sorted(metrics)}"
            )
        if row.get("headline_direction") not in ("higher-better", "lower-better", "neither"):
            errs.append(
                f"line {lineno}: headline_direction {row.get('headline_direction')!r} is "
                "not one of higher-better / lower-better / neither"
            )
    return errs


def _canonical(row: Dict) -> str:
    return json.dumps(row, sort_keys=True, separators=(",", ":"))


def lint_ledger(text: str) -> List[str]:
    """Lint a whole ledger. Returns the list of problems; empty == clean.

    An EMPTY ledger is a problem, not a clean sweep: linting zero rows and
    reporting success is the empty-set pass that ``run-selftests.sh`` already
    guards against in three other places.

    A repeated ``run_id`` whose payload is IDENTICAL is not a problem -- it is
    the benign `merge=union` artifact of both branches carrying the same row,
    and :func:`parse_ledger` dedupes it. A repeat whose payload DIFFERS is
    corruption: two different runs claiming one identity, which would put a
    foreign measurement into a band.

    WHAT THIS CANNOT SEE (#8346): a row that is simply MISSING. Every check
    here is over the rows that are present, so a dropped row leaves a
    well-formed, internally consistent, lint-clean file. Three real gate
    records were lost to a no-op ``merge.union.driver`` and this leg stayed
    green throughout. :func:`lint_merge_completeness` is the check that can
    see it, because it compares against the merge parents rather than against
    the file alone.
    """
    problems: List[str] = []
    seen = 0
    by_run_id: Dict[str, str] = {}
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        seen += 1
        try:
            row = json.loads(line)
        except ValueError as exc:
            problems.append(f"line {lineno}: not parseable as JSON ({exc})")
            continue
        row_errs = lint_row(row, lineno)
        problems.extend(row_errs)
        if row_errs or not isinstance(row, dict):
            continue
        run_id = row.get("run_id")
        canon = _canonical(row)
        if run_id in by_run_id and by_run_id[run_id] != canon:
            problems.append(
                f"line {lineno}: run_id {run_id!r} repeats with DIFFERENT content — "
                "two runs claiming one identity"
            )
        by_run_id.setdefault(run_id, canon)
    if seen == 0:
        problems.append("the ledger has zero rows — linting an empty ledger is not a pass")
    return problems


def run_ids(text: str) -> set:
    """The set of ``run_id`` values in a ledger, ignoring damaged lines.

    Deliberately tolerant where :func:`parse_ledger` refuses: this is used by
    :func:`lint_merge_completeness`, whose job is to answer "did a row go
    MISSING", and a parent that also has a damaged line should not mask that.
    """
    out = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict) and isinstance(row.get("run_id"), str):
            out.add(row["run_id"])
    return out


def lint_merge_completeness(merged: str, parents: Sequence[str]) -> List[str]:
    """A merge result must retain every ``run_id`` present in EITHER parent.

    #8346: this is the check :func:`lint_ledger` structurally cannot make, and
    the distinction is the whole point. ``lint_ledger`` keys on a repeated
    ``run_id`` whose payload DIFFERS -- corruption. A row that is simply GONE
    leaves a well-formed, internally consistent, perfectly lint-clean file. It
    is the "fails to a value indistinguishable from healthy" shape: nothing in
    the surviving rows says anything is missing.

    That is not hypothetical. `merge.union.driver = true` in this repo's
    ``.git/config`` shadowed git's BUILT-IN union driver with a no-op, so every
    ``merge=union`` file silently resolved to "ours" -- no conflict, no warning,
    not even a line in the merge summary, while ``git check-attr`` reported
    ``merge: union`` throughout. Three real gate records were lost that way
    before anyone noticed, and they were noticed by hand.

    A SET check, not a count. Counting rows would pass a merge that dropped one
    row and added another, which is exactly the coincidence a count cannot see.

    Mechanism-independent by design: it does not care WHY a row vanished, so it
    survives the config being fixed, the storage moving to one-file-per-run, or
    a future driver regressing again.
    """
    # #8346 note: the SET LOGIC moved to lint_merge_completeness_ids so a caller
    # that already has the ids -- read off shard FILENAMES in a git tree,
    # without parsing anything -- can use it directly. This text-taking
    # signature is kept as the public door rather than replaced, because
    # #8349's cells drive the guard through it; retiring it would leave the
    # logic tested only through the newer path and quietly decommission the
    # tests that were written against the real incident.
    return lint_merge_completeness_ids(run_ids(merged), [run_ids(p_) for p_ in parents])


def lint_merge_completeness_ids(merged: set, parents: Sequence[set]) -> List[str]:
    """The set check itself, over run-id SETS rather than ledger text.

    Same rule, same message, one layer down: a merge result must retain every
    ``run_id`` present in either parent. A SET check and not a count -- a count
    is satisfied by a merge that dropped one row and added another, which is
    exactly the coincidence a count cannot see.
    """
    problems: List[str] = []
    for idx, parent in enumerate(parents):
        missing = set(parent) - set(merged)
        if missing:
            problems.append(
                f"merge dropped {len(missing)} run_id(s) present in parent {idx}: "
                + ", ".join(sorted(missing))
                + " — the ledger is append-only and nothing prunes it, so a "
                "shrink is never legitimate"
            )
    return problems


def run_ids_at_rev(rev: str, *, run=None) -> set:
    """Every ``run_id`` recorded at a git revision, across BOTH layouts.

    This is the transition-safety of the #8349 guard, and it is the one place
    the storage change could have silently disarmed it.

    ``lint_merge_completeness`` compares the merge result's run-id set against
    each PARENT's. After #8346 a parent that predates the migration has no
    ``ledger.d/`` at all -- so a source that read only the new layout would
    return the EMPTY SET for it, ``missing`` would be empty, and the guard would
    pass vacuously. It would pass loudest on exactly the merge most likely to
    drop rows: the migration's own, whose other parent is legacy-only. A
    detector that reports "none dropped" because it looked in the wrong place
    is worse than no detector, which is the lesson #8348 already cost us.

    So both sources are read at every rev and unioned:

    * ``git show <rev>:test/results/ledger.jsonl`` -- ids parsed out of the
      legacy file, if it exists at that rev;
    * ``git ls-tree <rev> test/results/ledger.d/`` -- ids read straight off the
      FILENAMES, with no parsing at all, because under one-file-per-run the
      filename is the identity.

    The second source is strictly more robust than the first: a shard whose
    CONTENT was damaged still contributes its id, so a merge that damaged a row
    is reported by the linter rather than being invisible to the guard because
    the guard could not parse it. ``lint_shard_names`` is what keeps that
    trustworthy by pinning filename == payload id.

    Returns the empty set for a rev that has neither -- correct, and the reason
    the guard is only meaningful when at least one parent is non-empty.
    """
    import subprocess

    if run is None:
        run = lambda cmd: subprocess.run(cmd, capture_output=True, text=True)  # noqa: E731

    out = set()

    legacy = run(["git", "show", f"{rev}:test/results/{LEGACY_LEDGER_NAME}"])
    if legacy.returncode == 0:
        out |= run_ids(legacy.stdout)

    tree = run(
        ["git", "ls-tree", "--name-only", rev, f"test/results/{LEDGER_DIR_NAME}/"]
    )
    if tree.returncode == 0:
        for line in tree.stdout.splitlines():
            name = line.strip().rsplit("/", 1)[-1]
            if name.endswith(".json"):
                out.add(name[: -len(".json")])
    return out


def parse_ledger(text: str) -> List[Dict]:
    """Parse a ledger into rows, REFUSING on the first damaged line.

    Skipping a bad line would be the worse failure: the skipped row does not
    count toward K, so a corrupt ledger silently produces a thinner baseline
    that still reports WITHIN-BAND.

    A byte-identical repeat of a ``run_id`` IS dropped -- that is the benign
    `merge=union` artifact of both branches carrying one row, and a baseline is
    a count of runs, so counting it twice inflates one. A repeat whose payload
    differs is refused.
    """
    rows: List[Dict] = []
    by_run_id: Dict[str, str] = {}
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError as exc:
            raise LedgerError(f"line {lineno}: not parseable as JSON ({exc})") from exc
        errs = lint_row(row, lineno)
        if errs:
            raise LedgerError(errs[0])
        run_id = row["run_id"]
        canon = _canonical(row)
        if run_id in by_run_id:
            if by_run_id[run_id] != canon:
                raise LedgerError(
                    f"line {lineno}: run_id {run_id!r} repeats with DIFFERENT content — "
                    "two runs claiming one identity"
                )
            # A byte-identical repeat is the `merge=union` artifact of both
            # branches carrying the same row. Dropping it is the whole reason
            # rows carry an identity: counted twice it would inflate a
            # baseline, and a baseline is a count of RUNS.
            continue
        by_run_id[run_id] = canon
        rows.append(row)
    return rows


# ---------------------------------------------------------------------------
# The band
# ---------------------------------------------------------------------------


def band(values: Sequence[float]) -> Tuple[float, float, float]:
    """Return (median, lo, hi) for a baseline. Requires a non-empty sequence."""
    if not values:
        raise ValueError("band() over an empty baseline")
    med = statistics.median(values)
    mad = statistics.median([abs(v - med) for v in values])
    half = max(BAND_Z * 1.4826 * mad, BAND_REL_FLOOR * abs(med))
    return med, med - half, med + half


def classify(value: float, lo: float, hi: float, direction: str) -> str:
    """Place a value against a band, in the metric's own direction."""
    if lo <= value <= hi:
        return WITHIN_BAND
    if direction == "higher-better":
        return IMPROVED if value > hi else REGRESSION
    if direction == "lower-better":
        return IMPROVED if value < lo else REGRESSION
    # direction "neither": a move in either direction is reported, never
    # celebrated. Calling an unattributed move an improvement is a claim the
    # row does not support.
    return REGRESSION


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------


def _sorted_rows(rows: Iterable[Dict]) -> List[Dict]:
    """Chronological order, with a tie-break that does not depend on storage.

    The tie-break is ``run_id``, NOT the order the rows were loaded in, and the
    #8346 storage change is why. Under the old single appended file, load order
    WAS write order, so ties resolved chronologically by accident. Under one
    file per run the load order is the sorted filename order -- random hex --
    so a load-order tie-break makes "which row is newest" depend on which
    random id sorted first. Two runs finishing in the same second would then
    get a verdict that is not a function of the data, and a nondeterministic
    comparator makes every disagreement unattributable.

    ``run_id`` does not recover the true order within a second -- ``ts`` carries
    milliseconds since #8346 so that real runs do not tie at all -- but it makes
    the answer DETERMINISTIC, which is the property a comparator owes: identical
    input, identical verdict, whatever the storage.
    """
    return sorted(rows, key=lambda r: (r["ts"], r.get("run_id", "")))


def compare(
    rows: Sequence[Dict],
    gate: str,
    env: Optional[str] = None,
    k: int = MIN_BASELINE_RUNS,
) -> Dict:
    """Compare the newest row for ``gate`` (at ``env``) against its band."""
    matching = [r for r in rows if r.get("gate") == gate]
    if env is not None:
        matching = [r for r in matching if r.get("env") == env]
    matching = _sorted_rows(matching)

    if not matching:
        return {
            "outcome": NO_BASELINE,
            "gate": gate,
            "env": env,
            "k_required": k,
            "baseline_n": 0,
            "note": (
                f"no rows for gate {gate!r}"
                + (f" at env {env!r}" if env is not None else "")
                + " — nothing has been measured, which is not a pass"
            ),
        }

    newest = matching[-1]
    # An env was not given: judge the newest row against its OWN env only.
    # Mixing envs into one band is how a comparator reports a clean history for
    # a gate whose runs never actually compared to each other.
    resolved_env = newest.get("env")
    prior = [r for r in matching[:-1] if r.get("env") == resolved_env]

    result = {
        "outcome": None,
        "gate": gate,
        "env": resolved_env,
        "k_required": k,
        "ts": newest.get("ts"),
        "verdict": newest.get("verdict"),
        "build_git_sha": newest.get("build_git_sha"),
        "running_exe_sha256": newest.get("running_exe_sha256"),
        "exe_check": newest.get("exe_check"),
        "headline_metric": newest.get("headline_metric"),
        "baseline_n": 0,
    }

    if newest.get("verdict") == "VOID":
        result["outcome"] = VOID
        result["void_reason"] = newest.get("void_reason")
        result["note"] = "the newest row is VOID — nothing was measured, so there is nothing to compare"
        return result

    headline = newest.get("headline_metric")
    direction = newest.get("headline_direction")
    value = newest["metrics"][headline]
    result["value"] = value
    result["headline_direction"] = direction

    # The baseline: GREEN rows only (PASS -- never FAIL, never VOID), at the
    # same env, carrying the SAME headline metric. A row measuring something
    # else is not a prior measurement of this.
    greens = [
        r
        for r in prior
        if r.get("verdict") == "PASS" and headline in (r.get("metrics") or {})
    ]
    baseline = greens[-k:] if k > 0 else []
    result["baseline_n"] = len(baseline)
    result["baseline_ts"] = [r.get("ts") for r in baseline]

    # #9922 F-086: FAIL rows inside the baseline window. They never ENTER the
    # band (see above), but a comparator that judges only the newest row lets
    # a gate failing every other run read as a clean WITHIN-BAND. Surfaced
    # here so the aggregate and the render show them. The window starts at
    # the oldest baseline member; below the K floor there is no baseline, so
    # the window is the whole prior history at this env.
    window_start = baseline[0].get("ts") if baseline else None
    wfails = [
        r
        for r in prior
        if r.get("verdict") == "FAIL"
        and r.get("env") == resolved_env
        and headline in (r.get("metrics") or {})
        and (window_start is None or r.get("ts", "") >= window_start)
    ]
    result["window_fails"] = len(wfails)
    result["window_fail_ts"] = [r.get("ts") for r in wfails]

    if len(baseline) < k:
        result["outcome"] = NO_BASELINE
        result["note"] = (
            f"only {len(baseline)} green run(s) with metric {headline!r} at env "
            f"{resolved_env!r} precede this one; {k} are required before a "
            "regression may be claimed. NO-BASELINE is not a PASS."
        )
        return result

    values = [r["metrics"][headline] for r in baseline]
    med, lo, hi = band(values)
    result.update(
        {
            "baseline_values": values,
            "band_median": med,
            "band_lo": lo,
            "band_hi": hi,
            "outcome": classify(value, lo, hi, direction),
        }
    )

    # #9922 F-088: the PINNED baseline. The rolling band above re-trusts every
    # small step, so a slow geometric decay reads WITHIN-BAND at every step
    # while the total displacement grows unboundedly. The pin is the FIRST K
    # greens at this env (prior-only, so it is stable once K+1 greens exist),
    # judged with the same band arithmetic. `drift` is newest-inside-rolling
    # but outside-pinned: the step the rolling window just absorbed.
    #
    # Informational only: drift attribution needs a human (an intentional
    # change and a regression have the same shape here). The layer's job is to
    # surface the displacement, which today is invisible. A zero pinned median
    # (e.g. cells_failed pinned at 0) carries no ratio: displacement is None
    # and drift stays False rather than crashing — the rolling band still
    # judges the step (0 -> 1 on a zero-width band is a REGRESSION there).
    genesis = greens[:k]
    pvals = [r["metrics"][headline] for r in genesis]
    pmed, plo, phi = band(pvals)
    result.update(
        {
            "pinned_values": pvals,
            "pinned_median": pmed,
            "pinned_lo": plo,
            "pinned_hi": phi,
            "pinned_n": len(genesis),
            "pinned_ts": [r.get("ts") for r in genesis],
            "displacement": (value - pmed) / abs(pmed) if pmed != 0 else None,
            "drift": bool(
                pmed != 0
                and result["outcome"] == WITHIN_BAND
                and not (plo <= value <= phi)
            ),
        }
    )

    # Invariants: every other metric the newest row carries that also has a
    # baseline of its own.
    invariants: Dict[str, Dict] = {}
    for name, mvalue in sorted((newest.get("metrics") or {}).items()):
        if name == headline:
            continue
        ivals = [
            r["metrics"][name]
            for r in prior
            if r.get("verdict") == "PASS" and name in (r.get("metrics") or {})
        ][-k:]
        if len(ivals) < k:
            continue
        imed, ilo, ihi = band(ivals)
        invariants[name] = {
            "value": mvalue,
            "band_lo": ilo,
            "band_hi": ihi,
            "held": ilo <= mvalue <= ihi,
            "baseline_n": len(ivals),
        }
    result["invariants"] = invariants

    if result["outcome"] in (REGRESSION, IMPROVED):
        if not invariants:
            # "Every invariant held" and "there were no invariants to check"
            # are the same sentence only if you do not look.
            result["signal"] = "undetermined"
            result["signal_note"] = (
                "no invariant metric has a baseline of its own, so this move cannot "
                "be told from a flake without re-running"
            )
        elif all(i["held"] for i in invariants.values()):
            result["signal"] = "flake-candidate"
            result["signal_note"] = (
                "the headline moved and every invariant with a baseline held — "
                "re-run THIS gate before bisecting"
            )
        else:
            moved = [n for n, i in invariants.items() if not i["held"]]
            result["signal"] = "regression-candidate"
            result["signal_note"] = (
                "the headline moved and so did " + ", ".join(moved) + " — the move came "
                "with a behaviour change"
            )
    return result


def compare_all(
    rows: Sequence[Dict],
    k: int = MIN_BASELINE_RUNS,
) -> Dict:
    """Compare the newest row of EVERY (gate, env) pair against its band.

    #9922 F-086: ``compare()`` over one gate needs a human ``GATE=`` and no
    automation ever ran it over real rows, so a gate failing every run stayed
    green everywhere. This is the aggregate that runs it over all of them.

    A pair is RED when its outcome is REGRESSION or its newest verdict is
    FAIL. VOID / NO-BASELINE pairs are SURFACED, not failed: the aggregate
    is a red-watch, not a baseline-completeness gate (thin baselines are the
    normal state of young gates; completeness of a different kind — zero-row
    gates — is the coverage census's job, F-087).
    """
    pairs = sorted(
        set(
            (r.get("gate"), r.get("env"))
            for r in rows
            if r.get("gate") is not None
        )
    )
    results = {pair: compare(rows, pair[0], pair[1], k) for pair in pairs}
    red = {
        pair: res
        for pair, res in results.items()
        if res.get("outcome") == REGRESSION or res.get("verdict") == "FAIL"
    }
    undetermined = {
        pair: res
        for pair, res in results.items()
        if pair not in red and res.get("outcome") in (VOID, NO_BASELINE)
    }
    green = {
        pair: res for pair, res in results.items() if pair not in red and pair not in undetermined
    }
    return {
        "pairs": results,
        "red": red,
        "undetermined": undetermined,
        "green": green,
        "k_required": k,
    }


def parse_expected_red(text: str) -> Tuple[Dict[Tuple[str, str], str], List[str]]:
    """Parse an expected-red declaration file.

    One pair per line: ``gate env reason...`` — the reason is REQUIRED (it is
    what makes a tolerated red reviewable; cite the tracking issue). Blank
    lines and ``#`` comments are skipped. Returns (declared, problems);
    problems is non-empty when any line is malformed.
    """
    declared: Dict[Tuple[str, str], str] = {}
    problems: List[str] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 2)
        if len(parts) < 3:
            problems.append(
                f"line {lineno}: expected `gate env reason...`, got {stripped!r}"
            )
            continue
        declared[(parts[0], parts[1])] = parts[2]
    return declared, problems


def render_all(agg: Dict, declared: Optional[Dict[Tuple[str, str], str]] = None) -> str:
    """Render the aggregate: every pair's full verdict, then the summary.

    Each pair prints its complete single-gate render (band, pinned baseline,
    window FAILs, invariants) — a one-line-per-pair summary would leave the
    FAILs-inside-the-window and the drift flag automation-invisible again,
    which is the defect being fixed.
    """
    declared = declared or {}
    out: List[str] = []
    pairs = agg.get("pairs") or {}
    if not pairs:
        return "ledger-compare-all: no (gate, env) pairs in the ledger"
    for pair in sorted(pairs):
        res = pairs[pair]
        mark = (
            "RED"
            if pair in (agg.get("red") or {})
            else ("UNDETERMINED" if pair in (agg.get("undetermined") or {}) else "green")
        )
        annotation = ""
        if pair in declared:
            annotation = (
                "  [expected-red: still red]"
                if pair in (agg.get("red") or {})
                else "  [expected-red: STALE — no longer red, remove the declaration]"
            )
        out.append(f"=== {pair[0]} @ {pair[1]} [{mark}]{annotation}")
        out.append(render(res))
        out.append("")
    red = agg.get("red") or {}
    undet = agg.get("undetermined") or {}
    green = agg.get("green") or {}
    undeclared_red = sorted(p for p in red if p not in declared)
    stale = sorted(p for p in declared if p not in red)
    out.append(
        f"summary: {len(red)} red ({len(undeclared_red)} undeclared), "
        f"{len(undet)} undetermined, {len(green)} green, "
        f"{len(stale)} stale declaration(s)"
    )
    for pair in undeclared_red:
        out.append(f"  RED: {pair[0]} @ {pair[1]} — {red[pair].get('outcome')}/{red[pair].get('verdict')}")
    for pair in stale:
        out.append(f"  STALE: {pair[0]} @ {pair[1]} — declared red but no longer red ({declared[pair][:80]})")
    return "\n".join(out)


def all_exit_status(agg: Dict, declared: Optional[Dict[Tuple[str, str], str]] = None) -> int:
    """1 = an undeclared red pair or a stale declaration, else 0.

    Undetermined pairs never fail the aggregate (see compare_all): the
    aggregate watches for red. A stale declaration fails so the file can only
    shrink — a tolerated red that went green must be un-declared, loudly.
    """
    declared = declared or {}
    red = agg.get("red") or {}
    if any(p not in declared for p in red):
        return 1
    if any(p not in red for p in declared):
        return 1
    return 0


def _jsonable_agg(agg: Dict, declared: Dict[Tuple[str, str], str]) -> Dict:
    """The aggregate with string keys, for --json (JSON has no tuples)."""
    def keyed(d: Dict) -> Dict:
        return {f"{pair[0]} @ {pair[1]}": res for pair, res in d.items()}
    return {
        "pairs": keyed(agg.get("pairs") or {}),
        "red": sorted(f"{p[0]} @ {p[1]}" for p in (agg.get("red") or {})),
        "undetermined": sorted(f"{p[0]} @ {p[1]}" for p in (agg.get("undetermined") or {})),
        "green": sorted(f"{p[0]} @ {p[1]}" for p in (agg.get("green") or {})),
        "declared": {f"{p[0]} @ {p[1]}": reason for p, reason in declared.items()},
        "k_required": agg.get("k_required"),
    }


#: A ledger-wrapped Makefile recipe names its gate `--gate <name>`. Values
#: containing `$` are make expansions (the `harness-compare` recipe's `$(GATE)`)
#: rather than gates and are excluded by coverage().
WRAPPED_GATE_RE = re.compile(r"--gate (\S+)")

#: The positive control: this gate is wrapped AND has measured rows, so a
#: coverage matcher that never reports REACHED trips here by name instead of
#: reporting a clean board over an inverted world.
COVERAGE_POSITIVE_CONTROL = "test-failover"


def parse_coverage_declared(text: str) -> Tuple[Dict[str, str], List[str]]:
    """Parse a coverage-declaration file: `gate reason...` per line.

    Same shape as parse_expected_red but per GATE (coverage is per gate over
    any env; the envs a gate was measured in are reported, not gated).
    """
    declared: Dict[str, str] = {}
    problems: List[str] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        if len(parts) < 2:
            problems.append(
                f"line {lineno}: expected `gate reason...`, got {stripped!r}"
            )
            continue
        declared[parts[0]] = parts[1]
    return declared, problems


def coverage(
    makefile_text: str,
    rows: Sequence[Dict],
    declared_text: str,
) -> Dict:
    """Census: every ledger-wrapped gate measured, or declared unreached.

    #9922 F-087: emitter refusal (rc 2, NO row) is the design's falsifiability
    backstop, and its reader was never built — 12 of 18 wrapped gates have
    ZERO rows while every aggregate stays green. This is that reader: the
    wrapped set comes from the Makefile's `--gate` recipes, reached means
    >= 1 PASS or FAIL row, and anything else must be declared with a reason.

    VOID rows do NOT count as coverage: a gate whose rows are all VOID never
    measured anything, and counting them would let it read green in both this
    census and the red-watch aggregate (which surfaces undetermined pairs
    without failing). Such gates report as void-only, distinctly from zero-row.
    """
    wrapped = sorted(
        {
            m.group(1)
            for m in WRAPPED_GATE_RE.finditer(makefile_text)
            if "$" not in m.group(1)
        }
    )
    declared, problems = parse_coverage_declared(declared_text)
    problems = list(problems)
    by_gate: Dict[str, List[Dict]] = {}
    for r in rows:
        by_gate.setdefault(r.get("gate", ""), []).append(r)
    per_gate = {}
    for gate in wrapped:
        grows = by_gate.get(gate, [])
        measured = [r for r in grows if r.get("verdict") in ("PASS", "FAIL")]
        per_gate[gate] = {
            "rows": len(grows),
            "measured_rows": len(measured),
            "envs": sorted({str(r.get("env")) for r in grows}),
            "newest_ts": max((r.get("ts", "") for r in grows), default=None),
        }
    reached = sorted(g for g in wrapped if per_gate[g]["measured_rows"] > 0)
    void_only = sorted(
        g for g in wrapped if per_gate[g]["rows"] > 0 and per_gate[g]["measured_rows"] == 0
    )
    zero_row = sorted(g for g in wrapped if per_gate[g]["rows"] == 0)
    unreached = sorted(set(wrapped) - set(reached))
    missing = sorted(g for g in unreached if g not in declared)
    stale = sorted(g for g in declared if g not in unreached)
    if not wrapped:
        problems.append("no --gate recipes found in the Makefile text — the parse is wrong")
    control_ok = COVERAGE_POSITIVE_CONTROL in reached
    if COVERAGE_POSITIVE_CONTROL in wrapped and not control_ok:
        problems.append(
            f"positive control: {COVERAGE_POSITIVE_CONTROL} is wrapped but unreached"
        )
    if COVERAGE_POSITIVE_CONTROL not in wrapped:
        problems.append(
            f"positive control: {COVERAGE_POSITIVE_CONTROL} is not wrapped anymore"
        )
    return {
        "wrapped": wrapped,
        "reached": reached,
        "void_only": void_only,
        "zero_row": zero_row,
        "declared": declared,
        "missing": missing,
        "stale": stale,
        "problems": problems,
        "per_gate": per_gate,
        "ok": not missing and not stale and not problems,
    }


def render_coverage(cov: Dict) -> str:
    """Render the coverage census: every wrapped gate, then the verdict."""
    out = [f"ledger-coverage: {len(cov.get('reached', []))} of {len(cov.get('wrapped', []))} wrapped gates measured"]
    for gate in cov.get("wrapped", []):
        pg = (cov.get("per_gate") or {}).get(gate, {})
        if gate in (cov.get("reached") or []):
            state = f"REACHED ({pg.get('measured_rows')} measured / {pg.get('rows')} rows)"
        elif gate in (cov.get("void_only") or []):
            state = f"VOID-ONLY ({pg.get('rows')} rows, none measured)"
        else:
            state = "ZERO ROWS"
        extra = ""
        if gate in (cov.get("declared") or {}):
            extra = (
                "  [declared: still unreached]"
                if gate not in (cov.get("reached") or [])
                else "  [declared: STALE — measured now, remove the declaration]"
            )
        envs = ",".join(pg.get("envs") or []) or "-"
        out.append(f"  {gate:<32} {state:<34} envs={envs}{extra}")
    for gate in cov.get("missing", []):
        out.append(f"  MISSING: {gate} — unreached and undeclared (add rows or declare it)")
    for gate in cov.get("stale", []):
        out.append(f"  STALE: {gate} — declared but measured now (remove the declaration)")
    for prob in cov.get("problems", []):
        out.append(f"  PROBLEM: {prob}")
    out.append("coverage: OK" if cov.get("ok") else "coverage: FAIL")
    return "\n".join(out)


def render(result: Dict) -> str:
    out = [f"outcome: {result['outcome']}"]
    out.append(f"gate: {result['gate']}   env: {result['env']}")
    if result.get("ts"):
        out.append(f"newest run: {result['ts']}   verdict: {result.get('verdict')}")
        out.append(
            f"  build_git_sha={result.get('build_git_sha')}  "
            f"exe_check={result.get('exe_check')}  "
            f"running_exe_sha256={result.get('running_exe_sha256') or '-'}"
        )
    if result.get("void_reason"):
        out.append(f"  void reason: {result['void_reason']}")
    if "value" in result:
        out.append(
            f"headline {result['headline_metric']} = {result['value']} "
            f"({result.get('headline_direction')})"
        )
    if result.get("baseline_n") and "band_lo" in result:
        out.append(
            f"band over the last {result['baseline_n']} green run(s): "
            f"[{result['band_lo']:.6g}, {result['band_hi']:.6g}] "
            f"median {result['band_median']:.6g}"
        )
    elif result.get("baseline_n"):
        # Below the K floor there IS no band. Printing a "band over the last N
        # green run(s)" line with a placeholder invites reading a number that
        # was never computed; the note below says what happened instead.
        out.append(f"green runs available: {result['baseline_n']} (below the K floor)")
    if "pinned_median" in result:
        disp = result.get("displacement")
        disp_s = f"{disp:+.1%}" if disp is not None else "n/a (pinned median is 0)"
        flag = "  DRIFT — inside the rolling band, outside the pinned one" if result.get("drift") else ""
        out.append(
            f"pinned baseline over the first {result['pinned_n']} green run(s): "
            f"[{result['pinned_lo']:.6g}, {result['pinned_hi']:.6g}] "
            f"median {result['pinned_median']:.6g}  "
            f"cumulative displacement {disp_s}{flag}"
        )
    if result.get("window_fails"):
        out.append(
            f"FAIL rows inside the baseline window: {result['window_fails']} "
            f"({', '.join(result.get('window_fail_ts') or [])})"
        )
    if result.get("note"):
        out.append(f"note: {result['note']}")
    inv = result.get("invariants") or {}
    if inv:
        out.append("invariants:")
        for name, i in inv.items():
            mark = "held" if i["held"] else "MOVED"
            out.append(
                f"  {name:<24} {i['value']:<14} [{i['band_lo']:.6g}, {i['band_hi']:.6g}]  {mark}"
            )
    if result.get("signal"):
        out.append(f"signal: {result['signal']} — {result['signal_note']}")
    return "\n".join(out)


def exit_status(result: Dict) -> int:
    """0 = within band / improved and green, 1 = measured bad, 2 = undetermined.

    Mirrors mouse_latency_aggregate.py's mapping on purpose. A FAIL row exits 1
    even when its headline sits inside the band: the band says the metric did
    not move, and the row says the gate was violated, and the second one wins.
    The same win applies below the K floor (#9922 F-086): a FAIL newest with
    a thin baseline is still a measured FAIL, not an undetermined one.
    """
    outcome = result.get("outcome")
    if result.get("verdict") == "FAIL":
        return 1
    if outcome in (VOID, NO_BASELINE, LEDGER_CORRUPT):
        return 2
    if outcome == REGRESSION:
        return 1
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Compare the newest gate run against its band.")
    p.add_argument(
        "--ledger",
        default=None,
        help="path to the ledger: a ledger.d/ shard directory, or a legacy .jsonl file",
    )
    p.add_argument("--gate", help="gate name to compare")
    p.add_argument("--env", default=None, help="restrict to this env")
    p.add_argument("--k", type=int, default=MIN_BASELINE_RUNS, help="green runs required")
    p.add_argument("--json", action="store_true", help="emit JSON instead of text")
    p.add_argument(
        "--all",
        action="store_true",
        help=(
            "compare EVERY (gate, env) pair in the ledger (#9922 F-086); exit 1 "
            "on any REGRESSION or newest-FAIL. Undetermined pairs are surfaced, "
            "not failed. Mutually exclusive with --gate/--env."
        ),
    )
    p.add_argument(
        "--expected-red",
        default=None,
        metavar="FILE",
        help=(
            "declaration file of tolerated-red pairs for --all, one `gate env "
            "reason...` per line; undeclared red and stale declarations fail"
        ),
    )
    p.add_argument(
        "--coverage",
        action="store_true",
        help=(
            "census every Makefile --gate recipe against the ledger (#9922 "
            "F-087); exit 1 unless each wrapped gate is measured or declared"
        ),
    )
    p.add_argument(
        "--makefile",
        default="Makefile",
        help="Makefile to read --gate recipes from (default: Makefile)",
    )
    p.add_argument(
        "--coverage-declared",
        default="test/incus/LEDGER_COVERAGE.unreached",
        metavar="FILE",
        help="declaration file of unreached gates, one `gate reason...` per line",
    )
    p.add_argument("--lint", action="store_true", help="lint the ledger and exit")
    p.add_argument(
        "--lint-merge",
        action="store_true",
        help=(
            "verify the ledger retained every run_id from both parents across "
            "the last --lint-merge-count merges (#8346, window widened #9046); "
            "exit 3 when there is no merge to check"
        ),
    )
    p.add_argument(
        "--lint-merge-count",
        type=int,
        default=25,
        help=(
            "how many recent merges --lint-merge inspects (default 25). #9046: "
            "this was effectively 1 (HEAD only), so a shard-dropping merge was "
            "invisible one commit later."
        ),
    )
    args = p.parse_args(argv)

    import pathlib

    ledger = args.ledger if args.ledger is not None else default_ledger_path()

    if args.lint_merge:
        import subprocess

        # #9046: this was HEAD-only. A merge that drops a shard was catchable
        # ONLY by running the gate while HEAD was exactly that merge; one
        # commit later it is permanently invisible, because plain lint_ledger
        # cannot see a missing row -- a deleted shard leaves a lint-clean
        # directory (see lint_merge_completeness's docstring).
        #
        # So the window is the defect, and widening it is the fix: check the
        # last N merges rather than only the tip.
        revs = subprocess.run(
            ["git", "rev-list", "--merges", "-n", str(args.lint_merge_count), "HEAD"],
            capture_output=True,
            text=True,
        ).stdout.split()
        if not revs:
            # #9046: this used to `return 0`, and the caller mapped rc 0 to a
            # PASS line. The label said "nothing to check", which the author
            # intended as the disclosure -- but a PASS line still increments
            # the suite's `passed=` total, and the total is what anyone
            # actually reads. A disclosure that does not survive aggregation
            # is not a disclosure.
            #
            # Exit 3 is "we could not look", distinct from 0 "we looked and it
            # is clean" and 1 "we looked and it is not". The caller maps it to
            # SKIP, so the count stops claiming a check that did not happen.
            print(
                f"lint-merge: no merge commits in the last "
                f"{args.lint_merge_count} — nothing to check"
            )
            return 3
        checked = 0
        total_ids = 0
        for rev in revs:
            parents = subprocess.run(
                ["git", "rev-parse", f"{rev}^@"], capture_output=True, text=True
            ).stdout.split()
            if len(parents) < 2:
                continue
            # run_ids_at_rev, not a read of one path: it unions the legacy file
            # and the shard directory at every rev, so a parent from before
            # #8346 is not silently the empty set. See its docstring.
            merged = run_ids_at_rev(rev)
            probs = lint_merge_completeness_ids(
                merged, [run_ids_at_rev(p_) for p_ in parents]
            )
            if probs:
                print(f"lint-merge: at merge {rev[:12]}:")
                for pr in probs:
                    print(f"  {pr}")
                return 1
            checked += 1
            total_ids = max(total_ids, len(merged))
        if checked == 0:
            print(
                f"lint-merge: no merge commits in the last "
                f"{args.lint_merge_count} — nothing to check"
            )
            return 3
        print(
            f"lint-merge: OK — {checked} merge(s) checked, "
            f"{total_ids} run_id(s), none dropped"
        )
        return 0

    # A MISSING ledger and an EMPTY one are different answers and must not
    # collapse. Missing is a read error (exit 2, "we could not look"); empty is
    # the zero-row FAIL that lint_ledger reports (exit 1, "we looked and there
    # is nothing"). Collapsing them would make a fresh checkout with no ledger
    # indistinguishable from a directory whose shards were all deleted.
    if not pathlib.Path(ledger).exists():
        print(f"LEDGER-CORRUPT: cannot read {ledger}: no such path", file=sys.stderr)
        return 2
    try:
        text = load_ledger_text(ledger)
    except OSError as exc:
        print(f"LEDGER-CORRUPT: cannot read {ledger}: {exc}", file=sys.stderr)
        return 2

    if args.lint:
        problems = lint_ledger(text) + lint_shard_names(ledger)
        if problems:
            print(f"ledger-lint: {len(problems)} problem(s) in {ledger}", file=sys.stderr)
            for prob in problems:
                print(f"  {prob}", file=sys.stderr)
            return 1
        rows = len([ln for ln in text.splitlines() if ln.strip()])
        print(f"ledger-lint: OK — {rows} row(s) in {ledger}")
        return 0

    if args.all:
        if args.gate or args.env:
            p.error("--all is mutually exclusive with --gate/--env")
        declared: Dict[Tuple[str, str], str] = {}
        if args.expected_red:
            try:
                with open(args.expected_red, encoding="utf-8") as fh:
                    declared_text = fh.read()
            except OSError as exc:
                print(
                    f"LEDGER-CORRUPT: cannot read --expected-red "
                    f"{args.expected_red}: {exc}",
                    file=sys.stderr,
                )
                return 2
            declared, decl_problems = parse_expected_red(declared_text)
            if decl_problems:
                print(
                    f"ledger-compare-all: {len(decl_problems)} problem(s) in "
                    f"{args.expected_red}:",
                    file=sys.stderr,
                )
                for prob in decl_problems:
                    print(f"  {prob}", file=sys.stderr)
                return 1
        try:
            rows = parse_ledger(text)
        except LedgerError as exc:
            result = {"outcome": LEDGER_CORRUPT, "gate": None, "env": None, "note": str(exc)}
            print(json.dumps(result, indent=2) if args.json else render(result))
            return 2
        agg = compare_all(rows, args.k)
        if args.json:
            print(json.dumps(_jsonable_agg(agg, declared), indent=2))
        else:
            print(render_all(agg, declared))
        return all_exit_status(agg, declared)

    if args.coverage:
        if args.gate or args.env or args.all:
            p.error("--coverage is mutually exclusive with --gate/--env/--all")
        try:
            with open(args.makefile, encoding="utf-8") as fh:
                makefile_text = fh.read()
        except OSError as exc:
            print(f"LEDGER-CORRUPT: cannot read {args.makefile}: {exc}", file=sys.stderr)
            return 2
        try:
            with open(args.coverage_declared, encoding="utf-8") as fh:
                declared_text = fh.read()
        except OSError as exc:
            print(
                f"LEDGER-CORRUPT: cannot read --coverage-declared "
                f"{args.coverage_declared}: {exc}",
                file=sys.stderr,
            )
            return 2
        try:
            rows = parse_ledger(text)
        except LedgerError as exc:
            result = {"outcome": LEDGER_CORRUPT, "gate": None, "env": None, "note": str(exc)}
            print(json.dumps(result, indent=2) if args.json else render(result))
            return 2
        cov = coverage(makefile_text, rows, declared_text)
        if args.json:
            print(json.dumps(cov, indent=2))
        else:
            print(render_coverage(cov))
        return 0 if cov.get("ok") else 1

    if not args.gate:
        p.error("--gate is required unless --lint, --all or --coverage is given")

    try:
        rows = parse_ledger(text)
    except LedgerError as exc:
        result = {"outcome": LEDGER_CORRUPT, "gate": args.gate, "env": args.env, "note": str(exc)}
        print(json.dumps(result, indent=2) if args.json else render(result))
        return 2

    result = compare(rows, args.gate, args.env, args.k)
    print(json.dumps(result, indent=2) if args.json else render(result))
    return exit_status(result)


if __name__ == "__main__":
    sys.exit(main())
