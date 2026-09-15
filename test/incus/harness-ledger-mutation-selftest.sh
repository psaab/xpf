#!/usr/bin/env bash
# Mutation gate for the harness ledger layer: ledger_compare.py and
# harness-result.sh. Hermetic -- no cluster, no lock, no network, seconds.
#
# Usage: ./test/incus/harness-ledger-mutation-selftest.sh   (rc 0 = every
#        mutation was KILLED)
#
# ── Why this exists and why review cannot replace it ─────────────────
#
# A comparator with a broken band is INDISTINGUISHABLE from a healthy one on
# every green run. A loop is green almost all the time by construction, so the
# clean history a decayed comparator produces looks exactly like the clean
# history a working one produces. Reading the code does not separate them
# either: every one of the mutations below is a plausible-looking line.
#
# Only a mutation can see it. Each cell removes ONE piece of the guard and
# asserts that the cell suite goes RED. A mutation that survives is the report:
# it says the guard has no power, and a guard with no power is worse than none
# because its green is quoted as evidence.
#
# ── Why not scripts/mutate.sh ────────────────────────────────────────
#
# scripts/mutate.sh gates on `go` and `rust` only, and REFUSES a cell whose
# language no configured gate covers -- correctly, because a single-language
# runner scores every cross-language mutation as an ESCAPE, which is a claim
# that the code is untested. Python and shell are not among its gates, so these
# cells belong in their own runner rather than being fed to one that would
# refuse them.
#
# ── Falsifiability of THIS file ──────────────────────────────────────
#
# If a guard is missing:              the cell that should have caught it is
#                                     reported ESCAPED, by name, and this exits
#                                     1.
# If the mutation did not happen:     `old` not present exactly once is a VOID
#                                     cell, reported as such and counted as a
#                                     FAILURE -- never silently as a kill and
#                                     never as an escape. "The measurement did
#                                     not happen" is a third state.
# If the runner itself is broken:     the POSITIVE CONTROL runs the UNMUTATED
#                                     copies first and requires them GREEN. A
#                                     runner whose gate always reds would score
#                                     every mutation as killed and report a
#                                     perfect sweep of an inverted world; the
#                                     control trips instead.
# On an empty set:                    zero cells run is a FAILURE, not a clean
#                                     sweep.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v python3 >/dev/null 2>&1; then
	echo "SKIP: python3 not installed"
	exit 77
fi

WORK=$(mktemp -d "${TMPDIR:-/var/tmp}/xpf-harness-mutation.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

# deploy-lib.sh is staged alongside because harness-result.sh sources it from
# its OWN directory for the running-exe readback. Without it the staged copy
# silently degrades every cluster cell to UNAVAILABLE and the positive control
# reds -- which is the control doing its job, but the cause would be the
# staging, not the code.
cp "$SCRIPT_DIR/ledger_compare.py" "$SCRIPT_DIR/ledger_compare_test.py" \
	"$SCRIPT_DIR/harness-result.sh" "$SCRIPT_DIR/deploy-lib.sh" "$WORK/" || {
	echo "FATAL: cannot stage the files under mutation" >&2
	exit 1
}
cp "$WORK/ledger_compare.py" "$WORK/ledger_compare.py.orig"
cp "$WORK/harness-result.sh" "$WORK/harness-result.sh.orig"

# ── The mutation table ───────────────────────────────────────────────
#
# One python heredoc so the `old`/`new` fragments carry literal tabs, quotes
# and newlines without passing through shell quoting. `list` prints
# "<cell>\t<gate>" per cell; `apply` edits the staged copy and REFUSES unless
# `old` occurs exactly once.
mutate() {
	python3 - "$1" "${2:-}" "$WORK" <<'PY'
import shutil, sys

mode, cell, work = sys.argv[1], sys.argv[2], sys.argv[3]

PY_FILE, SH_FILE = "ledger_compare.py", "harness-result.sh"

# cell -> (file, gate, old, new, what it removes)
MUTATIONS = {
    # ---- the four the brief names ------------------------------------
    "band-over-void-rows": (
        PY_FILE, "py",
        'if r.get("verdict") == "PASS" and headline in (r.get("metrics") or {})',
        'if headline in (r.get("metrics") or {})',
        "the VOID/FAIL exclusion from the baseline: voids become data points",
    ),
    "no-baseline-collapsed-into-pass": (
        PY_FILE, "py",
        'NO_BASELINE = "NO-BASELINE"',
        'NO_BASELINE = "WITHIN-BAND"',
        '"we cannot judge this" reported as "this is fine"',
    ),
    "no-baseline-exits-zero": (
        PY_FILE, "py",
        "    if outcome in (VOID, NO_BASELINE, LEDGER_CORRUPT):\n        return 2",
        "    if outcome in (VOID, LEDGER_CORRUPT):\n        return 2",
        "the exit-status half of the same collapse: NO-BASELINE exits 0",
    ),
    "k-floor-below-three": (
        PY_FILE, "py",
        "MIN_BASELINE_RUNS = 3",
        "MIN_BASELINE_RUNS = 1",
        "the K>=3 floor: one green run becomes enough to claim a regression",
    ),
    "band-widened-by-floor": (
        PY_FILE, "py",
        "BAND_REL_FLOOR = 0.05",
        "BAND_REL_FLOOR = 1.0",
        "band width: a 48% throughput regression now fits inside the band",
    ),
    "band-widened-by-z": (
        PY_FILE, "py",
        "BAND_Z = 3.0",
        "BAND_Z = 500.0",
        "band width via the robust-sigma multiplier instead of the floor",
    ),
    # ---- the design's remaining cells --------------------------------
    "band-comparison-inverted": (
        PY_FILE, "py",
        "    if lo <= value <= hi:\n        return WITHIN_BAND",
        "    if not (lo <= value <= hi):\n        return WITHIN_BAND",
        "the direction of the band test itself",
    ),
    "pinned-baseline-uses-last-k": (
        PY_FILE, "py",
        "    genesis = greens[:k]",
        "    genesis = greens[-k:]",
        "the genesis pin: the pinned baseline becomes the rolling one and a "
        "slow decay is absorbed by both (#9922 F-088)",
    ),
    "fail-newest-exits-undetermined": (
        PY_FILE, "py",
        '    if result.get("verdict") == "FAIL":\n        return 1',
        "    if False:",
        "the FAIL-first exit: a FAIL newest on a thin baseline reads "
        "undetermined instead of measured-bad (#9922 F-086)",
    ),
    "aggregate-ignores-fail-verdict": (
        PY_FILE, "py",
        '        if res.get("outcome") == REGRESSION or res.get("verdict") == "FAIL"',
        '        if res.get("outcome") == REGRESSION',
        "the verdict half of the aggregate's red condition: newest-FAIL pairs "
        "drop out of the red set (#9922 F-086)",
    ),
    "aggregate-never-red": (
        PY_FILE, "py",
        '        if res.get("outcome") == REGRESSION or res.get("verdict") == "FAIL"',
        "        if False:",
        "the aggregate's red condition itself: every pair reads non-red "
        "(#9922 F-086)",
    ),
    "window-fails-dropped": (
        PY_FILE, "py",
        '    result["window_fails"] = len(wfails)',
        '    result["window_fails"] = 0',
        "the FAILs-inside-the-window count: a gate failing every other run "
        "reads as a clean WITHIN-BAND (#9922 F-086)",
    ),
    "expected-red-stale-check-dropped": (
        PY_FILE, "py",
        "    if any(p not in red for p in declared):\n        return 1",
        "    if False:",
        "the shrink-only half of expected-red: a tolerated red that went "
        "green stays declared forever (#9922 F-086)",
    ),
    "env-filter-dropped": (
        PY_FILE, "py",
        'prior = [r for r in matching[:-1] if r.get("env") == resolved_env]',
        "prior = list(matching[:-1])",
        "the same-env restriction: runs that never compared enter one band",
    ),
    "corrupt-line-skipped": (
        PY_FILE, "py",
        'raise LedgerError(f"line {lineno}: not parseable as JSON ({exc})") from exc',
        "continue",
        "the refusal on a damaged ledger line: a thinner baseline, silently",
    ),
    "empty-ledger-lints-clean": (
        PY_FILE, "py",
        "    if seen == 0:",
        "    if seen is None:",
        "the empty-set FAIL in ledger-lint",
    ),
    "empty-invariant-set-reads-as-flake": (
        PY_FILE, "py",
        "        if not invariants:",
        "        if invariants and False:",
        '"no invariant had a baseline" collapsed into "every invariant held"',
    ),
    # ---- the adapter table -------------------------------------------
    "ha-adapter-anchored-on-a-label-prefix": (
        SH_FILE, "sh",
        """\tline=$(grep -oE '[0-9]+ passed, [0-9]+ failed' "$log" | tail -1)""",
        """\tline=$(grep -oE 'Failover test: [0-9]+ passed, [0-9]+ failed' "$log" | tail -1 | sed 's/^Failover test: //')""",
        "numeric-tail matching: the adapter silently covers a subset of the gates",
    ),
    "ha-adapter-anchored-at-end-of-line": (
        SH_FILE, "sh",
        """\tline=$(grep -oE '[0-9]+ passed, [0-9]+ failed' "$log" | tail -1)""",
        """\tline=$(grep -oE '[0-9]+ passed, [0-9]+ failed$' "$log" | tail -1)""",
        "tolerance of a trailing field: test-connectivity.sh's summary stops matching",
    ),
    "missing-summary-scored-as-a-pass": (
        SH_FILE, "sh",
        '\t\tprintf \'VOID\\tno "<n> passed, <n> failed" summary line',
        '\t\tprintf \'PASS\\tno "<n> passed, <n> failed" summary line',
        "the VOID for a smoke that died before its summary",
    ),
    "void-without-a-reason-accepted": (
        SH_FILE, "sh",
        '\tif [[ "$verdict" == "VOID" && -z "$void_reason" ]]; then',
        "\tif false; then",
        'the "a VOID must say why" refusal',
    ),
    "unnameable-binary-accepted": (
        SH_FILE, "sh",
        '\tif [[ "$verdict" != "VOID" && ( "$exe_check" == "MISMATCH" || "$exe_check" == "UNAVAILABLE" ) ]]; then\n\t\t_hr_warn "REFUSED: exe_check=$exe_check',
        '\tif false; then\n\t\t_hr_warn "REFUSED: exe_check=$exe_check',
        "the #2176 refusal: a PASS measured on a binary nobody can name",
    ),
    "row-void-degrades-the-gate-exit-status": (
        SH_FILE, "sh",
        '\tcase "$gate_verdict" in\n\tVOID) return 2 ;;',
        '\tcase "$verdict" in\n\tVOID) return 2 ;;',
        "the separation of the ROW's verdict from the GATE's exit status: an "
        "unattributable row now reds `make test-failover`",
    ),
    "comparator-reads-a-single-path": (
        PY_FILE, "py",
        "    p = pathlib.Path(path)\n    if p.is_dir():",
        "    p = pathlib.Path(path)\n    if False:",
        "the shard-directory read: the comparator falls back to single-file "
        "behaviour and the glob is decorative (#8346 acceptance)",
    ),
    "merge-guard-blind-to-a-legacy-parent": (
        PY_FILE, "py",
        '    legacy = run(["git", "show", f"{rev}:test/results/{LEGACY_LEDGER_NAME}"])',
        '    legacy = run(["git", "show", f"{rev}:test/results/NOTHING"])',
        "the legacy source in run_ids_at_rev: a parent from before the migration "
        "reads as the EMPTY SET and the completeness guard passes vacuously",
    ),
    "ordering-tie-break-is-storage-dependent": (
        PY_FILE, "py",
        '    return sorted(rows, key=lambda r: (r["ts"], r.get("run_id", "")))',
        '    return sorted(rows, key=lambda r: r["ts"])',
        "the storage-independent tie-break: which row is 'newest' becomes a "
        "function of the filenames rather than of the data",
    ),
    "shard-filename-identity-unchecked": (
        PY_FILE, "py",
        '        if row.get("run_id") != name:',
        "        if False:",
        "the filename==run_id check, which is what makes reading the run-id set "
        "off a git tree trustworthy",
    ),
    "dirty-flag-permanently-on": (
        SH_FILE, "sh",
        '\tdirt=$(git -C "$root" status --porcelain -uall 2>/dev/null |',
        '\tdirt=$(git -C "$root" status --porcelain 2>/dev/null |',
        "the -uall that makes the ledger exclusion match: git collapses an "
        "untracked dir, so every row is marked -dirty forever",
    ),
    "identical-repeat-counted-twice": (
        PY_FILE, "py",
        "            # A byte-identical repeat is the `merge=union` artifact",
        "            rows.append(row)\n            # A byte-identical repeat is the `merge=union` artifact",
        "the run_id dedup: a row both branches carried inflates a baseline",
    ),
    "conflicting-run-id-accepted": (
        PY_FILE, "py",
        "            if by_run_id[run_id] != canon:",
        "            if False:",
        "the refusal of two different runs claiming one run_id",
    ),
    "non-numeric-metric-accepted": (
        PY_FILE, "py",
        "        if isinstance(v, bool) or not isinstance(v, (int, float)):",
        "        if False:",
        "the numeric-metric contract in ledger-lint",
    ),
}

if mode == "list":
    for name, (_f, gate, _o, _n, _w) in MUTATIONS.items():
        print(f"{name}\t{gate}")
    raise SystemExit(0)

if mode == "describe":
    print(MUTATIONS[cell][4])
    raise SystemExit(0)

fname, gate, old, new, _what = MUTATIONS[cell]
src = f"{work}/{fname}"
shutil.copyfile(f"{src}.orig", src)
text = open(src, encoding="utf-8").read()
n = text.count(old)
if n != 1:
    # NOT an escape and NOT a kill. The mutation did not happen, so the cell
    # measured nothing; collapsing that into either result is how a mutation
    # sweep reports power it does not have.
    print(f"VOID: `old` occurs {n} times in {fname} (expected exactly 1)", file=sys.stderr)
    raise SystemExit(3)
mutated = text.replace(old, new)
if mutated == text:
    print(f"VOID: the replacement changed nothing in {fname}", file=sys.stderr)
    raise SystemExit(3)
open(src, "w", encoding="utf-8").write(mutated)

# LANDING CHECK: re-READ the file from disk and confirm the edit is actually
# there. An escaped mutation and a killed one are equally meaningless if the
# edit never reached the tree, and the two failure directions look nothing
# alike from the outside: a write that silently did not land reads as an
# ESCAPE ("this guard has no power"), which argues for deleting a guard that
# works. Checking the in-memory string is not the same as checking the file --
# a failed/partial write, a read-only path, or a stale copy are exactly what
# this is for.
landed = open(src, encoding="utf-8").read()
if new not in landed:
    print(f"VOID: the mutation did not land in {src} (new text absent after write)", file=sys.stderr)
    raise SystemExit(3)
# Only meaningful for a REPLACEMENT. An INSERTION mutation deliberately keeps
# the original text -- `new` contains `old` -- and asserting its absence there
# would VOID a perfectly landed edit. (It did, on first run: the run_id-dedup
# cell inserts a line above the text it anchors on.) Refine the check rather
# than reshape the mutation to satisfy it; a guard that forces a workaround is
# mis-specified.
if old not in new and old in landed:
    print(f"VOID: the original text is STILL in {src} after the write", file=sys.stderr)
    raise SystemExit(3)
raise SystemExit(0)
PY
}

restore() {
	cp "$WORK/ledger_compare.py.orig" "$WORK/ledger_compare.py"
	cp "$WORK/harness-result.sh.orig" "$WORK/harness-result.sh"
}

# gate_py: run the comparator cells against the STAGED copy. cwd is the staging
# dir so `import ledger_compare` resolves to the mutant, never the original.
gate_py() {
	(cd "$WORK" && python3 -m unittest discover -s "$WORK" -p ledger_compare_test.py) >"$WORK/gate.out" 2>&1
}

# gate_sh: run the real selftest IN PLACE (its adapter census reads the actual
# test-*.sh gates next to it) but pointed at the staged harness-result.sh.
gate_sh() {
	HARNESS_RESULT_LIB="$WORK/harness-result.sh" bash "$SCRIPT_DIR/harness-result-selftest.sh" \
		>"$WORK/gate.out" 2>&1
}

run_gate() {
	case "$1" in
	py) gate_py ;;
	sh) gate_sh ;;
	*) return 99 ;;
	esac
}

# ── Positive control: the UNMUTATED copies must be GREEN ─────────────
#
# A runner whose gate always reds scores every mutation as KILLED and reports a
# perfect sweep of an inverted world. This is the only cell that can tell the
# two apart, and it runs first.
# ── Staging check: the gates must read the STAGED copies ─────────────
#
# Both gates are pointed at $WORK -- the py gate by cwd + `discover -s`, the sh
# gate by HARNESS_RESULT_LIB. If either override were ignored the gate would
# run against the pristine tree, every mutation would score as an ESCAPE, and
# the report would read "these guards have no power" when nothing had been
# mutated at all. Prove the plumbing before trusting any verdict: mutate a
# staged copy so that it CANNOT pass, and require each gate to notice.
staging_fail=""
restore
printf '\nraise SystemExit("staged-copy canary")\n' >>"$WORK/ledger_compare.py"
gate_py && staging_fail="$staging_fail py"
restore
printf '\nharness_adapt() { return 99; }\n' >>"$WORK/harness-result.sh"
gate_sh && staging_fail="$staging_fail sh"
restore
if [ -n "$staging_fail" ]; then
	echo "FAIL: staging check — these gates did NOT read the staged copy:$staging_fail" >&2
	echo "  Every mutation below would have scored as an ESCAPE against an unmutated tree." >&2
	exit 1
fi
echo "PASS: staging check — both gates read the staged copies, not the tree"

restore
control_fail=0
for g in py sh; do
	if run_gate "$g"; then
		echo "PASS: positive control — the unmutated $g gate is GREEN"
	else
		echo "FAIL: positive control — the unmutated $g gate is RED; every verdict below would be meaningless" >&2
		sed 's/^/    /' "$WORK/gate.out" | tail -30 >&2
		control_fail=1
	fi
done
if ((control_fail)); then
	echo >&2
	echo "MUTATION RUN VOID: the control failed, so nothing below was measured." >&2
	exit 1
fi

# ── The cells ────────────────────────────────────────────────────────
KILLED=0
ESCAPED=""
VOIDED=""
CELLS=0

while IFS=$'\t' read -r cell gate; do
	[[ -n "$cell" ]] || continue
	CELLS=$((CELLS + 1))
	restore
	if ! mutate apply "$cell" 2>"$WORK/mut.err"; then
		VOIDED="$VOIDED $cell"
		echo "VOID: $cell — $(cat "$WORK/mut.err")" >&2
		continue
	fi
	what=$(mutate describe "$cell")
	if run_gate "$gate"; then
		ESCAPED="$ESCAPED $cell"
		echo "ESCAPED: $cell (removes: $what) — the gate stayed GREEN with the guard removed" >&2
	else
		KILLED=$((KILLED + 1))
		echo "KILLED:  $cell (removes: $what)"
	fi
done < <(mutate list)

restore

echo
echo "  harness-ledger mutation: $KILLED killed, $(wc -w <<<"$ESCAPED") escaped, $(wc -w <<<"$VOIDED") void, of $CELLS cells"

# An empty sweep is not a clean sweep.
if ((CELLS == 0)); then
	echo "FAIL: the mutation table is EMPTY — zero cells ran" >&2
	exit 1
fi
if [[ -n "$VOIDED" ]]; then
	echo "FAIL: cells whose mutation did not apply (the code moved under them):$VOIDED" >&2
	exit 1
fi
if [[ -n "$ESCAPED" ]]; then
	echo "FAIL: ESCAPED mutations — these guards have no power:$ESCAPED" >&2
	exit 1
fi
echo "  OK — every mutation was killed by a named cell"
exit 0
