#!/bin/sh
# scripts/selftest-census.sh — census over the hermetic self-tests (#9922 F-156).
#
# WHAT IT ASSERTS
#
#   1. Every self-test on disk is INVOKED by scripts/run-selftests.sh, across
#      all six locations that carry them (not just test/incus/):
#        test/incus/*-selftest.sh  test/xsk-repro/selftest*.sh
#        test/routing/selftest*.sh test/mutation/selftest*.sh
#        scripts/*selftest*.sh     scripts/docs/*selftest*.sh
#      Registration is a `run_bash <path>` / `run_shell <path>` call in the
#      runner with comments stripped (a bare filename mention would be
#      satisfied by a comment naming the script — the shape where a
#      source-scanning gate passes on its own documentation).
#   2. The §4 odd-name set is EXACTLY the four declared below. These are
#      registered self-tests outside every discovery glob; a fifth odd name
#      must extend the glob or the declaration, never slip past both.
#   3. Every §3 python self-test (scripts/image, scripts/dist,
#      scripts/deploy, scripts root, test_*.py) defines a `__main__` guard.
#      Each runs via direct `python3 <file>`; without the guard a file
#      defines its cells and exits 0 running nothing. (#9669 guards cells
#      AFTER the guard; this guards the guard's EXISTENCE. Complement, not
#      overlap.)
#
# WHY IT EXISTS
#
#   #7296's census globbed ONE location (test/incus/*-selftest.sh), so four
#   xsk-repro self-tests, one routing, one mutation, and every
#   scripts/*selftest* accumulated reachable-by-hand-only while the census
#   reported a clean board. The defect was never "one script was forgotten" —
#   it was that NOTHING NOTICED, in five more places than the fix covered.
#
# FALSIFIABILITY — what this reports when the property is FALSE
#
#   * A self-test on disk with no run_bash/run_shell registration fails the
#     census NAMING the file.
#   * An EMPTY discovery (overall, or any one glob matching nothing) fails
#     instead of reporting a clean sweep over nothing.
#   * A §4 registration outside the globs that is not in the odd set fails
#     (an undeclared odd name); an odd-set member no longer registered in §4
#     fails the other direction (a stale declaration).
#   * A §3 python file without `__main__` fails naming the file.
#   * The positive control names a file that must be discovered AND
#     registered; a matcher that finds nothing trips here by name.
#
# ODD NAMES (read: grandfathered, not invisible)
#
#   scripts/dist/selftest.sh and scripts/image/test-grow-root.sh predate the
#   *-selftest.sh convention and stay explicitly registered. So do
#   test/incus/wire-policy-deny.sh and test/incus/wire-appmatch-twins.sh,
#   which are verdict cores driven with a --selftest flag rather than
#   standalone self-test files. Renaming any of the four into a glob (or out
#   of §4) means updating the set below — loudly, in review.
#
# USAGE
#   sh scripts/selftest-census.sh
#   SELFTEST_CENSUS_ROOT=<fixture> SELFTEST_CENSUS_RUNNER=<file> sh scripts/selftest-census.sh
set -u

# shellcheck disable=SC1007
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck disable=SC1007
DEFAULT_ROOT=$(CDPATH= cd -- "$HERE/.." && pwd)
ROOT=${SELFTEST_CENSUS_ROOT:-$DEFAULT_ROOT}
RUNNER=${SELFTEST_CENSUS_RUNNER:-scripts/run-selftests.sh}

cd "$ROOT" || { echo "FATAL: cannot cd to $ROOT" >&2; exit 2; }
[ -f "$RUNNER" ] || { echo "FATAL: runner not found: $RUNNER" >&2; exit 2; }

FAIL=0
note_fail() { echo "  FAIL: $*" >&2; FAIL=$((FAIL + 1)); }
note_pass() { echo "  PASS: $*"; }

SELFTEST_GLOBS="test/incus/*-selftest.sh test/xsk-repro/selftest*.sh test/routing/selftest*.sh test/mutation/selftest*.sh scripts/*selftest*.sh scripts/docs/*selftest*.sh"
PY_GLOBS="scripts/image/test_*.py scripts/dist/test_*.py scripts/deploy/test_*.py scripts/test_*.py"
ODD_SET="scripts/dist/selftest.sh scripts/image/test-grow-root.sh test/incus/wire-policy-deny.sh test/incus/wire-appmatch-twins.sh"
POSITIVE_CONTROL="test/incus/harness-result-selftest.sh"

runner_code=$(sed 's/#.*//' "$RUNNER")

# ── 1. discovery: every self-test invoked ──
echo "selftest census: discovery over 6 globs"
discovered=""
set -f
for g in $SELFTEST_GLOBS; do
	set +f
	glob_n=0
	for f in $g; do
		[ -f "$f" ] || continue
		# The runner matches scripts/*selftest*.sh by NAME but is not a
		# leg; without this exclusion the census requires the runner to
		# invoke itself.
		if [ "$f" = "$RUNNER" ] || [ "$f" = "scripts/run-selftests.sh" ]; then
			continue
		fi
		glob_n=$((glob_n + 1))
		discovered="$discovered
$f"
		discovered_n=$((discovered_n + 1))
	done
	if [ "$glob_n" -eq 0 ]; then
		note_fail "glob matched nothing: $g (a location that lost its last self-test narrows the census silently)"
	fi
	set -f
done
set +f
if [ "$discovered_n" -eq 0 ]; then
	note_fail "discovery is EMPTY — the census swept nothing"
fi
case "$discovered" in
*"$POSITIVE_CONTROL"*) note_pass "positive control: $POSITIVE_CONTROL is discovered" ;;
*) note_fail "positive control: $POSITIVE_CONTROL is NOT discovered — the matcher is broken, not the tree" ;;
esac
missing=""
for f in $discovered; do
	case "$runner_code" in
	*"run_bash $f"* | *"run_shell $f"*) ;;
	*) missing="$missing $f" ;;
	esac
done
if [ -n "$missing" ]; then
	note_fail "on disk but not invoked by $RUNNER:$missing"
else
	note_pass "$discovered_n discovered self-tests, all invoked"
fi

# ── 2. the §4 odd-name exact set ──
sec4=$(sed -n '/── 4. shell self-tests ──/,/-- harness reachability census (#8302) --/p' "$RUNNER" | sed 's/#.*//')
if [ -z "$sec4" ]; then
	note_fail "§4 region not found in $RUNNER — the section markers moved"
else
	sec4_regs=$(printf '%s\n' "$sec4" | sed -n 's/^run_bash \([^ ]*\).*/\1/p; s/^run_shell \([^ ]*\).*/\1/p')
	odd_actual=""
	for reg in $sec4_regs; do
		case "$discovered" in
		*"$reg"*) ;;
		*) odd_actual="$odd_actual $reg" ;;
		esac
	done
	odd_extra=""
	for reg in $odd_actual; do
		case " $ODD_SET " in
		*" $reg "*) ;;
		*) odd_extra="$odd_extra $reg" ;;
		esac
	done
	odd_stale=""
	for want in $ODD_SET; do
		case " $odd_actual " in
		*" $want "*) ;;
		*) odd_stale="$odd_stale $want" ;;
		esac
	done
	if [ -n "$odd_extra" ]; then
		note_fail "§4 registrations outside every glob and outside the odd set (extend the glob or declare them):$odd_extra"
	fi
	if [ -n "$odd_stale" ]; then
		note_fail "odd-set members no longer registered in §4 (remove the declaration):$odd_stale"
	fi
	if [ -z "$odd_extra" ] && [ -z "$odd_stale" ]; then
		note_pass "§4 odd-name set is exactly the 4 declared"
	fi
fi

# ── 3. the __main__ guard over §3 python ──
echo "selftest census: __main__ guard over 4 python globs"
py_n=0
py_missing=""
set -f
for g in $PY_GLOBS; do
	set +f
	glob_n=0
	for f in $g; do
		[ -f "$f" ] || continue
		glob_n=$((glob_n + 1))
		py_n=$((py_n + 1))
		if ! grep -q '__main__' "$f"; then
			py_missing="$py_missing $f"
		fi
	done
	if [ "$glob_n" -eq 0 ]; then
		note_fail "python glob matched nothing: $g"
	fi
	set -f
done
set +f
if [ "$py_n" -eq 0 ]; then
	note_fail "python discovery is EMPTY — the guard swept nothing"
fi
if [ -n "$py_missing" ]; then
	note_fail "runs via direct python3 but defines no __main__ guard (exits 0 measuring nothing):$py_missing"
else
	note_pass "$py_n §3 python files, all guarded"
fi

# ── verdict ──
echo ""
if [ "$FAIL" -ne 0 ]; then
	echo "selftest census: FAIL ($FAIL problem(s))" >&2
	exit 1
fi
echo "selftest census: OK ($discovered_n self-tests invoked, $py_n python guarded)"
exit 0
