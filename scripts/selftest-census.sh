#!/bin/sh
# scripts/selftest-census.sh — census over the hermetic self-tests (#9922 F-156).
#
# WHAT IT ASSERTS
#
#   1. Every self-test on disk is INVOKED by scripts/run-selftests.sh, across
#      all nine locations that carry them (not just test/incus/):
#        test/incus/*-selftest.sh  test/xsk-repro/selftest*.sh
#        test/routing/selftest*.sh test/mutation/selftest*.sh
#        test/daemon/selftest*.sh  scripts/*selftest*.sh
#        scripts/docs/*selftest*.sh
#        test/image/*-test.sh      test/debian/*-test.sh
#      Registration is a `run_bash <path>` / `run_shell <path>` call in the
#      runner with comments stripped (a bare filename mention would be
#      satisfied by a comment naming the script — the shape where a
#      source-scanning gate passes on its own documentation).
#   2. The §4 odd-name set is EXACTLY the ten declared below. These are
#      registered self-tests outside every discovery glob; an eleventh odd
#      name must extend the glob or the declaration, never slip past both.
#   2b. (#14653) Every shell script on disk under test/ or scripts/ carrying
#      a `--selftest)` case arm is either registered in the runner (and, if
#      outside every glob, declared in the odd set) — the arm scan finds
#      verdict cores that no filename glob can see.
#   3. Every §3 python self-test (scripts/image, scripts/dist,
#      scripts/deploy, scripts root, test_*.py and *_test.py) defines a
#      `__main__` guard, and (§3b, #15241 A58-05) every tracked
#      `*test*.py` under scripts/ is covered by the union of PY_GLOBS --
#      the suffix-convention file
#      scripts/userspace_ha_validation_matrix_test.py was invisible to
#      both the runner and this census because it satisfies neither the
#      scripts/test_*.py prefix nor any listed directory glob.
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
#   * (#14653) A script carrying a `--selftest)` arm with no
#     `run_bash/run_shell <path> --selftest` registration in the runner
#     fails NAMING the file; an arm scan that finds nothing fails instead
#     of passing.
#   * A §3 python file without `__main__` fails naming the file.
#   * The positive control names a file that must be discovered AND
#     registered; a matcher that finds nothing trips here by name.
#
# ODD NAMES (read: grandfathered, not invisible)
#
#   scripts/dist/selftest.sh and scripts/image/test-grow-root.sh predate the
#   *-selftest.sh convention and stay explicitly registered. So do
#   test/incus/wire-policy-deny.sh, test/incus/wire-appmatch-twins.sh,
#   test/incus/wire-zone-matrix.sh, test/incus/wire-hostinbound-deny.sh,
#   test/incus/wire-conntrack-lifecycle.sh,
#   test/incus/wire-routing-separation.sh,
#   test/incus/wire-nat-frag-needed.sh (#14653, #12809) and
#   test/incus/t12-g2-9506.sh (#14653, #9506), which are verdict cores driven
#   with a --selftest flag rather than standalone self-test files. Renaming
#   any of the ten into a glob (or out of §4) means updating the set below —
#   loudly, in review. The §2b arm scan below is what now NOTICES a new
#   --selftest-arm script that nobody registered, instead of trusting this
#   list to be complete.
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

SELFTEST_GLOBS="test/incus/*-selftest.sh test/xsk-repro/selftest*.sh test/routing/selftest*.sh test/mutation/selftest*.sh test/daemon/selftest*.sh scripts/*selftest*.sh scripts/docs/*selftest*.sh test/image/*-test.sh test/debian/*-test.sh"
PY_GLOBS="scripts/image/test_*.py scripts/dist/test_*.py scripts/deploy/test_*.py scripts/test_*.py scripts/*_test.py"
ODD_SET="scripts/dist/selftest.sh scripts/image/test-grow-root.sh test/incus/wire-policy-deny.sh test/incus/wire-appmatch-twins.sh test/incus/wire-zone-matrix.sh test/incus/wire-hostinbound-deny.sh test/incus/wire-conntrack-lifecycle.sh test/incus/wire-routing-separation.sh test/incus/wire-nat-frag-needed.sh test/incus/t12-g2-9506.sh"
POSITIVE_CONTROL="test/incus/harness-result-selftest.sh"

runner_code=$(sed 's/#.*//' "$RUNNER")

# ── 1. discovery: every self-test invoked ──
echo "selftest census: discovery over 9 globs"
discovered=""
discovered_n=0
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
elif [ "$discovered_n" -gt 0 ]; then
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
		note_pass "§4 odd-name set is exactly the 10 declared"
	fi
fi

# ── 2b. the --selftest-arm scan (#14653): a verdict core that no filename
# glob can see ──
# Some gates are ordinary scripts (wire-nat-frag-needed.sh, t12-g2-9506.sh)
# whose hermetic core hides behind a `--selftest)` case arm. They match no
# SELFTEST_GLOBS entry, so §1 never discovers them and §2 sees them only if
# someone hand-adds them to ODD_SET — the #7296 "NOTHING NOTICED" shape one
# level down: before #14653 the census reported OK while two such cores were
# reached only by hand via `make test-*-lib`. Scan the disk for the arm
# itself so the NEXT such script fails here by name until it is registered
# in the runner.
# Registration for an arm script means a `run_bash <path> --selftest` /
# `run_shell <path> --selftest` line anywhere in the runner (comments
# stripped) — registration without the flag would run the LIVE gate, not
# the hermetic core, so it does not count. (Scripts recognising the flag
# via an `if [ "$1" = "--selftest" ]` test rather than a case arm, e.g.
# selftest-probe-filter_6898.sh, match a discovery glob by name and are
# covered by §1; they are not this scan's subject.)
# Keeping ODD_SET as the exemption DECLARATION is preserved through §2
# above: an arm script added to ODD_SET without a §4 registration fails
# §2 as stale, and a §4 registration without ODD_SET fails §2 as extra —
# so no arm script can be exempted by declaration alone without §2 red.
# grep over test/ and scripts/ (--include='*.sh') needs no extra fixture
# layout; an EMPTY scan fails rather than sweeping nothing. This census
# itself is excluded exactly as §1 excludes the runner: its own comments
# and matcher name the arm, so requiring it to register itself would be
# the source-scanning gate passing on its own documentation.
echo "selftest census: --selftest-arm scan over test/ and scripts/"
arm_files=$(grep -rl --include='*.sh' -- '--selftest)' test scripts 2>/dev/null | grep -v '^scripts/selftest-census\.sh$' | sort)
if [ -z "$arm_files" ]; then
	note_fail "--selftest-arm scan is EMPTY — the arm sweep found nothing (matcher broken, not the tree)"
else
	arm_n=0
	arm_missing=""
	for f in $arm_files; do
		arm_n=$((arm_n + 1))
		case "$runner_code" in
		*"run_bash $f --selftest"* | *"run_shell $f --selftest"*) ;;
		*) arm_missing="$arm_missing $f" ;;
		esac
	done
	if [ -n "$arm_missing" ]; then
		note_fail "scripts with a --selftest arm but no --selftest registration in $RUNNER (register them in §4 with --selftest and declare them in the odd set if outside every glob, or remove the arm):$arm_missing"
	elif [ "$arm_n" -gt 0 ]; then
		note_pass "$arm_n --selftest-arm scripts, all registered with --selftest"
	fi
fi

# ── 3. the __main__ guard over §3 python ──
echo "selftest census: __main__ guard over 5 python globs"
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
		if ! grep -qE "^[[:space:]]*if __name__ == ['\"]__main__['\"]:" "$f"; then
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
elif [ "$py_n" -gt 0 ]; then
	note_pass "$py_n §3 python files, all guarded"
fi

# ── 3b. (#15241 A58-05) tracked python tests under scripts/ are covered ──
# The glob list above is a convention, not a census: a new
# scripts/foo_test.py (suffix) or scripts/subdir/test_foo.py outside the
# listed directories satisfied no glob and ran in no gate, while this
# census reported OK. Compare the tracked set against the union of the
# globs actually expanded above, so adding a file in an uncovered shape
# fails here by name until a glob (or the runner) covers it.
echo "selftest census: tracked scripts/*test*.py covered by PY_GLOBS"
py_covered=""
set -f
for g in $PY_GLOBS; do
	set +f
	for f in $g; do
		[ -f "$f" ] || continue
		py_covered="$py_covered
$f"
	done
	set -f
done
set +f
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
	note_pass "tracked-python check skipped (fixture tree is not a git checkout)"
else
	py_tracked=$(git ls-files 'scripts/*test*.py' 2>/dev/null | sort)
	if [ -z "$py_tracked" ]; then
		note_fail "tracked python discovery is EMPTY — git ls-files found no scripts/*test*.py"
	else
		py_uncovered=""
		for f in $py_tracked; do
			case "$py_covered" in
			*"
$f"*) ;;
			*) py_uncovered="$py_uncovered $f" ;;
			esac
		done
		if [ -n "$py_uncovered" ]; then
			note_fail "tracked python test(s) under scripts/ covered by no PY_GLOBS entry (invisible to run-selftests.sh §3):$py_uncovered"
		else
			note_pass "all tracked scripts/*test*.py covered by PY_GLOBS"
		fi
	fi
fi

# ── verdict ──
echo ""
if [ "$FAIL" -ne 0 ]; then
	echo "selftest census: FAIL ($FAIL problem(s))" >&2
	exit 1
fi
echo "selftest census: OK ($discovered_n self-tests invoked, $py_n python guarded)"
exit 0
