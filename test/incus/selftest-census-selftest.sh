#!/usr/bin/env bash
# Self-test for scripts/selftest-census.sh (#9922 F-156). Hermetic — fixture
# trees under a mktemp -d, no network, no cluster.
#
# Falsifiability of this file: every failure cell pairs a fixture that must
# FAIL the census with the clean twin that must PASS it (stamp_clean), so a
# census that reddened on everything — or on nothing — fails here rather
# than satisfying every cell. The run_* missing-file cells drive the REAL
# functions eval-extracted from scripts/run-selftests.sh at test time, with
# a trivial-script control proving the extraction executes real code.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1007
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
CENSUS="$ROOT/scripts/selftest-census.sh"

PASS=0
FAIL=0
ok() { echo "PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

WORK=$(mktemp -d "${TMPDIR:-/var/tmp}/xpf-selftest-census-selftest.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
n=0

# stamp_clean <dir> — a fixture tree satisfying every census check: one file
# per discovery glob, the positive control, one guarded file per python
# glob, and a runner registering all of them plus exactly the 8 odd names.
stamp_clean() {
	local fix="$1"
	mkdir -p "$fix/test/incus" "$fix/test/xsk-repro" "$fix/test/routing" \
		"$fix/test/mutation" "$fix/scripts/docs" "$fix/scripts/image" \
		"$fix/scripts/dist" "$fix/scripts/deploy"
	echo '#!/bin/sh' >"$fix/test/incus/a-selftest.sh"
	echo '#!/bin/sh' >"$fix/test/xsk-repro/selftest-a.sh"
	echo '#!/bin/sh' >"$fix/test/routing/selftest-a.sh"
	echo '#!/bin/sh' >"$fix/test/mutation/selftest-a.sh"
	echo '#!/bin/sh' >"$fix/scripts/selftest-a.sh"
	echo '#!/bin/sh' >"$fix/scripts/docs/selftest-a.sh"
	echo '#!/bin/sh' >"$fix/test/incus/harness-result-selftest.sh"
	for d in image dist deploy; do
		printf 'x = 1\nif __name__ == "__main__":\n    pass\n' >"$fix/scripts/$d/test_a.py"
	done
	printf 'x = 1\nif __name__ == "__main__":\n    pass\n' >"$fix/scripts/test_a.py"
	cat >"$fix/runner.sh" <<'RUNNER'
# ── 4. shell self-tests ──
run_bash test/incus/a-selftest.sh
run_bash test/incus/harness-result-selftest.sh
run_shell test/xsk-repro/selftest-a.sh
run_shell test/routing/selftest-a.sh
run_shell test/mutation/selftest-a.sh
run_bash scripts/selftest-a.sh
run_bash scripts/docs/selftest-a.sh
run_shell scripts/dist/selftest.sh
run_shell scripts/image/test-grow-root.sh
run_bash test/incus/wire-policy-deny.sh --selftest
run_bash test/incus/wire-appmatch-twins.sh --selftest
run_bash test/incus/wire-zone-matrix.sh --selftest
run_bash test/incus/wire-hostinbound-deny.sh --selftest
run_bash test/incus/wire-conntrack-lifecycle.sh --selftest
run_bash test/incus/wire-routing-separation.sh --selftest
# -- harness reachability census (#8302) --
RUNNER
}

run_census() {
	SELFTEST_CENSUS_ROOT="$1" SELFTEST_CENSUS_RUNNER=runner.sh sh "$CENSUS" 2>&1
}

# ── 1. clean fixture passes ──
n=$((n + 1)); fix="$WORK/f$n"; mkdir -p "$fix"; stamp_clean "$fix"
if out=$(run_census "$fix"); then
	ok "clean fixture passes"
else
	bad "clean fixture failed: $out"
fi

# ── 2. discovered but unregistered fails, naming the file ──
n=$((n + 1)); fix="$WORK/f$n"; mkdir -p "$fix"; stamp_clean "$fix"
sed -i '/test\/xsk-repro\/selftest-a.sh/d' "$fix/runner.sh"
if out=$(run_census "$fix"); then
	bad "unregistered self-test passed the census"
else
	case "$out" in
	*"test/xsk-repro/selftest-a.sh"*) ok "unregistered self-test fails, naming the file" ;;
	*) bad "unregistered failure did not name the file: $out" ;;
	esac
fi

# ── 3. an emptied glob fails, naming the glob ──
n=$((n + 1)); fix="$WORK/f$n"; mkdir -p "$fix"; stamp_clean "$fix"
rm "$fix/test/routing/selftest-a.sh"
if out=$(run_census "$fix"); then
	bad "emptied glob passed the census"
else
	case "$out" in
	*"test/routing/selftest*.sh"*) ok "emptied glob fails, naming the glob" ;;
	*) bad "emptied-glob failure did not name the glob: $out" ;;
	esac
fi

# ── 4. a §3 file without __main__ fails, naming the file ──
n=$((n + 1)); fix="$WORK/f$n"; mkdir -p "$fix"; stamp_clean "$fix"
printf 'x = 1\n' >"$fix/scripts/image/test_a.py"
if out=$(run_census "$fix"); then
	bad "unguarded python file passed the census"
else
	case "$out" in
	*"scripts/image/test_a.py"*) ok "unguarded python file fails, naming the file" ;;
	*) bad "unguarded failure did not name the file: $out" ;;
	esac
fi

# ── 4b. `__main__` in a comment is not a guard ──
n=$((n + 1)); fix="$WORK/f$n"; mkdir -p "$fix"; stamp_clean "$fix"
printf '# classes must be defined before `if __name__ == "__main__":`\nx = 1\n' >"$fix/scripts/image/test_a.py"
if out=$(run_census "$fix"); then
	bad "comment-only __main__ mention passed the census"
else
	case "$out" in
	*"scripts/image/test_a.py"*) ok "comment-only __main__ fails, naming the file" ;;
	*) bad "comment-only failure did not name the file: $out" ;;
	esac
fi

# ── 4c. `__main__` in a string literal is not a guard ──
n=$((n + 1)); fix="$WORK/f$n"; mkdir -p "$fix"; stamp_clean "$fix"
printf 'GUARD = %s\nx = 1\n' "'if __name__ == \"__main__\":'" >"$fix/scripts/image/test_a.py"
if out=$(run_census "$fix"); then
	bad "string-only __main__ mention passed the census"
else
	case "$out" in
	*"scripts/image/test_a.py"*) ok "string-only __main__ fails, naming the file" ;;
	*) bad "string-only failure did not name the file: $out" ;;
	esac
fi

# ── 4d. the concrete victim: guard-deleted real file still mentions __main__ ──
n=$((n + 1)); fix="$WORK/f$n"; mkdir -p "$fix"; stamp_clean "$fix"
grep -vE "^[[:space:]]*if __name__ ==" "$ROOT/scripts/test_selftest_main_guard_9669.py" >"$fix/scripts/image/test_a.py"
if grep -q '__main__' "$fix/scripts/image/test_a.py"; then
	if out=$(run_census "$fix"); then
		bad "guard-deleted victim (mentions intact) passed the census"
	else
		case "$out" in
		*"scripts/image/test_a.py"*) ok "guard-deleted victim fails despite __main__ mentions" ;;
		*) bad "victim failure did not name the file: $out" ;;
		esac
	fi
else
	bad "victim fixture lost its __main__ mentions — the negative control is void"
fi

# ── 4e. all-globs-empty fails rc 1 with named EMPTY, not a set -u crash ──
n=$((n + 1)); fix="$WORK/f$n"; mkdir -p "$fix"
printf '# ── 4. shell self-tests ──\nrun_shell scripts/dist/selftest.sh\nrun_shell scripts/image/test-grow-root.sh\nrun_bash test/incus/wire-policy-deny.sh --selftest\nrun_bash test/incus/wire-appmatch-twins.sh --selftest\n# -- harness reachability census (#8302) --\n' >"$fix/runner.sh"
if out=$(run_census "$fix"); then
	bad "all-empty discovery passed the census"
else
	case "$out" in
	*"discovery is EMPTY"* | *"parameter not set"*)
		case "$out" in
		*"parameter not set"*) bad "all-empty discovery crashed (set -u): $out" ;;
		*) ok "all-empty discovery fails rc 1 with named EMPTY" ;;
		esac
		;;
	*) bad "all-empty failure did not name EMPTY: $out" ;;
	esac
fi

# ── 5. a ninth odd name fails (exact-set, extra direction) ──
n=$((n + 1)); fix="$WORK/f$n"; mkdir -p "$fix"; stamp_clean "$fix"
printf 'run_bash scripts/odd-new-thing.sh\n' >>"$fix/runner.sh"
# The append lands after the §4 end marker; move it inside (a registration
# outside §4 is a census leg, not an odd self-test — see cell 7's twin).
sed -i '/odd-new-thing/d' "$fix/runner.sh"
sed -i 's|# -- harness reachability census|run_bash scripts/odd-new-thing.sh\n# -- harness reachability census|' "$fix/runner.sh"
if out=$(run_census "$fix"); then
	bad "undeclared ninth odd name passed the census"
else
	case "$out" in
	*"scripts/odd-new-thing.sh"*) ok "undeclared odd name fails, naming the file" ;;
	*) bad "odd-extra failure did not name the file: $out" ;;
	esac
fi

# ── 6. a dropped odd registration fails (exact-set, stale direction) ──
n=$((n + 1)); fix="$WORK/f$n"; mkdir -p "$fix"; stamp_clean "$fix"
sed -i '/scripts\/dist\/selftest.sh/d' "$fix/runner.sh"
if out=$(run_census "$fix"); then
	bad "stale odd declaration passed the census"
else
	case "$out" in
	*"scripts/dist/selftest.sh"*) ok "stale odd declaration fails, naming the file" ;;
	*) bad "odd-stale failure did not name the file: $out" ;;
esac
fi

# ── 7. a census leg outside §4 is not an odd name (the cell-5 twin) ──
n=$((n + 1)); fix="$WORK/f$n"; mkdir -p "$fix"; stamp_clean "$fix"
printf '# -- harness reachability census (#8302) --\nrun_shell scripts/some-census.sh\n' >>"$fix/runner.sh"
# Runner now has two end markers; the §4 extract spans to the FIRST, so the
# census leg below it is outside the odd-set computation by construction.
if out=$(run_census "$fix"); then
	ok "census leg outside §4 is not treated as an odd name"
else
	bad "census leg outside §4 failed the census: $out"
fi

# ── 8-10. run_bash/run_shell/run_py on a missing file FAILs ──
# The REAL functions, extracted from the runner at test time: if the
# extraction breaks (a rename, a moved brace) the eval defines nothing and
# the control cell below errors instead of passing.
T_PASS=0
T_FAIL=0
T_SKIP=0
passl() { T_PASS=$((T_PASS + 1)); }
faill() { T_FAIL=$((T_FAIL + 1)); }
skipl() { T_SKIP=$((T_SKIP + 1)); }
eval "$(sed -n '/^run_bash() {/,/^}/p' "$ROOT/scripts/run-selftests.sh")"
eval "$(sed -n '/^run_shell() {/,/^}/p' "$ROOT/scripts/run-selftests.sh")"
eval "$(sed -n '/^run_py() {/,/^}/p' "$ROOT/scripts/run-selftests.sh")"

T_FAIL=0; T_SKIP=0; run_bash "$WORK/does-not-exist.sh"
if [ "$T_FAIL" -eq 1 ] && [ "$T_SKIP" -eq 0 ]; then
	ok "run_bash on a missing file FAILs (not SKIP)"
else
	bad "run_bash on a missing file: FAIL=$T_FAIL SKIP=$T_SKIP"
fi
T_FAIL=0; T_SKIP=0; run_shell "$WORK/does-not-exist.sh"
if [ "$T_FAIL" -eq 1 ] && [ "$T_SKIP" -eq 0 ]; then
	ok "run_shell on a missing file FAILs (not SKIP)"
else
	bad "run_shell on a missing file: FAIL=$T_FAIL SKIP=$T_SKIP"
fi
T_FAIL=0; T_SKIP=0; run_py "$WORK/does-not-exist.py"
if [ "$T_FAIL" -eq 1 ] && [ "$T_SKIP" -eq 0 ]; then
	ok "run_py on a missing file FAILs (not SKIP)"
else
	bad "run_py on a missing file: FAIL=$T_FAIL SKIP=$T_SKIP"
fi
# Control: the extracted functions execute real code (a passing script PASSes).
printf '#!/bin/sh\nexit 0\n' >"$WORK/trivial.sh"
T_PASS=0; T_FAIL=0; run_shell "$WORK/trivial.sh"
if [ "$T_PASS" -eq 1 ] && [ "$T_FAIL" -eq 0 ]; then
	ok "extracted run_shell executes (control)"
else
	bad "extracted run_shell control: PASS=$T_PASS FAIL=$T_FAIL"
fi

# ── 10b. the caller's warn excerpt preserves warnings on success ──
# run-selftests.sh prints tail -1 on a green aggregate; the warn-excerpt line
# below it must reprint window-FAIL and DRIFT lines so success stays
# informative. This cell executes the CALLER'S REAL pipeline text (extracted
# at test time — a copy would prove nothing about the runner) against a
# fixture aggregate carrying both markers.
if ! command -v python3 >/dev/null 2>&1; then
	ok "caller warn excerpt (SKIP: python3 not installed)"
else
	n=$((n + 1)); fix="$WORK/f$n"; mkdir -p "$fix/led"
	PYTHONPATH="$ROOT/test/incus" python3 - "$fix/led" <<'PY'
import json, sys
sys.path.insert(0, "test/incus")
from ledger_compare_test import row
led = sys.argv[1]
rows = (
    [row(f"2026-09-01T00:0{i}:00Z", value=100.0, gate="gate-win") for i in range(3)]
    + [row("2026-09-01T00:03:00Z", verdict="FAIL", value=10.0, gate="gate-win")]
    + [row("2026-09-01T00:04:00Z", value=100.0, gate="gate-win")]
    + [row(f"2026-09-01T00:{i:02d}:00Z", value=100.0 * (0.96 ** i), gate="gate-drift") for i in range(12)]
)
for r in rows:
    open(f"{led}/{r['run_id']}.json", "w").write(json.dumps(r))
PY
	out=$(python3 "$ROOT/test/incus/ledger_compare.py" --all --ledger "$fix/led" 2>&1)
	leg=$(grep -F 'warn: /' "$ROOT/scripts/run-selftests.sh" | head -1)
	if [ -z "$leg" ]; then
		bad "caller warn excerpt line not found in run-selftests.sh (extraction void)"
	else
		warns=$(eval "$leg")
		case "$warns" in
		*"FAIL rows inside the baseline window"* | *"DRIFT"*)
			case "$warns" in
			*"FAIL rows inside the baseline window"*)
				case "$warns" in
				*"DRIFT"*) ok "caller warn excerpt reprints window-FAIL and DRIFT lines" ;;
				*) bad "caller excerpt missed the DRIFT line: $warns" ;;
				esac
				;;
			*) bad "caller excerpt missed the window-FAIL line: $warns" ;;
			esac
			;;
		*) bad "caller warn excerpt printed nothing for a warnings-carrying aggregate" ;;
		esac
	fi
fi

# ── 11. positive control on the real tree ──
if out=$(sh "$CENSUS" 2>&1); then
	ok "census passes on the real tree"
else
	bad "census fails on the real tree: $out"
fi

echo ""
echo "selftest-census-selftest: passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]
