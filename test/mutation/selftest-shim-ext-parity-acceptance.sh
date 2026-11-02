#!/usr/bin/env bash
# Hermetic selftest for test/mutation/shim-ext-parity-acceptance.sh's own
# control flow (#18738): the signal handling and the ROWS filter. No cargo, no
# Rust build: a stub `cargo` stands in for the build and test gates, and the
# acceptance script runs from a copy inside a throwaway git checkout that
# holds a copy of the real walker, so the real mutators apply unchanged.
#
# Cells:
#   A  TERM mid-row (the stub hangs inside row 1's test gate): exit 143, the
#      walker is restored byte for byte, GOLD and the temp files are gone, no
#      "RESTORE FAILED", and row 2 never starts.
#   A0 positive control: the SAME probe against the pre-#18738 trap
#      (`trap cleanup EXIT INT TERM`, no exit) must report the defect, or cell
#      A could not tell a fixed harness from a broken one.
#   B  ROWS=2: only row 2 (plus row 0 and RESTORED) runs, it scores, and the
#      verdict says the matrix is partial.
#   C  ROWS naming no declared row is refused (exit 2) before anything is
#      touched.
#
# Exit 0 all cells pass, 1 a cell failed, 77 a tool is missing.
if [ -z "${BASH_VERSION:-}" ]; then exec bash "$0" "$@"; fi
set -uo pipefail

for tool in git python3 setsid cmp timeout; do
	command -v "$tool" >/dev/null 2>&1 || { echo "SKIP: $tool not found"; exit 77; }
done

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_REPO="$(cd "${HERE}/../.." && pwd)"
ACCEPT="${HERE}/shim-ext-parity-acceptance.sh"
REAL_WALK="${SRC_REPO}/userspace-xdp/src/ipv6_ext_walk.rs"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/shimsel.XXXXXX")"
trap 'rm -rf "${WORK}"' EXIT
fails=0
pass() { echo "PASS: $*"; }
failc() { echo "FAIL: $*"; fails=$((fails + 1)); }

# sandbox <name> <trap-variant: fixed|old> -> prints the sandbox repo path
sandbox() {
	local name=$1 variant=$2 repo="${WORK}/$1"
	mkdir -p "${repo}/test/mutation" "${repo}/userspace-xdp/src" "${repo}/userspace-dp" "${WORK}/$1.tmp"
	cp "${REAL_WALK}" "${repo}/userspace-xdp/src/ipv6_ext_walk.rs"
	cp "${REAL_WALK}" "${WORK}/$1.pristine"
	python3 - "${ACCEPT}" "${repo}/test/mutation/shim-ext-parity-acceptance.sh" "${WORK}/$1.lock" "${variant}" <<'PY'
import sys
src, dst, lock, variant = sys.argv[1:]
s = open(src).read()
old = 'LOCK="/var/worktrees/.cache/tmpdir/xpf-4555-acceptance.lock"'
assert s.count(old) == 1, "fixture: LOCK line not found exactly once"
s = s.replace(old, 'LOCK="%s"' % lock)
if variant == "old":
    traps = ('trap cleanup EXIT\n'
             'trap \'echo "SIGNAL: INT, walker restored, run stopped" >&2; cleanup; exit 130\' INT\n'
             'trap \'echo "SIGNAL: TERM, walker restored, run stopped" >&2; cleanup; exit 143\' TERM\n')
    assert s.count(traps) == 1, "fixture: fixed trap block not found exactly once"
    s = s.replace(traps, 'trap cleanup EXIT INT TERM\n')
open(dst, "w").write(s)
PY
	git -C "${repo}" init -q
	git -C "${repo}" add -A
	git -C "${repo}" -c user.name=selftest -c user.email=selftest@invalid commit -qm fixture
	mkdir -p "${WORK}/$1.bin"
	cat >"${WORK}/$1.bin/cargo" <<'STUB'
#!/usr/bin/env bash
# Stub cargo: `test --release --bin xpf-userspace-dp (--no-run | <filter>)`.
walk="${STUB_REPO}/userspace-xdp/src/ipv6_ext_walk.rs"
echo "cargo $*" >>"${STUB_LOG}"
case " $* " in
*" --no-run "*) grep -q "this is not rust" "${walk}" && exit 101; exit 0 ;;
esac
filter="${*: -1}"
[ "${filter}" = "tests_shim_ext_parity" ] || exit 0
if cmp -s "${walk}" "${STUB_PRISTINE}"; then g=ok; else g=FAILED; fi
if [ "${g}" = FAILED ] && [ -n "${STUB_HANG_MARK:-}" ]; then
	ps -o pgid= $$ | tr -d ' ' >"${STUB_HANG_MARK}"
	sleep 60
fi
for t in shim_walk_and_userspace_walk_agree_over_a_corpus shim_walk_is_not_more_permissive shim_ipv6_ext_walk_matches_userspace_walker; do
	echo "test afxdp::frame::tests_shim_ext_parity::${t} ... ${g}"
done
for t in shim_walk_corpus_negative_control shim_ext_parity_negative_control_unchanged_classifications; do
	echo "test afxdp::frame::tests_shim_ext_parity::${t} ... ok"
done
[ "${g}" = ok ] && exit 0
echo "[l3=0] stub divergence"
exit 101
STUB
	chmod +x "${WORK}/$1.bin/cargo"
	echo "${repo}"
}

# run_term <name> <variant>: start the harness in its own session, TERM its
# process group once the stub hangs inside row 1, and record rc + output.
run_term() {
	local name=$1 variant=$2 repo
	repo="$(sandbox "${name}" "${variant}")"
	local mark="${WORK}/${name}.hang"
	(
		export PATH="${WORK}/${name}.bin:${PATH}" TMPDIR="${WORK}/${name}.tmp"
		export STUB_REPO="${repo}" STUB_PRISTINE="${WORK}/${name}.pristine" STUB_LOG="${WORK}/${name}.cargo.log" STUB_HANG_MARK="${mark}"
		exec setsid -w bash "${repo}/test/mutation/shim-ext-parity-acceptance.sh"
	) >"${WORK}/${name}.out" 2>&1 &
	local pid=$!
	local i
	for i in $(seq 1 300); do [ -s "${mark}" ] && break; sleep 0.1; done
	if [ ! -s "${mark}" ]; then
		kill -KILL "${pid}" 2>/dev/null
		echo "fixture: the stub never hung inside row 1" >"${WORK}/${name}.rc"
		return
	fi
	kill -TERM -- "-$(cat "${mark}")"
	if timeout 30 tail --pid="${pid}" -f /dev/null; then
		wait "${pid}"; echo $? >"${WORK}/${name}.rc"
	else
		kill -KILL "${pid}" 2>/dev/null
		echo "hung after TERM" >"${WORK}/${name}.rc"
	fi
}

# verdict_term <name>: 0 when every cell-A property holds, else prints why.
verdict_term() {
	local name=$1 repo="${WORK}/$1" why=""
	local rc; rc="$(cat "${WORK}/${name}.rc")"
	[ "${rc}" = "143" ] || why+=" exit=${rc} (want 143);"
	cmp -s "${repo}/userspace-xdp/src/ipv6_ext_walk.rs" "${WORK}/${name}.pristine" || why+=" walker NOT restored;"
	ls "${WORK}/${name}.tmp"/ipv6_ext_walk.gold.* >/dev/null 2>&1 && why+=" GOLD left behind;"
	grep -q "RESTORE FAILED" "${WORK}/${name}.out" && why+=" RESTORE FAILED printed;"
	grep -q "HARNESS ERROR" "${WORK}/${name}.out" && why+=" HARNESS ERROR (the run resumed after TERM);"
	grep -qE '^ 2\. ' "${WORK}/${name}.out" && why+=" row 2 ran after TERM;"
	grep -q "SIGNAL: TERM" "${WORK}/${name}.out" || why+=" no SIGNAL: TERM line;"
	[ -z "${why}" ] && return 0
	echo "${why}"
	return 1
}

# --- A: TERM mid-row against the fixed harness -------------------------------
run_term termfix fixed
if why="$(verdict_term termfix)"; then
	pass "A  TERM mid-row 1: exit 143, walker restored, GOLD gone, row 2 never started"
else
	failc "A  TERM mid-row 1:${why}"
	sed 's/^/      /' "${WORK}/termfix.out" | tail -12
fi

# --- A0: the same probe must SEE the pre-#18738 trap defect ------------------
run_term termold old
if why="$(verdict_term termold)"; then
	failc "A0 the pre-#18738 trap (cleanup without exit) passed cell A's checks; cell A cannot detect the defect"
else
	pass "A0 positive control: the pre-#18738 trap is caught:${why}"
fi

# --- B: ROWS=2 runs and scores row 2 only ------------------------------------
repo="$(sandbox rows2 fixed)"
(
	export PATH="${WORK}/rows2.bin:${PATH}" TMPDIR="${WORK}/rows2.tmp" ROWS=2
	export STUB_REPO="${repo}" STUB_PRISTINE="${WORK}/rows2.pristine" STUB_LOG="${WORK}/rows2.cargo.log"
	timeout 120 bash "${repo}/test/mutation/shim-ext-parity-acceptance.sh"
) >"${WORK}/rows2.out" 2>&1
rc=$?
out="${WORK}/rows2.out"
why=""
[ "${rc}" -eq 0 ] || why+=" exit=${rc};"
grep -q "ROWS=2: running rows 2 of 20" "${out}" || why+=" no ROWS selection line;"
grep -qE '^ 2\. GENERIC post-advance revalidation DELETED' "${out}" || why+=" row 2 did not run;"
grep -qE '^ (1|3)\. ' "${out}" && why+=" an unselected row ran;"
grep -q "rows passed: 2/2" "${out}" || why+=" accounting is not 2/2 (row 2 + RESTORED);"
grep -q "NOT a full matrix" "${out}" || why+=" the verdict does not say the matrix is partial;"
cmp -s "${repo}/userspace-xdp/src/ipv6_ext_walk.rs" "${WORK}/rows2.pristine" || why+=" walker not restored;"
if [ -z "${why}" ]; then
	pass "B  ROWS=2 runs row 2 only, scores 2/2 with RESTORED, and calls itself partial"
else
	failc "B  ROWS=2:${why}"
	tail -12 "${out}" | sed 's/^/      /'
fi

# --- C: an undeclared row is refused before anything is touched --------------
repo="$(sandbox rowsbad fixed)"
for bad in 21 0 3-1 x; do
	# Each refusal is judged on its own: nothing an earlier probe left behind.
	rm -f "${WORK}/rowsbad.cargo.log" "${WORK}/rowsbad.lock"
	(
		export PATH="${WORK}/rowsbad.bin:${PATH}" TMPDIR="${WORK}/rowsbad.tmp" ROWS="${bad}"
		export STUB_REPO="${repo}" STUB_PRISTINE="${WORK}/rowsbad.pristine" STUB_LOG="${WORK}/rowsbad.cargo.log"
		timeout 30 bash "${repo}/test/mutation/shim-ext-parity-acceptance.sh"
	) >"${WORK}/rowsbad.out" 2>&1
	rc=$?
	if [ "${rc}" -eq 2 ] && [ ! -e "${WORK}/rowsbad.cargo.log" ] && [ ! -e "${WORK}/rowsbad.lock" ] &&
		cmp -s "${repo}/userspace-xdp/src/ipv6_ext_walk.rs" "${WORK}/rowsbad.pristine"; then
		pass "C  ROWS=${bad} refused (exit 2) before the lock, the capture or any build"
	else
		failc "C  ROWS=${bad}: exit=${rc}, cargo log $([ -e "${WORK}/rowsbad.cargo.log" ] && echo present || echo absent), lock $([ -e "${WORK}/rowsbad.lock" ] && echo taken || echo untouched)"
	fi
done

[ "${fails}" -eq 0 ] && { echo "shim-ext-parity acceptance selftest: all cells pass"; exit 0; }
echo "shim-ext-parity acceptance selftest: ${fails} cell(s) failed"
exit 1
