#!/bin/sh
# ci_tooling_check.sh (#16197): decoupled ADVISORY tooling CI leg.
#
# An isolated, bounded entry point -- NOT `scripts/run-selftests.sh`
# whole (that runner self-declares non-hermetic: host tools / sudo can
# SKIP whole legs). This leg runs only:
#
#   1. pinned shellcheck (-S warning) over the explicit file list
#      owned below, and
#   2. the hermetic Python unittest subset under scripts/ (the
#      scripts/test_*.py, scripts/*_test.py and scripts/lib/test_*.py
#      files), run directly with python3.
#
# It is decoupled from the proto leg (#16195) and from any
# selftest-registry work: the shell list is owned here on purpose,
# not parsed out of run-selftests.sh.
#
# Denominators are published per leg, exactly one line per leg:
#   TOOLING_LEG shellcheck ran=<n> skipped=<n> failed=<n> expected_skipped=0
#   TOOLING_LEG python     ran=<n> skipped=<n> failed=<n> expected_skipped=0
# (appended to $GITHUB_STEP_SUMMARY when set). A leg that ran nothing
# is RED, never green: ran==0 fails. An all-skip Python file counts
# as skipped, not passed.
#
# Expected-SKIP policy (explicit): expected_skipped=0 for BOTH legs.
# No file in either subset is expected to skip. Any skipped Python
# test, or any deviation from these zeros, is red. Raising an
# expectation means editing the constants below AND
# docs/ci-gate-contract.md in the same change, with a reason --
# silently absorbing a new skip is exactly the false green this leg
# exists to refuse.
#
# Advisory status: per docs/ci-gate-contract.md this leg is NOT a
# merge gate and must not be made a required status without a
# recorded baseline-green period on master.
#
# Pins: shellcheck v0.11.0 (verified after fetch, like the protoc pin
# in scripts/proto_regen_check.sh). Override SHELLCHECK to supply a
# pre-pinned binary (used by the hermetic self-test; a wrong-version
# override is a hard failure, not a silent substitution).
set -u

# shellcheck disable=SC1007  # `CDPATH= cd` clears CDPATH for this command only
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT" || { echo "FATAL: cannot cd to repo root $ROOT" >&2; exit 1; }

SHELLCHECK_VERSION=0.11.0
EXPECTED_SHELLCHECK_SKIPPED=0
EXPECTED_PYTHON_SKIPPED=0

SCRATCH_BASE=${TMPDIR:-/var/worktrees/.cache/tmpdir}
if ! mkdir -p "$SCRATCH_BASE" 2>/dev/null; then
	SCRATCH_BASE=/tmp
fi
SCRATCH=$SCRATCH_BASE/xpf-ci-tooling.$$
mkdir -p "$SCRATCH/bin"
trap 'rm -rf "$SCRATCH"' EXIT INT TERM

OVERALL_FAIL=0

publish() {
	echo "$1"
	if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
		echo "$1" >> "$GITHUB_STEP_SUMMARY"
	fi
}

# ── pinned shellcheck acquisition ────────────────────────────────────
shellcheck_version() {
	"$1" --version 2>/dev/null | sed -n 's/^version: //p' | head -1
}

resolve_shellcheck() {
	if [ -n "${SHELLCHECK:-}" ]; then
		# Explicit override: must already be the pinned version.
		if [ "$(shellcheck_version "$SHELLCHECK")" = "$SHELLCHECK_VERSION" ]; then
			echo "$SHELLCHECK"
			return 0
		fi
		echo "ci_tooling_check: SHELLCHECK=$SHELLCHECK is '$(shellcheck_version "$SHELLCHECK")', want $SHELLCHECK_VERSION" >&2
		return 1
	fi
	if command -v shellcheck >/dev/null 2>&1 && [ "$(shellcheck_version "$(command -v shellcheck)")" = "$SHELLCHECK_VERSION" ]; then
		command -v shellcheck
		return 0
	fi
	case "$(uname -s)-$(uname -m)" in
	Linux-x86_64) asset=shellcheck-v$SHELLCHECK_VERSION.linux.x86_64.tar.xz ;;
	Linux-aarch64) asset=shellcheck-v$SHELLCHECK_VERSION.linux.aarch64.tar.xz ;;
	*) echo "ci_tooling_check: no pinned shellcheck asset for $(uname -s)-$(uname -m); set SHELLCHECK" >&2; return 1 ;;
	esac
	if ! command -v curl >/dev/null 2>&1 || ! command -v tar >/dev/null 2>&1; then
		echo "ci_tooling_check: need curl+tar to fetch pinned shellcheck, or set SHELLCHECK" >&2
		return 1
	fi
	if ! curl -fsSL -o "$SCRATCH/shellcheck.tar.xz" \
		"https://github.com/koalaman/shellcheck/releases/download/v$SHELLCHECK_VERSION/$asset"; then
		echo "ci_tooling_check: pinned shellcheck download failed" >&2
		return 1
	fi
	if ! tar -xJf "$SCRATCH/shellcheck.tar.xz" -C "$SCRATCH"; then
		echo "ci_tooling_check: pinned shellcheck unpack failed" >&2
		return 1
	fi
	bin=$SCRATCH/shellcheck-v$SHELLCHECK_VERSION/shellcheck
	if [ "$(shellcheck_version "$bin")" = "$SHELLCHECK_VERSION" ]; then
		echo "$bin"
		return 0
	fi
	echo "ci_tooling_check: fetched shellcheck is '$(shellcheck_version "$bin")', want $SHELLCHECK_VERSION" >&2
	return 1
}

# ── 1. shellcheck leg ────────────────────────────────────────────────
# The bounded list this leg owns (kept shellcheck-clean at -S warning).
SHELLCHECK_FILES="
scripts/ci_tooling_check.sh
scripts/ci-tooling-check-selftest.sh
scripts/image/xpf-day0-config
scripts/image/xpf-grow-root
scripts/image/xpf-uefi-slots
scripts/image/xpf-kernel-promote
scripts/image/incus-agent-setup
scripts/image/test-grow-root.sh
scripts/dist/selftest.sh
scripts/dist/install.sh
scripts/dist/build-apt-repo.sh
userspace-dp/build_support/dp-toolchain.sh
scripts/run-selftests.sh
scripts/mutate-lib.sh
scripts/mutate.sh
scripts/mutate-selftest.sh
scripts/docs/check-upgrade-docs.sh
scripts/docs/check-upgrade-docs-selftest.sh
test/incus/fbf-steering-lib.sh
test/incus/fbf-steering-selftest.sh
test/incus/test-fbf-steering.sh
test/incus/newflow-ceiling-lib.sh
test/incus/newflow-ceiling-selftest.sh
test/incus/newflow-ceiling-harness.sh
test/incus/stress-failover-lib.sh
test/incus/test-stress-failover.sh
test/incus/stress-failover-selftest.sh
test/incus/mouse-elephant-lib.sh
test/incus/mouse-elephant-selftest.sh
scripts/harness-census.sh
test/incus/harness-census-selftest.sh
test/incus/harness-result.sh
test/incus/harness-result-selftest.sh
test/incus/harness-ledger-mutation-selftest.sh
scripts/ignored-cell-census.sh
test/incus/ignored-cell-census-selftest.sh
scripts/go-skip-census.sh
test/incus/go-skip-census-selftest.sh
scripts/go-buildtag-census.sh
test/incus/go-buildtag-census-selftest.sh
scripts/selftest-census.sh
test/incus/selftest-census-selftest.sh
scripts/miri-census.sh
scripts/miri-leg.sh
scripts/debug-leg-census-selftest.sh
test/incus/miri-census-selftest.sh
scripts/close_keyword_lint_ci.sh
scripts/proto_regen_check.sh
scripts/proto-regen-check-selftest.sh
scripts/git-hooks/commit-msg
scripts/git-hooks/install.sh
test/incus/ha-smoke-iperf-lib.sh
"

sh_ran=0
sh_skipped=0
sh_failed=0
if shellcheck_bin=$(resolve_shellcheck); then
	for s in $SHELLCHECK_FILES; do
		if [ ! -f "$s" ]; then
			echo "  FAIL: shellcheck $s (not present -- a covered file that is gone)" >&2
			sh_failed=$((sh_failed + 1))
			continue
		fi
		sh_ran=$((sh_ran + 1))
		if out=$("$shellcheck_bin" -S warning "$s" 2>&1); then
			echo "  PASS: shellcheck $s"
		else
			echo "  FAIL: shellcheck $s" >&2
			printf '%s\n' "$out" | sed 's/^/      /' >&2
			sh_failed=$((sh_failed + 1))
		fi
	done
else
	echo "  FAIL: pinned shellcheck $SHELLCHECK_VERSION unavailable" >&2
	sh_failed=$((sh_failed + 1))
fi
sh_status=PASS
if [ "$sh_ran" -eq 0 ] || [ "$sh_failed" -ne 0 ] || [ "$sh_skipped" -ne "$EXPECTED_SHELLCHECK_SKIPPED" ]; then
	sh_status=FAIL
	OVERALL_FAIL=1
fi
publish "TOOLING_LEG shellcheck ran=$sh_ran skipped=$sh_skipped failed=$sh_failed expected_skipped=$EXPECTED_SHELLCHECK_SKIPPED status=$sh_status"

# ── 2. python leg ────────────────────────────────────────────────────
# The bounded hermetic subset: scripts root + scripts/lib unittest
# files, run directly (each resolves its target relative to itself).
py_ran=0
py_skipped=0
py_failed=0
py_files=0
if ! command -v python3 >/dev/null 2>&1; then
	echo "  FAIL: python3 not installed" >&2
	py_failed=$((py_failed + 1))
else
	# Intentional word splitting: glob expansion enumerates the subset.
	# shellcheck disable=SC2086
	for t in scripts/test_*.py scripts/*_test.py scripts/lib/test_*.py; do
		[ -f "$t" ] || continue
		py_files=$((py_files + 1))
		out=$(python3 "$t" 2>&1)
		rc=$?
		ran=$(printf '%s\n' "$out" | sed -n 's/^Ran \([0-9][0-9]*\) test.*/\1/p' | head -1)
		nskip=$(printf '%s\n' "$out" | sed -n 's/.*skipped=\([0-9][0-9]*\).*/\1/p' | head -1)
		[ -n "$nskip" ] || nskip=0
		if [ "$rc" -ne 0 ]; then
			echo "  FAIL: $t" >&2
			printf '%s\n' "$out" | sed 's/^/      /' >&2
			py_failed=$((py_failed + 1))
			[ -n "$ran" ] && py_ran=$((py_ran + ran))
			py_skipped=$((py_skipped + nskip))
		elif [ -z "$ran" ] || [ "$ran" -eq 0 ]; then
			# No denominator: a file that measured nothing is red,
			# not a pass and not a skip.
			echo "  FAIL: $t (ran=0 -- measures nothing)" >&2
			py_failed=$((py_failed + 1))
		elif [ "$ran" -eq "$nskip" ]; then
			echo "  SKIP: $t (all $nskip tests skipped)"
			py_ran=$((py_ran + ran))
			py_skipped=$((py_skipped + nskip))
		else
			echo "  PASS: $t ($ran tests, skipped=$nskip)"
			py_ran=$((py_ran + ran))
			py_skipped=$((py_skipped + nskip))
		fi
	done
fi
py_status=PASS
if [ "$py_files" -eq 0 ] || [ "$py_ran" -eq 0 ] || [ "$py_failed" -ne 0 ] || [ "$py_skipped" -ne "$EXPECTED_PYTHON_SKIPPED" ]; then
	py_status=FAIL
	OVERALL_FAIL=1
fi
publish "TOOLING_LEG python ran=$py_ran skipped=$py_skipped failed=$py_failed files=$py_files expected_skipped=$EXPECTED_PYTHON_SKIPPED status=$py_status"

if [ "$OVERALL_FAIL" -ne 0 ]; then
	echo "ci_tooling_check: FAIL (advisory leg; see TOOLING_LEG lines above)" >&2
	exit 1
fi
echo "ci_tooling_check: OK (advisory leg; see TOOLING_LEG lines above)"
exit 0
