#!/usr/bin/env bash
# Stale no-CI claim guard (#12632).
#
# CI exists and is advisory: `.github/workflows/close-keyword-lint.yml`
# (#9551, 2026-09-23) runs the close-keyword lint on every PR, and
# `.github/workflows/test.yml` ("CI tests", 2026-10-01) runs the harness
# census, affected Go tests, and the Rust workspace compile check on
# every PR. None of those checks blocks merges until required in master
# branch rulesets, and the packet-level gates stay manual — that whole
# contract lives in docs/ci-gate-contract.md, the single source of truth.
#
# Live prose that still asserts there is NO CI at all sends maintainers
# to the wrong enforcement surface (#12444 fixed the first set; master
# drifted again within hours of that review). The stale literals below
# are therefore banned in live docs, the Makefile, and
# scripts/run-selftests.sh. History archives that quote the old claims
# while recording their removal are excluded, same posture as #9783:
# docs/issues/, docs/log/, docs/reviews/, docs/pr/.
#
# Deliberately standalone (run via `make docs-check`), NOT wired into
# `make test` — same posture as the upgrade-docs canary. Exit non-zero
# if a banned literal reappears, OR if a search target is missing (a
# renamed doc / absent target is an ERROR, never a vacuous pass — the
# guard is fail-closed).

set -euo pipefail

# Resolve repo root from this script's location so the guard works from
# any CWD (Makefile target, CI, manual run).
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
# DOCS_CHECK_ROOT points the guard at a fixture tree instead (#12632,
# scripts/docs/check-no-ci-claims-selftest.sh). Unset, it is the repo.
cd "${DOCS_CHECK_ROOT:-$repo_root}"

status=0

# The stale literals. Each asserts (or presupposes) that no CI runs at
# all; the advisory-CI reality is documented in docs/ci-gate-contract.md,
# so any occurrence in a live file is the stale claim. Narrow on purpose:
# legitimate narrower claims ("CI does not run the packet gates", "not
# wired into CI", census vocabulary such as "no CIR") must NOT match.
phrases=(
	"no CI in this repo"
	"no CI in this repository"
	"this repo has no CI"
	"this repository has no CI"
	"There is no CI"
	"there is no CI"
	"repo has no CI"
	"repository has no CI"
	"this repo has no GitHub Actions"
	"There is no GitHub Actions"
	"no GitHub Actions / CI"
	"nothing runs automatically"
	"there is no CI,"
	"no CI at all"
)

# History archives excluded from the docs scan (they quote the claims
# while recording their removal).
is_history() {
	case "$1" in
	docs/issues/* | docs/log/* | docs/reviews/* | docs/pr/*) return 0 ;;
	*) return 1 ;;
	esac
}

# Search targets, checked explicitly so a missing one fails closed
# instead of silently narrowing the scan.
targets=()
if [ ! -d docs ]; then
	echo "ERROR: docs directory not found at docs/ — the no-CI guard" >&2
	echo "       cannot run. If the docs tree moved, update this guard." >&2
	status=1
else
	while IFS= read -r f; do
		is_history "$f" || targets+=("$f")
	done < <(find docs -type f -name '*.md' | sort)
fi
for f in Makefile scripts/run-selftests.sh; do
	if [ ! -f "$f" ]; then
		echo "ERROR: search target $f not found — the no-CI guard cannot" >&2
		echo "       run its scan. If it moved, update this guard." >&2
		status=1
	else
		targets+=("$f")
	fi
done

if [ "${#targets[@]}" -eq 0 ]; then
	echo "ERROR: no live search targets collected — refusing to pass" >&2
	echo "       on an empty scan." >&2
	status=1
fi

for phrase in "${phrases[@]}"; do
	# Distinguish grep's outcomes explicitly: 0 = matched (stale claim),
	# 1 = no match (good), >=2 = error (never a pass). `|| rc=$?` keeps
	# a no-match grep from tripping `set -e`.
	rc=0
	out="$(grep -niF -- "$phrase" "${targets[@]}" 2>&1)" || rc=$?
	if [ "$rc" -ge 2 ]; then
		echo "ERROR: grep failed (rc=$rc) scanning for \"$phrase\":" >&2
		printf '%s\n' "$out" >&2
		status=1
	elif [ "$rc" -eq 0 ]; then
		echo "ERROR: stale no-CI claim \"$phrase\" found:" >&2
		printf '%s\n' "$out" >&2
		echo "       CI is advisory but real (close-keyword-lint on every" >&2
		echo "       PR since 2026-09-23; CI tests since 2026-10-01). Reword" >&2
		echo "       to that reality and point at docs/ci-gate-contract.md." >&2
		status=1
	fi
done

if [ "$status" -eq 0 ]; then
	echo "OK: no stale no-CI claims in ${#targets[@]} live files (docs/ci-gate-contract.md is the CI source of truth)."
fi
exit "$status"
