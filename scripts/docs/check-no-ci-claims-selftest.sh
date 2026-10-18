#!/usr/bin/env bash
# Fixture-based self-test for the stale no-CI claims canary (#12632).
# The positive control is load-bearing: a guard that scans nothing or whose
# phrase matcher is accidentally weakened must fail on a live stale claim.
set -u
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
guard="$here/check-no-ci-claims.sh"
tmp="$(mkdir -p /var/worktrees/.cache/tmpdir && TMPDIR=/var/worktrees/.cache/tmpdir mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fail=0

mkroot() {
	local root="$tmp/$1"
	mkdir -p "$root/docs/log" "$root/scripts"
	printf '# Contract\nCI is advisory; see docs/ci-gate-contract.md.\n' >"$root/docs/ci-gate-contract.md"
	printf '# Live docs\nThe CI tests workflow runs on every PR.\n' >"$root/docs/engineering-style.md"
	printf '# Makefile\n' >"$root/Makefile"
	printf '# Runner\n' >"$root/scripts/run-selftests.sh"
	printf '# Archived claim\nThere is no CI in this repository.\n' >"$root/docs/log/claim.md"
	printf '%s\n' "$root"
}

expect() {
	local want=$1 name=$2 root=$3 out rc
	out="$(DOCS_CHECK_ROOT="$root" bash "$guard" 2>&1)"
	rc=$?
	if [ "$rc" -eq "$want" ]; then
		echo "ok   $name (rc=$rc)"
	else
		echo "FAIL $name: want rc=$want, got rc=$rc"
		printf '%s\n' "$out" | sed 's/^/      /'
		fail=1
	fi
}

r="$(mkroot clean)"
expect 0 "clean live docs pass; archived claim is excluded" "$r"

r="$(mkroot stale)"
printf 'There is no CI in this repository.\n' >>"$r/docs/engineering-style.md"
expect 1 "POSITIVE CONTROL: stale live claim fails" "$r"

r="$(mkroot capitalized)"
printf 'Nothing runs automatically.\\n' >>"$r/docs/engineering-style.md"
expect 1 "capitalized categorical claim is rejected" "$r"

r="$(mkroot narrow)"
printf 'CI does not run the packet-level gates.\n' >>"$r/docs/engineering-style.md"
expect 0 "narrow accurate claim about manual packet gates passes" "$r"

r="$(mkroot missing)"
rm "$r/Makefile"
expect 1 "missing required target fails closed" "$r"

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "PASS: no-CI claims guard self-test"
