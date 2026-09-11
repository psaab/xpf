#!/usr/bin/env bash
# Upgrade/install docs canary (#2001).
#
# A small fail-closed guard against the two upgrade-install doc phrasings
# that repeatedly mislead the next maintainer once the hardened model
# (#1964 versioned-runtime seed, #1982 manifest SSOT, #1983 reject-non-
# default endpoint) landed:
#
#   1. "symlinks into the staging path" — the live /usr/local/sbin/*
#      symlinks resolve THROUGH versions/current on a normal first install
#      (xpfd seed-runtime); they point straight at staged/* ONLY in the
#      degraded direct-staged FALLBACK when seeding fails. So this phrase
#      must never describe the normal install layout. install-images.md is
#      the install-layout doc; the phrase is banned there outright (the
#      fallback is documented without the misleading literal).
#
#   2. `manifest.Managed` — that symbol does NOT exist. The managed-binary
#      SSOT is the UNEXPORTED `managed` slice in
#      pkg/upgrade/manifest/manifest.go, reachable only via the exported
#      accessors All() / Names() / LockstepNames(). Docs that tell a
#      maintainer to edit `manifest.Managed` send them to a phantom symbol.
#      Banned across docs/, except the generated history archives
#      (docs/issues/, docs/log/, docs/reviews/), which quote it while
#      recording its removal (#9783).
#
# This is a docs-only grep guard, deliberately standalone (run via
# `make docs-check`) and NOT wired into `make test` — same posture as the
# audit-check drift guard. Exit non-zero if either phrase reappears, OR if
# a search target is missing (a renamed install doc / absent docs/ dir is
# an ERROR, never a vacuous pass — the guard is fail-closed).

set -euo pipefail

# Resolve repo root from this script's location so the canary works from
# any CWD (Makefile target, CI, manual run).
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
# DOCS_CHECK_ROOT points the guard at a fixture tree instead (#9783,
# scripts/docs/check-upgrade-docs-selftest.sh). Unset, it is the repo.
cd "${DOCS_CHECK_ROOT:-$repo_root}"

status=0

# The guard is FAIL-CLOSED: a missing search target is an ERROR, not a
# vacuous pass. If the install-layout doc is renamed/removed or docs/ is
# gone, the canary fails loudly so a refactor cannot silently disable it.

# Phrase 1: banned in the install-layout doc. The direct-staged fallback
# is documented in install-images.md WITHOUT this literal, so any
# occurrence is the stale pre-#1964 layout language.
phrase_staging="symlinks into the staging path"
doc_install="docs/install-images.md"
if [ ! -f "$doc_install" ]; then
	echo "ERROR: install-layout doc not found at $doc_install — the upgrade" >&2
	echo "       docs canary cannot run its phrase-1 check. If the doc moved," >&2
	echo "       update doc_install in scripts/docs/check-upgrade-docs.sh." >&2
	status=1
elif grep -nF -- "$phrase_staging" "$doc_install"; then
	echo "ERROR ($doc_install): the literal \"$phrase_staging\" describes the" >&2
	echo "       pre-#1964 layout. On a normal install the sbin symlinks resolve" >&2
	echo "       THROUGH versions/current (xpfd seed-runtime); only the degraded" >&2
	echo "       fallback points at staged/*. Reword without this literal." >&2
	status=1
fi

# Phrase 2: banned across all live docs. manifest.Managed is a phantom symbol;
# the SSOT is the unexported `managed` slice + All()/Names()/LockstepNames().
phrase_symbol="manifest.Managed"
docs_dir="docs"
if [ ! -d "$docs_dir" ]; then
	echo "ERROR: docs directory not found at $docs_dir/ — the upgrade docs" >&2
	echo "       canary cannot run its phrase-2 check. Expected the repo docs/" >&2
	echo "       tree at the repo root." >&2
	status=1
else
	# Distinguish grep's three outcomes explicitly so a grep ERROR (exit
	# >=2: unreadable tree, etc.) is NOT mistaken for "no match" (exit 1,
	# the good case). Route matched lines to stderr alongside the failure
	# message. `|| rc=$?` keeps the captured grep from tripping `set -e`.
	rc=0
	matches="$(grep -rnF -- "$phrase_symbol" "$docs_dir/")" || rc=$?
	# #9783: the generated history archives (docs/issues/, docs/log/,
	# docs/reviews/) QUOTE the phantom symbol while recording its removal.
	# Scanning them kept this guard red on a tree with no live-doc hit: a
	# failure nobody could fix, and a red nobody reads hides a real
	# reintroduction. Filter by PATH PREFIX rather than --exclude-dir, which
	# matches a directory base name at any depth and would also skip, say,
	# docs/guide/log/.
	if [ "$rc" -eq 0 ]; then
		matches="$(printf '%s\n' "$matches" | grep -Ev "^$docs_dir/(issues|log|reviews)/")" || rc=1
	fi
	case "$rc" in
		0)
			# Match(es) found — the banned symbol is present.
			printf '%s\n' "$matches" >&2
			echo "ERROR ($docs_dir/): \"$phrase_symbol\" does not exist. The managed-binary" >&2
			echo "       SSOT is the unexported \`managed\` slice in" >&2
			echo "       pkg/upgrade/manifest/manifest.go; callers use the exported" >&2
			echo "       accessors All() / Names() / LockstepNames()." >&2
			status=1
			;;
		1)
			# No match — the good case.
			;;
		*)
			# grep itself failed (exit >=2).
			echo "ERROR: grep failed (exit $rc) scanning $docs_dir/ for" >&2
			echo "       \"$phrase_symbol\" — cannot verify the phrase-2 guard." >&2
			status=1
			;;
	esac
fi

if [ "$status" -eq 0 ]; then
	echo "check-upgrade-docs: upgrade/install docs are clean"
fi
exit "$status"
