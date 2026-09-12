#!/usr/bin/env bash
# close_keyword_lint_ci.sh (#9551): the two legs a pull request must pass, in
# the one place both the workflow and the selftest call.
#
#   PR body          -- a scope heading there closed an issue it disclaimed
#   commit messages  -- a negated sentence there closed another
#
# A check that ran only one leg would have caught exactly one of the two
# recorded incidents. Both legs always run, and the verdict is the worse of the
# two: 2 (the lint could not read its input) outranks 1 (a refusal).
#
# Inputs (environment): PR_BODY, PR_NUMBER, BASE_SHA, HEAD_SHA.
# The body arrives through the environment and is never interpolated into a
# command line, so a PR body cannot inject shell.
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
lint="$here/close_keyword_lint.py"

if [ -z "${BASE_SHA:-}" ] || [ -z "${HEAD_SHA:-}" ]; then
	echo "close_keyword_lint_ci.sh: BASE_SHA and HEAD_SHA are both required" >&2
	exit 2
fi

printf '%s' "${PR_BODY-}" | python3 "$lint" --source "PR ${PR_NUMBER:-?} body" -
body_rc=$?

python3 "$lint" --commits "${BASE_SHA}..${HEAD_SHA}"
commits_rc=$?

if [ "$body_rc" -ge 2 ] || [ "$commits_rc" -ge 2 ]; then
	exit 2
fi
if [ "$body_rc" -ne 0 ] || [ "$commits_rc" -ne 0 ]; then
	exit 1
fi
exit 0
