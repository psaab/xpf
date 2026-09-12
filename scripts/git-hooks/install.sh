#!/usr/bin/env bash
# install.sh (#9551): install the commit-msg hook into this clone's hooks
# directory, honouring core.hooksPath.
#
# What is installed is a small DELEGATOR that runs scripts/git-hooks/commit-msg
# from the worktree being committed to. Updating the tracked hook therefore
# needs no reinstall, and a worktree that does not have it is not blocked.
#
# Refuses to replace a DIFFERENT existing commit-msg hook, because silently
# overwriting someone's hook is its own defect. Idempotent when the delegator
# is already present.
set -euo pipefail

hooks=$(git rev-parse --git-path hooks)
case "$hooks" in
/*) ;;
*) hooks="$(pwd)/$hooks" ;;
esac
target="$hooks/commit-msg"

# shellcheck disable=SC2016 # the delegator is written out literally; it expands when git runs it
delegator='#!/bin/sh
# Installed by `make install-git-hooks` (#9551). Delegates to the tracked hook
# in the worktree being committed to; a worktree without it is not blocked.
top=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
hook="$top/scripts/git-hooks/commit-msg"
[ -f "$hook" ] || exit 0
exec sh "$hook" "$@"'

mkdir -p "$hooks"
if [ -e "$target" ]; then
	if [ "$(cat "$target")" = "$delegator" ]; then
		echo "install-git-hooks: already installed at $target"
		exit 0
	fi
	echo "install-git-hooks: REFUSING to replace a different existing hook at $target" >&2
	echo "  To chain it, add this line to that hook:" >&2
	# shellcheck disable=SC2016 # printed literally for the operator to paste
	echo '    sh "$(git rev-parse --show-toplevel)/scripts/git-hooks/commit-msg" "$1" || exit $?' >&2
	exit 1
fi
printf '%s\n' "$delegator" >"$target"
chmod +x "$target"
echo "install-git-hooks: installed $target"
