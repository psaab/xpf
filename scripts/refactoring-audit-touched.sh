#!/usr/bin/env bash
# Changed-set modularity probe (#7253).
#
# Prints one line per audit-eligible file THIS BRANCH changed:
#
#     <base-LOC|-> <head-LOC> <path>
#
# base-LOC is the file's line count at the branch's merge base with the
# base ref; `-` means the file did not exist there (a file the branch
# added). head-LOC is the line count in the WORKING TREE, which is what
# scripts/refactoring-audit.sh measures.
#
# The consumer is pkg/refactoraudit's touched-file gate, which reds when
# one of these files crossed $AUDIT_FLOOR or $AUDIT_REFACTOR_FLOOR
# between the two columns. That gate replaces the freshness half of the
# old TestHeatmapNotStale, which fused two different properties:
#
#   modularity — "a file is growing past the point where it should be
#   split", aimed at the author of the growth and worth interrupting
#   them for; and
#
#   freshness — "the committed global snapshot disagrees with the tree",
#   aimed at whoever merges next, NOT worth interrupting them for, and
#   unable to stay true from authoring to merge on a board that lands
#   several PRs an hour (#7235, #7252, #7254 — #7252 was already stale
#   when it merged).
#
# Nothing here reads docs/refactoring-audit-current.txt. The verdict is a
# function of (changed set, base content, working tree) only, so it is
# reproducible from the branch's own diff and cannot be invalidated by an
# unrelated file growing elsewhere in the tree. Global freshness is the
# refresh job's problem (scripts/refactoring-audit-refresh.sh).
#
# CHANGED-SET MECHANISM AND ITS FAILURE MODE
#
# The changed set is `git diff --name-only <merge-base> --` (plus
# untracked files), where <merge-base> = `git merge-base <base-ref> HEAD`
# and base-ref defaults to origin/master. For tracked renames, the probe
# also reads `git diff --name-status --find-renames=100%` and carries
# the old path into the merge-base lookup; `--name-only` alone would
# lose that ancestry and measure a pure rename as a new file.
# Diffing against the MERGE BASE rather than the base ref tip is what
# keeps master's own commits out of the set: a file master grew after
# this branch forked is not in HEAD, so it is not in the diff, however
# far behind the branch is.
#
# What it gets wrong:
#
#   * A STACKED branch inherits its parent PR's changed set, because the
#     merge base against master is the parent's fork point, not the
#     parent's tip. A crossing caused by the parent reds the child too.
#     Point the child at its parent with XPF_AUDIT_BASE_REF=<parent> (or
#     argv[1]) to get the child's own diff.
#   * After the branch merges origin/master into itself (this project
#     merges rather than rebases), the merge base moves forward, so a
#     crossing MASTER caused is correctly attributed to master and this
#     branch goes silent on it. That is intended — the branch did not
#     cause it — but it means a crossing can be announced to nobody if it
#     first appears in a merge. The refresh job is what records it.
#   * It is a whole-branch view, not a last-commit view: every file the
#     branch ever touched is in the set. That is deliberate. The rejected
#     alternative, diffing HEAD~..HEAD, misses every crossing introduced
#     before the last commit, which is most of them on a multi-commit
#     branch.
#
# When the changed set cannot be determined — no git, no such base ref,
# no common ancestor (a shallow or grafted clone) — this exits non-zero
# with the reason rather than printing an empty set. An empty set reads
# as "nothing crossed", which is the one answer a broken probe must never
# give. Same posture as the rest of pkg/refactoraudit's fixtures, which
# t.Fatal when their source is unreadable.
set -euo pipefail

prog="$(basename "$0")"
die() {
    echo "$prog: $*" >&2
    exit 3
}

ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" ||
    die "not inside a git work tree; the changed set is undeterminable"
cd "$ROOT"

# shellcheck source=scripts/refactoring-audit-lib.sh
. "$ROOT/scripts/refactoring-audit-lib.sh"

# Base ref precedence: argv[1], then $XPF_AUDIT_BASE_REF, then
# origin/master. The override exists for stacked branches and for a
# checkout whose remote is not named origin.
base_ref="${1:-${XPF_AUDIT_BASE_REF:-origin/master}}"

git rev-parse --verify --quiet "${base_ref}^{commit}" >/dev/null ||
    die "base ref '${base_ref}' does not resolve to a commit; fetch it
  (git fetch origin master) or name another with XPF_AUDIT_BASE_REF=<ref>.
  Refusing to print an empty changed set, which would read as 'nothing
  crossed a modularity threshold'."

merge_base="$(git merge-base "$base_ref" HEAD 2>/dev/null)" ||
    die "no common ancestor between '${base_ref}' and HEAD; a shallow or
  grafted clone cannot produce a changed set. Deepen it
  (git fetch --unshallow) or name a reachable base with
  XPF_AUDIT_BASE_REF=<ref>."

# Tracked changes (merge base vs WORKING TREE, so uncommitted growth
# counts too; --diff-filter=d drops deletions, which cannot cross a floor
# upward) plus untracked files, which the generator already measures
# because it walks the working tree. Keep rename ancestry separately:
# --name-only below intentionally remains the changed-path stream, while
# this status stream lets a destination use its source's merge-base blob.
declare -A rename_sources=()
while IFS=$'\t' read -r status old new; do
    case "$status" in
    R100*) rename_sources["$new"]="$old" ;;
    esac
done < <(git diff --name-status --find-renames=100% --diff-filter=d "$merge_base" --)

{
    git diff --name-only --diff-filter=d "$merge_base" --
    git ls-files --others --exclude-standard
} | LC_ALL=C sort -u | while read -r p; do
    audit_is_audited_path "$p" || continue
    [ -f "$p" ] || continue
    base_path="$p"
    if ! git cat-file -e "$merge_base:$base_path" 2>/dev/null; then
        base_path="${rename_sources["$p"]-}"
    fi
    if [ -n "$base_path" ] &&
        git cat-file -e "$merge_base:$base_path" 2>/dev/null; then
        base_loc="$(git show "$merge_base:$base_path" | wc -l)"
    else
        base_loc='-'
    fi
    printf '%s %s %s\n' "$base_loc" "$(audit_loc "$p")" "$p"
done
