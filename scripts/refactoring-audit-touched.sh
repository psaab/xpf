#!/usr/bin/env bash
# Changed-set modularity probe (#7253).
#
# Prints one line per audit-eligible file THIS BRANCH changed:
#
#     <base-LOC|-> <head-LOC> <path>
#
# base-LOC is the file's line count at the branch's merge base with the
# base ref; for a recognized rename it is the predecessor path's count.
# `-` means the file did not exist at the merge base (a file the branch
# added, copied, or moved in from outside the audit population). head-LOC is
# the line count in the WORKING TREE, which is what
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
# The changed set is a NUL-delimited `git diff --name-status -M90%` stream
# against the merge base (plus NUL-delimited untracked files). Git's
# `R<score>\0<old>\0<new>\0` record carries the predecessor path needed to
# measure a rename from the correct merge-base blob. The destination remains
# the only emitted path: the Go consumer and its three-field row protocol do
# not change.
#
# `-M90%` is deliberate. Bare `-M` uses Git's 50% default and can pair an
# unrelated large file sharing boilerplate, suppressing a real crossing.
# `-M100%` would leave a rename with even one line of growth looking new.
# Rewrites below 90% conservatively degrade to addition/deletion, preserving
# the existing false-positive direction rather than silencing a crossing.
# `diff.renames=true` is explicit so a user's configuration cannot disable
# rename detection or turn it into copy detection; `-C` is never requested.
#
# The changed set still has the same merge-base semantics:
#
#   * A STACKED branch inherits its parent's changed set, because the merge
#     base against master is the parent's fork point. Point the child at its
#     parent with XPF_AUDIT_BASE_REF=<parent> (or argv[1]).
#   * After a branch merges origin/master into itself, the merge base moves
#     forward, so a crossing MASTER caused is correctly attributed to master
#     and this branch goes silent on it. That is intended.
#   * It is a whole-branch view, not a last-commit view: every file the branch
#     ever touched is in the set.
#
# Every path status visible after `--diff-filter=d` is handled: A/C are new,
# M/T/X/B use the same path, R uses its old path only when that source is
# audit-eligible, and D is excluded by the filter. The producer's
# tree-vs-working-tree form reports a conflict as one M row; if a future
# refactor accidentally feeds index-form U+M records, duplicate paths are
# coalesced before measurement so one path cannot emit two rows.
#
# When the changed set cannot be determined — no git, no such base ref,
# no common ancestor (a shallow or grafted clone) — this exits non-zero
# with the reason rather than printing an empty set. An empty set reads
# as "nothing crossed", which is the one answer a broken probe must never
# give. Missing merge-base blobs fall back to `-` with a warning so partial
# or shallow availability does not turn a normal probe into infrastructure
# red; the missing-base-commit case remains a hard error.
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
# because it walks the working tree.
tmp="$(mktemp -d "${TMPDIR:-/tmp}/refactoring-audit-touched.XXXXXX")" ||
    die "cannot create a temporary workspace for the changed set"
trap 'rm -rf "$tmp"' EXIT

tracked="$tmp/tracked"
untracked="$tmp/untracked"
diff_stderr="$tmp/diff-stderr"
rows="$tmp/rows"

if ! git cat-file -e "${merge_base}^{commit}" 2>/dev/null; then
    die "merge-base commit '${merge_base}' is unreadable; deepen or repair
  the checkout before measuring a touched changed set"
fi

if ! git -c diff.renames=true diff --name-status -z -M90% \
    --diff-filter=d "$merge_base" -- >"$tracked" 2>"$diff_stderr"; then
    cat "$diff_stderr" >&2
    die "git diff could not determine the tracked changed set"
fi
cat "$diff_stderr" >&2

if ! git ls-files --others --exclude-standard -z >"$untracked"; then
    die "git ls-files could not determine the untracked changed set"
fi

: >"$rows"
declare -a record_paths=()
declare -A record_status=()
declare -A record_source=()
declare -A consumed_sources=()

add_record() {
    local kind="$1" path="$2" source="${3:-}" existing

    # Deletions are excluded by --diff-filter=d. If a future Git emits one
    # anyway, it cannot cross upward and must not create a duplicate path.
    [ "$kind" = D ] && return 0

    if [[ ${record_status["$path"]+present} ]]; then
        existing="${record_status["$path"]}"
        case "$existing:$kind" in
            U:M)
                # Defensive support for an index-form U+M pair. The actual
                # producer uses git diff <merge-base> and emits M only.
                record_status["$path"]=M
                ;;
            M:U)
                return 0
                ;;
            *)
                die "duplicate status records for path '$path': $existing/$kind"
                ;;
        esac
    else
        record_paths+=("$path")
        record_status["$path"]="$kind"
    fi

    if [ "$kind" = R ]; then
        record_source["$path"]="$source"
        consumed_sources["$source"]=1
    fi
}

parse_tracked() {
    local status path source dest kind
    while :; do
        status=''
        if ! IFS= read -r -d '' status; then
            [ -z "$status" ] && break
            die "truncated NUL-delimited tracked diff status"
        fi
        [[ "$status" =~ ^[ACDMRTUXB][0-9]*$ ]] ||
            die "malformed tracked diff status '$status'"
        kind="${status:0:1}"
        case "$kind" in
            R|C)
                [[ "$status" =~ ^[RC][0-9]*$ ]] ||
                    die "malformed rename/copy status '$status'"
                source=''
                IFS= read -r -d '' source ||
                    die "truncated NUL-delimited ${kind} source path"
                dest=''
                IFS= read -r -d '' dest ||
                    die "truncated NUL-delimited ${kind} destination path"
                [ -n "$source" ] || die "empty ${kind} source path"
                [ -n "$dest" ] || die "empty ${kind} destination path"
                add_record "$kind" "$dest" "$source"
                ;;
            *)
                [ "$status" = "$kind" ] ||
                    die "unexpected score on non-rename status '$status'"
                path=''
                IFS= read -r -d '' path ||
                    die "truncated NUL-delimited $kind path"
                [ -n "$path" ] || die "empty $kind path"
                add_record "$kind" "$path"
                ;;
        esac
    done <"$tracked"
}

parse_untracked() {
    local path
    while :; do
        path=''
        if ! IFS= read -r -d '' path; then
            [ -z "$path" ] && break
            die "truncated NUL-delimited untracked path"
        fi
        [ -n "$path" ] || die "empty untracked path"
        [[ ${record_status["$path"]+present} ]] && continue
        if [[ ${consumed_sources["$path"]+present} ]]; then
            add_record A "$path"
        else
            add_record W "$path"
        fi
    done <"$untracked"
}

emit_touched() {
    local base_path="$1" dest="$2" warn_missing="${3:-0}"
    local base_loc head_loc

    audit_is_audited_path "$dest" || return 0
    [ -f "$dest" ] || return 0
    [[ "$dest" =~ [[:space:]] ]] &&
        die "audited destination path contains whitespace; refusing ambiguous row '$dest'"

    if [ -z "$base_path" ]; then
        base_loc='-'
    elif git cat-file -e "$merge_base:$base_path" 2>/dev/null; then
        if ! base_loc="$(git show "$merge_base:$base_path" | wc -l)"; then
            die "could not count merge-base blob '$base_path'"
        fi
    else
        base_loc='-'
        if [ "$warn_missing" = 1 ]; then
            printf '%s: merge-base blob unavailable for %s; treating it as new\n' \
                "$prog" "$base_path" >&2
        fi
    fi

    if ! head_loc="$(audit_loc "$dest")"; then
        die "could not count working-tree file '$dest'"
    fi
    printf '%s %s %s\n' "$base_loc" "$head_loc" "$dest" >>"$rows" ||
        die "could not stage touched row for '$dest'"
}

parse_tracked
parse_untracked

for path in "${record_paths[@]}"; do
    kind="${record_status["$path"]}"
    case "$kind" in
        A|C)
            emit_touched '' "$path"
            ;;
        W)
            # An untracked path can be new or can already exist at the
            # merge base. A missing same-path blob is expected for a new file.
            emit_touched "$path" "$path"
            ;;
        M|T)
            emit_touched "$path" "$path" 1
            ;;
        X|B)
            printf '%s: Git reported %s for %s; preserving same-path measurement\n' \
                "$prog" "$kind" "$path" >&2
            emit_touched "$path" "$path" 1
            ;;
        R)
            source="${record_source["$path"]}"
            if audit_is_audited_path "$source"; then
                emit_touched "$source" "$path" 1
            else
                # Destination eligibility governs inclusion; an excluded
                # predecessor was never production LOC in this audit.
                emit_touched '' "$path"
            fi
            ;;
        U)
            die "unmerged status for '$path' lacks its matching M record"
            ;;
        D)
            ;;
        *)
            die "unsupported parsed status '$kind' for '$path'"
            ;;
    esac
done

# The row protocol has three whitespace-delimited fields, so destination
# paths were rejected above before the deterministic path sort.
LC_ALL=C sort -u -k3,3 "$rows"
