#!/usr/bin/env bash
#
# #4555 acceptance harness: prove the IPv6 extension-header parity guards
# actually fire, by mutating the shim's walk and observing the guards red.
#
# Committed deliberately. The mutation rows in the PR body and _Log.md are only
# evidence if the procedure that produced them can be audited — ordering, return
# codes, restore verification and signal handling all change what the rows mean.
# Prose describing a harness is not a harness.
#
# EVERY CHECK MUST BE ABLE TO OBSERVE THE THING IT REPORTS ON.
#
# Review found the same defect three times in this one file: a probe that
# reports success without having observed anything. The build gate ran
# `cargo build`, which never compiles the file being mutated, so a mutation
# that did not even parse scored as "the guard fired". The row's per-test
# columns were decorative — deleting BOTH negative-control tests left every row
# printing an empty column and the script still exited PASS, because
# `cargo test <filter matching nothing>` exits 0 with `0 passed` and no
# Go-style `[no tests to run]` marker. And the "first divergence" extractor's
# character class excluded `{` and `:`, so once the assertion text changed it
# matched nothing and every RED row printed no reason at all.
#
# So each check below closes its own path to vacuous success, and the two that
# were previously inoperative are DEMONSTRATED by preflights rather than
# asserted:
#
#   P1  a deliberate syntax error in the mutated file must make the BUILD gate
#       fail. If it does not, the build gate does not compile that file and no
#       row it prints can distinguish an assertion from a compile error.
#   P2  a filter matching nothing must be REPORTED AS MISSING by the same
#       per-test extractor the rows use — not scored as a pass.
#
# Four properties, each learned from a failure of an earlier version:
#
#   1. EXCLUSIVE LOCK, at a fixed path. Two concurrent runs mutate the same file
#      and interleave their restores; one run's row then describes the other
#      run's tree. The lock used to live under ${TMPDIR}, which this repo
#      routinely varies, so two runs took two different locks and serialised
#      nothing.
#   2. GREEN BASELINE SELF-CHECK (row 0), plus a VERIFIED-BEFORE-CAPTURED
#      baseline. If the tree is not clean before the first mutation, every later
#      row is void. An earlier run was killed mid-mutation, the next run
#      captured the mutated tree as its "pristine" copy, and reported a clean
#      tree as failing. Passing tests are NOT tree cleanliness: a mutation the
#      guards do not detect would be captured as GOLD and restored as
#      "pristine", so the file is compared against git as well — BEFORE the
#      capture, and refusing to run at all when git cannot answer.
#
#      Scope, precisely, because an earlier revision of this comment said
#      "a tree-cleanliness check" and meant something narrower: exactly ONE
#      path is compared against git, ${WALK_REL}, because that is the file this
#      script OVERWRITES and restores. The guard tests and the negative
#      controls are NOT compared against git; they are covered BEHAVIOURALLY
#      instead — row 0 requires them green on the unmutated tree (so a locally
#      broken or unconditionally-red guard aborts the run) and the NEG-CTL row
#      requires them to SURVIVE a semantically null edit (so a guard rewritten
#      to red on any change fails too). Neither of those is a claim that the
#      working tree matches HEAD.
#   3. RESTORE ON EXIT/INT/TERM, VERIFIED. A trap cannot catch SIGKILL, so the
#      trap is not the safety property — property 2 is. The trap narrows the
#      window; the `cmp` is what proves the restore happened.
#   4. EVERY ROW CARRIES AN EXPECTATION. A row that must RED and a row that must
#      SURVIVE are both checked, so a harness that reds unconditionally fails
#      just as loudly as one that never reds. The NEG-CTL row is a semantically
#      null edit to the mutated file: it must survive, which is what separates
#      "the guard binds this BEHAVIOUR" from "the guard noticed the file
#      changed". Rows are named, not numbered, in this prose — inserting a
#      mutation renumbers every row after it, and a comment citing a stale
#      number is the same defect in miniature as a check citing prose.
#   5. ONE MUTATION PER ROW, and one arm per row where an edit could be
#      applied to several. A row that mutates two arms at once scores RED on
#      either one reding, so it cannot support a claim about both.
#
# Usage:  test/mutation/shim-ext-parity-acceptance.sh
# Requires: cargo + the pinned toolchain, python3; no root, no cluster, no
# network.
# Runtime: ~5 min per row, and there are 18 rows plus two preflights — the
# mutated file is `#[path]`-included into the userspace-dp test binary, so
# every row is a full release rebuild of that crate. Budget an hour and a half.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WALK="${REPO}/userspace-xdp/src/ipv6_ext_walk.rs"
WALK_REL="userspace-xdp/src/ipv6_ext_walk.rs"
GOLD="$(mktemp -t ipv6_ext_walk.gold.XXXXXX)"
# Fixed path, NOT ${TMPDIR}-derived: this repo documents TMPDIR=/tmp as a
# workaround for unix-socket tests, so a TMPDIR-scoped lock is routinely two
# different locks.
LOCK="/var/worktrees/.cache/tmpdir/xpf-4555-acceptance.lock"
: "${CARGO_TARGET_DIR:=/var/worktrees/.cache/cargo-4555-acceptance}"
export CARGO_TARGET_DIR
export TMPDIR="${TMPDIR:-/var/worktrees/.cache/tmpdir}"

# The tests this harness scores. A name that does not appear in cargo's output
# is a HARNESS ERROR, never a pass — see P2.
TEST_PATH="afxdp::frame::tests_shim_ext_parity"
GUARDS=(
  shim_walk_and_userspace_walk_agree_over_a_corpus
  shim_is_not_more_permissive
  shim_ipv6_ext_walk_matches_userspace_walker
)
# Negative controls: they assert nothing about any shim-side behaviour the
# mutations below perturb, so they must stay `ok` in EVERY row. A row where a
# control moved is a row whose guard columns are not attributable.
CONTROLS=(
  shim_walk_corpus_negative_control
  shim_ext_parity_negative_control_unchanged_classifications
)
ALL_TESTS=("${GUARDS[@]}" "${CONTROLS[@]}")

exec 9>"${LOCK}"
flock -n 9 || { echo "another acceptance run holds ${LOCK}; refusing to interleave"; exit 1; }

# --- preconditions: the baseline is VERIFIED BEFORE IT IS CAPTURED -----------
#
# ORDER IS THE PROPERTY, and it used to be wrong. An earlier revision captured
# GOLD at the top of the script and consulted git 138 lines later, so on any
# tree git could not speak for, the capture had already happened: the script
# printed "UNVERIFIED", accepted whatever bytes were on disk as the pristine
# copy, ran every row against them, and "restored" that state at the
# end. Measured by replaying the real capture-then-precondition sequence
# against an archive with no `.git`: it printed UNVERIFIED and continued with a
# `(len+1)*8 -> (len+1)*16` mutation installed as GOLD.
#
# So a baseline that CANNOT be verified now ABORTS. "We could not check" is not
# "it is fine": this file exists because a probe that reports success without
# having observed anything is the defect that keeps regrowing in it, and a
# harness cannot make an exception of itself.
abort() { echo "ABORT: $*" >&2; rm -f "${GOLD}"; exit 1; }

git -C "${REPO}" rev-parse --is-inside-work-tree >/dev/null 2>&1 || abort \
"${REPO} is not a git work tree (or GIT_DIR points elsewhere), so the pristine copy of
       ${WALK_REL} cannot be checked against a commit. Every row would run against whatever
       bytes are on disk — including a mutation left behind by a killed run, which would be
       captured as GOLD and restored as 'pristine' at the end. Run this from a checkout."

# `diff --quiet HEAD --`, NOT `diff --quiet --`. The latter compares the
# worktree against the INDEX, so a STAGED mutation is "no difference" and sails
# through a check whose own abort text spells out the consequence: the mutation
# is captured as GOLD, restored as pristine, and the whole matrix runs against a
# poisoned baseline. `HEAD` compares against the commit, which is what "matches
# git HEAD" claims and what the property needs.
git -C "${REPO}" diff --quiet HEAD -- "${WALK}" || abort \
"${WALK_REL} differs from git HEAD (staged or unstaged). A mutation the guards do NOT
       detect would be captured as the pristine copy and restored as such; passing tests
       are not tree cleanliness."

# `git diff` believes the INDEX for a path flagged assume-unchanged (a lowercase
# `ls-files -v` tag) or skip-worktree (`S`) — it does not stat the file — so a
# MUTATED walker compares equal to HEAD and the check above prints a clean
# result it did not establish. Measured: `git update-index --assume-unchanged`
# flipped `diff --quiet HEAD` from rc 1 to rc 0 with the `* 16` mutation still
# in the file, and the precondition then reported "matches git HEAD (index
# included)". An empty tag (the path is untracked) aborts for the same reason.
WALK_INDEX_FLAG="$(git -C "${REPO}" ls-files -v -- "${WALK}" 2>/dev/null | cut -c1)"
[ "${WALK_INDEX_FLAG}" = "H" ] || abort \
"${WALK_REL} carries the git index flag '${WALK_INDEX_FLAG:-<untracked>}', want 'H'.
       assume-unchanged and skip-worktree make git diff ignore the file's real bytes, so the
       HEAD comparison above cannot see a mutation and its clean result means nothing.
       Clear it with:
         git update-index --no-assume-unchanged --no-skip-worktree ${WALK_REL}"

echo "PRECONDITION: ${WALK_REL} matches git HEAD (index included, no assume-unchanged/skip-worktree)"

build_log="$(mktemp)"; test_log="$(mktemp)"; pysub="$(mktemp -t xpf4555sub.XXXXXX)"
cp "${WALK}" "${GOLD}"
cleanup() {
  cp "${GOLD}" "${WALK}" || echo "RESTORE FAILED: ${GOLD} -> ${WALK}" >&2
  rm -f "${GOLD}" "${build_log}" "${test_log}" "${pysub}"
}
trap cleanup EXIT INT TERM

fail() { echo "HARNESS ERROR: $*" >&2; exit 3; }

# Textual substitution that ASSERTS it matched. A `sed -i` that silently
# matches nothing runs the row against an UNMUTATED tree and reports
# "MUTATION SURVIVED", attributing a harness failure to the guard.
cat >"${pysub}" <<'PY'
import sys
path, want = sys.argv[1], int(sys.argv[2])
parts = sys.stdin.read().split("\n@@@\n")
if len(parts) != 2:
    sys.exit("mutation spec must be OLD then a lone @@@ line then NEW")
old, new = parts[0], parts[1]
if new.endswith("\n"):
    new = new[:-1]
if old == new:
    sys.exit("mutation is a no-op: OLD and NEW are identical")
s = open(path).read()
got = s.count(old)
if got != want:
    sys.exit("mutation target found %d times, expected %d:\n%s" % (got, want, old))
open(path, "w").write(s.replace(old, new))
PY
py_sub() { python3 "${pysub}" "${WALK}" "$1"; }
spec() { printf '%s\n@@@\n%s\n' "$1" "$2"; }

# --- the build gate -------------------------------------------------------
#
# `cargo test --no-run` and NOT `cargo build`. The mutated file enters the tree
# only through `#[cfg(test)] mod tests_shim_ext_parity` ->
# `#[path = "../../../../userspace-xdp/src/ipv6_ext_walk.rs"] mod shim_walk`,
# and `cargo build` sets no `cfg(test)`, so it compiles neither that file nor
# the userspace-xdp crate. P1 demonstrates that this command does.
#
# `9>&-` closes the lock fd in the child. Without it cargo and rustc INHERIT it,
# so a run killed mid-build leaves its lock held by orphaned compiler processes
# and the next run refuses to start against a lock nothing is using. Found by
# doing exactly that.
build_gate() {
  ( cd "${REPO}/userspace-dp" && cargo test --release --bin xpf-userspace-dp --no-run ) \
    >"${build_log}" 2>&1 9>&-
}

test_gate() {
  ( cd "${REPO}/userspace-dp" && cargo test --release --bin xpf-userspace-dp "$@" ) \
    >"${test_log}" 2>&1 9>&-
}

# `ok`, `FAILED`, `DUP`, or empty when the named test did not run. Anchored on
# the full module path, so no substring of another test's name satisfies it.
result_of() {
  local n
  n="$(grep -cE "^test ${TEST_PATH}::$1 \.\.\. (ok|FAILED)\$" "${test_log}")"
  if [ "${n}" -gt 1 ]; then echo DUP; return; fi
  sed -nE "s/^test ${TEST_PATH}::$1 \.\.\. (ok|FAILED)\$/\1/p" "${test_log}"
}

# A RED row must say WHY. Specific pattern first, generic panic context as a
# fallback; the caller asserts the result is non-empty. An extractor that
# silently matches nothing is the exact defect this file keeps regrowing.
explain() {
  local e
  e="$(grep -m1 -oE '(\[l3=[0-9]+\] |next-header [0-9]+: )[^"]*' "${test_log}")"
  if [ -z "${e}" ]; then
    # #6920: the thread-id is OPTIONAL because the toolchain started printing
    # one. Rust 1.96 emits `thread 'NAME' (307669) panicked at ...`, so the
    # previous `^thread '.*' panicked` — which required `panicked` immediately
    # after the closing quote — stopped matching, and any row whose mutation
    # PANICS instead of tripping an assertion had no extractable reason. That
    # is not cosmetic: `fail()` exits the whole run, so row 7 (FRAGMENT read
    # 8 -> 2, which indexes out of bounds) aborted the harness before rows
    # 8-21 ran. Third time this file's reason-extractor has rotted against
    # text it does not control; the header documents the other two.
    e="$(grep -m1 -A3 -E "^thread '.*' (\([0-9]+\) )?panicked" "${test_log}" | tr '\n' ' ')"
  fi
  printf '%s' "${e}"
}

# RETURNS 0 green, 1 red (a guard assertion fired), 2 build failure, and 3 for a
# row that cannot be attributed to the mutation because a negative control moved
# — see the `return 3` below for why a moved control must not share a code with
# a genuine red. Separately, `fail()` EXITS 3 on a harness error; that ends the
# whole run, where a `return 3` is one row that row() scores as failed.
run() {
  local label="$1"
  build_gate
  local brc=$?
  if [ ${brc} -ne 0 ]; then
    printf '%-56s BUILD rc=%-3d <-- FALSE RED, not an assertion\n' "${label}" "${brc}"
    grep -m2 -E '^error' "${build_log}" | sed 's/^/      /'
    return 2
  fi
  test_gate tests_shim_ext_parity
  local trc=$?

  local -a cols=()
  local -a bad=()
  local t r
  for t in "${ALL_TESTS[@]}"; do
    r="$(result_of "${t}")"
    case "${r}" in
      ok|FAILED) ;;
      *) bad+=("${t}=${r:-MISSING}") ;;
    esac
    cols+=("${r:-MISSING}")
  done
  if [ ${#bad[@]} -ne 0 ]; then
    printf '%-56s build=%d rc=%-3d | %s\n' "${label}" "${brc}" "${trc}" "${cols[*]}"
    fail "no usable result for: ${bad[*]}. cargo exits 0 on a filter that matches nothing, so an absent test is never a pass."
  fi

  printf '%-56s build=%d rc=%-3d | corpus=%-6s permissive=%-6s facts=%-6s CONTROL=%s/%s\n' \
    "${label}" "${brc}" "${trc}" "${cols[0]}" "${cols[1]}" "${cols[2]}" "${cols[3]}" "${cols[4]}"

  # The controls must be untouched by every shim-side mutation, or the guard
  # columns beside them are not attributable to the mutation.
  local i
  # Return 3, NOT 1. A moved control and a genuine guard red are different
  # outcomes and must not share an exit code: row() maps `red:1` to success, so
  # returning 1 here scored a row whose control had broken as a PASS while
  # printing "not attributable" directly above it. The harness would have
  # reported a clean matrix over a result that proved nothing.
  for i in 3 4; do
    if [ "${cols[$i]}" != "ok" ]; then
      echo "      ^^ CONTROL ${ALL_TESTS[$i]} = ${cols[$i]} — this row's guard columns are not attributable"
      return 3
    fi
  done

  if [ ${trc} -ne 0 ]; then
    local why; why="$(explain)"
    if [ -z "${why}" ]; then
      # #6920: DO NOT abort here. This used to call `fail()`, which exits the
      # whole run — so a rot in a DIAGNOSTIC path destroyed the entire matrix
      # rather than one row's reason column. That is exactly what happened:
      # row 7 panics instead of asserting, the panic fallback stopped matching
      # when the toolchain began printing thread ids, and rows 8-21 silently
      # never ran. A gate that reports on a third of its own subject is worse
      # than one that reports a gap.
      #
      # The row is still SCORED — its guard columns are what prove the guards
      # fire, and the reason text is diagnostics. The miss is counted and the
      # run FAILS at the end with a full accounting, so the rot stays loud
      # while the matrix stays complete.
      echo "      first divergence: <UNAVAILABLE — extractor matched nothing; see the end-of-run accounting>"
      extractor_misses=$((extractor_misses + 1))
      extractor_miss_rows+=("${label}")
    else
      echo "      first divergence: ${why}"
    fi
    return 1
  fi
  return 0
}

echo "=== #4555 acceptance: mutate the shim walk, the guards must red ==="

# --- P1: the build gate compiles the file this harness mutates ------------
# Without this, every row's build column is a hardcoded claim. Measured, not
# asserted: a file that is not valid Rust must make the gate fail.
printf 'P1  build gate observes %s ... ' "${WALK_REL}"
printf '\nthis is not rust\n' >>"${WALK}"
if build_gate; then
  cp "${GOLD}" "${WALK}"
  fail "the build gate SUCCEEDED with a syntax error in ${WALK_REL}. It does not compile the mutated file, so it cannot distinguish an assertion from a compile failure — which is the only thing it exists to do."
fi
cp "${GOLD}" "${WALK}"
cmp -s "${GOLD}" "${WALK}" || fail "restore after P1 did not reproduce the pristine file"
echo "yes (build failed on a deliberate syntax error)"

# --- P2: a test that does not run is reported MISSING, not ok -------------
# `cargo test <filter matching nothing>` exits 0 and prints `0 passed`. The
# per-test extractor must therefore report absence, or every column is
# decorative and a vacuous run scores as a pass.
printf 'P2  a vacuous run is reported MISSING ... '
test_gate xpf_4555_no_such_test_name
vac_rc=$?
[ ${vac_rc} -eq 0 ] || fail "expected a filter matching nothing to exit 0, got ${vac_rc}; P2 no longer demonstrates what it claims"
for t in "${ALL_TESTS[@]}"; do
  [ -z "$(result_of "${t}")" ] || fail "the per-test extractor reported a result for ${t} in a run that executed no tests"
done
echo "yes (cargo exit 0, all ${#ALL_TESTS[@]} columns MISSING)"

# --- row 0: green baseline ------------------------------------------------
if ! run "0. GREEN [baseline self-check]"; then
  echo "ABORT: baseline is not green. Every row after this would be meaningless."
  exit 1
fi

# --- mutation targets -----------------------------------------------------
GENERIC_ARM='            EH_CLASS_GENERIC => {
                let opt = unsafe { read_bytes(data, data_end, offset as usize, 2) }?;
                protocol = opt[0];
                offset = offset.checked_add(((opt[1] as u16) + 1) * 8)?;
                unsafe { read_bytes(
                    data,
                    data_end,
                    l3_offset as usize,
                    (offset - l3_offset) as usize,
                ) }?;
            }'
AUTH_ARM='            EH_CLASS_AUTH => {
                let opt = unsafe { read_bytes(data, data_end, offset as usize, 2) }?;
                protocol = opt[0];
                offset = offset.checked_add(((opt[1] as u16) + 2) * 4)?;
                unsafe { read_bytes(
                    data,
                    data_end,
                    l3_offset as usize,
                    (offset - l3_offset) as usize,
                ) }?;
            }'
FRAG_READ='                let frag = unsafe { read_bytes(data, data_end, offset as usize, 8) }?;'
FRAG_ADV='                offset = offset.checked_add(mem::size_of::<FragHdr>() as u16)?;'
LOOP_HEAD='    for _ in 0..MAX_EXT_HDRS {'

# #6920: THE TWO DIMENSIONS #4555 ACTUALLY DELIVERED.
#
# Every row above perturbs advance arithmetic, revalidation, the fragment read,
# the L3 base or a loop statement. None of them touches `MAX_EXT_HDRS` or
# `eh_class` — and those two ARE the deliverable: #4555 reached parity by
# raising the resolvable chain length to 7 AND widening the generic arm to the
# five #4517 types (Mobility 135, HIP 139, Shim6 140, experimental 253/254).
#
# `LOOP_HEAD` above names the bound, but only as an anchor for the
# statement-insertion row — mutating the text around a constant is not
# mutating the constant. So the artifact offered as "the guards fire" did not
# exercise either half of what shipped. The guards were independently
# confirmed to bind; this closes the EVIDENCE gap, not an unbound guard.
MAX_HDRS_DECL='pub const MAX_EXT_HDRS: usize = 7;'
MAX_HDRS_6="${MAX_HDRS_DECL/= 7;/= 6;}"
MAX_HDRS_8="${MAX_HDRS_DECL/= 7;/= 8;}"

# The generic arm with the five #4517 types removed — the pre-#4555 view.
EH_GENERIC_ARM='        NEXTHDR_HOP
        | NEXTHDR_ROUTING
        | NEXTHDR_DEST
        | NEXTHDR_MOBILITY
        | NEXTHDR_HIP
        | NEXTHDR_SHIM6
        | NEXTHDR_EXP1
        | NEXTHDR_EXP2 => EH_CLASS_GENERIC,'
EH_GENERIC_NARROW='        NEXTHDR_HOP | NEXTHDR_ROUTING | NEXTHDR_DEST => EH_CLASS_GENERIC,'

# Quoted patterns, so bash treats them literally rather than as globs.
GENERIC_ADV16="${GENERIC_ARM/"+ 1) * 8"/"+ 1) * 16"}"
GENERIC_REVAL_M1="${GENERIC_ARM/"(offset - l3_offset) as usize"/"(offset - l3_offset - 1) as usize"}"
AUTH_ADV8="${AUTH_ARM/"+ 2) * 4"/"+ 2) * 8"}"
AUTH_REVAL_M1="${AUTH_ARM/"(offset - l3_offset) as usize"/"(offset - l3_offset - 1) as usize"}"
FRAG_READ_7="${FRAG_READ/", 8) }?;"/", 7) }?;"}"
FRAG_READ_2="${FRAG_READ/", 8) }?;"/", 2) }?;"}"
# The revalidation's BASE offset, PER ARM. `${var/pat/rep}` replaces the first
# match, which inside a single arm is that arm's `l3_offset as usize,` line —
# `offset as usize, 2)` on the read above it does not contain the `l3_` prefix.
GENERIC_REVAL_L3_0="${GENERIC_ARM/"l3_offset as usize,"/"0usize,"}"
AUTH_REVAL_L3_0="${AUTH_ARM/"l3_offset as usize,"/"0usize,"}"
# A real edit that compiles and changes nothing observable — see property 4.
GENERIC_RENAMED="${GENERIC_ARM//opt/hdr}"
# Drop the whole post-advance revalidation call from an arm.
drop_reval() {
  printf '%s' "$1" | grep -v \
    -e '^                unsafe { read_bytes($' \
    -e '^                    data,$' \
    -e '^                    data_end,$' \
    -e '^                    l3_offset as usize,$' \
    -e '^                    (offset - l3_offset) as usize,$' \
    -e '^                ) }?;$'
}
GENERIC_NO_REVAL="$(drop_reval "${GENERIC_ARM}")"
AUTH_NO_REVAL="$(drop_reval "${AUTH_ARM}")"
LOOP_HEAD_GUARDED="${LOOP_HEAD}
        if offset > 200 {
            break;
        }"

m_max_hdrs_6()           { spec "${MAX_HDRS_DECL}"  "${MAX_HDRS_6}"        | py_sub 1; }
m_max_hdrs_8()           { spec "${MAX_HDRS_DECL}"  "${MAX_HDRS_8}"        | py_sub 1; }
m_eh_class_narrow()      { spec "${EH_GENERIC_ARM}" "${EH_GENERIC_NARROW}" | py_sub 1; }
m_generic_advance()      { spec "${GENERIC_ARM}"  "${GENERIC_ADV16}"      | py_sub 1; }
m_generic_reval_delete() { spec "${GENERIC_ARM}"  "${GENERIC_NO_REVAL}"   | py_sub 1; }
m_generic_reval_minus1() { spec "${GENERIC_ARM}"  "${GENERIC_REVAL_M1}"   | py_sub 1; }
m_auth_advance()         { spec "${AUTH_ARM}"     "${AUTH_ADV8}"          | py_sub 1; }
m_auth_reval_delete()    { spec "${AUTH_ARM}"     "${AUTH_NO_REVAL}"      | py_sub 1; }
m_auth_reval_minus1()    { spec "${AUTH_ARM}"     "${AUTH_REVAL_M1}"      | py_sub 1; }
m_frag_read_2()          { spec "${FRAG_READ}"    "${FRAG_READ_2}"        | py_sub 1; }
m_frag_read_7()          { spec "${FRAG_READ}"    "${FRAG_READ_7}"        | py_sub 1; }
m_stmt_outside_match()   { spec "${LOOP_HEAD}"    "${LOOP_HEAD_GUARDED}"  | py_sub 1; }
m_semantically_null()    { spec "${GENERIC_ARM}"  "${GENERIC_RENAMED}"    | py_sub 1; }
# The revalidation's BASE offset stops accounting for l3. Bit-identical at
# l3 = 0 — the only value the corpus used to walk at — and a fail-open of
# exactly l3 bytes at the 14 and 18 the shim actually passes.
#
# ONE ROW PER ARM, deliberately. A single row mutating BOTH arms at once
# requires only ONE guard failure to score RED, so the GENERIC arm reding
# satisfies it while AUTH coverage has degenerated to nothing — the row's
# "both arms" label would then be a claim the row cannot support. Split, each
# row is attributable to the arm it names.
m_generic_reval_l3_zero() { spec "${GENERIC_ARM}" "${GENERIC_REVAL_L3_0}" | py_sub 1; }
m_auth_reval_l3_zero()    { spec "${AUTH_ARM}"    "${AUTH_REVAL_L3_0}"    | py_sub 1; }

# --- DATA-KEYED mutations (rows 12-15) ------------------------------------
#
# Every mutation above perturbs an arm UNIFORMLY, which is the family two
# boundary witnesses at distinct declared lengths can exclude. These four are
# keyed on a SINGLE data value, so they are invisible at every other value and
# no sampled corpus excludes them. They are here because they were GREEN before
# the corpus gained its exhaustive dimension sweeps (floor 7): the generic arm
# sampled 5 declared lengths of 256, AUTH 3 of 256, the Fragment `reserved`
# byte 1 of 256, and every chain in the corpus declared TCP as its terminal so
# the byte an extension header CARRIES took 4 values of 256.
#
# All four change real packet classification, so a row that stops reding here
# means the sweep it depends on has been narrowed, not that the mutation became
# harmless.
GENERIC_ADV_AT_4="${GENERIC_ARM/"+ 1) * 8)?;"/"+ 1) * 8 + if opt[1] == 4 { 8 } else { 0 })?;"}"
AUTH_ADV_AT_2="${AUTH_ARM/"+ 2) * 4)?;"/"+ 2) * 4 + if opt[1] == 2 { 4 } else { 0 })?;"}"
FRAG_ADV_RESERVED="${FRAG_ADV/"as u16)?;"/"as u16 - if frag[1] != 0 { 1 } else { 0 })?;"}"
# The carried next-header, corrupted for ONE value: UDP (17) is propagated as
# TCP (6). Every session keyed off a UDP-over-extension-header flow would be
# built with the wrong protocol.
GENERIC_NEXT_UDP="${GENERIC_ARM/"protocol = opt[0];"/"protocol = if opt[0] == 17 { 6 } else { opt[0] };"}"

# The revalidation skipped for ONE MEMBER of the generic class. Eight
# next-header values share that `match` arm; before the per-member boundary
# witnesses the arm's bound was exercised at DestOpt only, so this was GREEN —
# a fail-open of exactly the shape row 2 catches, hidden behind a next-header
# check. `protocol` is reassigned inside the arm, so the entering value is
# captured first.
GENERIC_REVAL_SKIP_ROUTING="${GENERIC_ARM/"                let opt = unsafe { read_bytes"/"                let entered = protocol;
                let opt = unsafe { read_bytes"}"
GENERIC_REVAL_SKIP_ROUTING="${GENERIC_REVAL_SKIP_ROUTING/"                unsafe { read_bytes(
                    data,
                    data_end,
                    l3_offset as usize,
                    (offset - l3_offset) as usize,
                ) }?;"/"                if entered != 43 {
                    unsafe { read_bytes(
                        data,
                        data_end,
                        l3_offset as usize,
                        (offset - l3_offset) as usize,
                    ) }?;
                }"}"

m_generic_adv_at_len4()  { spec "${GENERIC_ARM}" "${GENERIC_ADV_AT_4}"    | py_sub 1; }
m_generic_reval_routing() { spec "${GENERIC_ARM}" "${GENERIC_REVAL_SKIP_ROUTING}" | py_sub 1; }
m_auth_adv_at_len2()     { spec "${AUTH_ARM}"    "${AUTH_ADV_AT_2}"       | py_sub 1; }
m_frag_adv_on_reserved() { spec "${FRAG_ADV}"    "${FRAG_ADV_RESERVED}"   | py_sub 1; }
m_generic_next_udp()     { spec "${GENERIC_ARM}" "${GENERIC_NEXT_UDP}"    | py_sub 1; }

# --- the matrix -----------------------------------------------------------
#
# Rows are ACCOUNTED, not just aggregated into a final PASS/FAIL. A bare
# "acceptance PASS" cannot be audited against the matrix it claims to have run:
# a row silently dropped from the list below produces the same line as a row
# that passed. The tail prints passed-of-total with every row's name and
# outcome, so the evidence quoted in a PR body is checkable against the script.
rc=0
rows_total=0
rows_passed=0
# #6920: rot accounting. A run that scores fewer rows than it declared, or that
# scores a row without being able to say why it red, is a run whose result must
# not read as clean.
extractor_misses=0
declare -a extractor_miss_rows=()
declare -a row_names=()
declare -a row_outcomes=()

row() {  # row <mutator> <red|survive> <label>
  local fn="$1" want="$2" label="$3"
  cp "${GOLD}" "${WALK}"
  "${fn}" || fail "mutator ${fn} did not apply"
  cmp -s "${GOLD}" "${WALK}" && fail "mutator ${fn} left the file unchanged"
  run "${label}"
  local got=$?
  local outcome
  rows_total=$((rows_total + 1))
  case "${want}:${got}" in
    red:1)     outcome="PASS (red as required)"; rows_passed=$((rows_passed + 1)) ;;
    survive:0) outcome="PASS (survived as required)"; rows_passed=$((rows_passed + 1)) ;;
    red:0)     outcome="FAIL (mutation SURVIVED)"
               echo "      ^^ MUTATION SURVIVED — the guards do not bind this edit"; rc=1 ;;
    survive:1) outcome="FAIL (red on a null edit)"
               echo "      ^^ RED ON A SEMANTICALLY NULL EDIT — this harness reds on change, not on behaviour"; rc=1 ;;
    *:2)       outcome="FAIL (build)"
               echo "      ^^ BUILD FAILED — this row proves nothing about the guards"; rc=1 ;;
    *:3)       outcome="FAIL (control moved)"
               echo "      ^^ CONTROL MOVED — this row proves nothing about the guards"; rc=1 ;;
    *)         outcome="FAIL (outcome ${got} for ${want})"
               echo "      ^^ unexpected outcome ${got} for expectation ${want}"; rc=1 ;;
  esac
  row_names+=("${label}")
  row_outcomes+=("${outcome}")
}

row m_generic_advance       red     " 1. GENERIC advance *8 -> *16"
row m_generic_reval_delete  red     " 2. GENERIC post-advance revalidation DELETED"
row m_generic_reval_minus1  red     " 3. GENERIC revalidation length - 1"
row m_auth_advance          red     " 4. AUTH advance *4 -> *8"
row m_auth_reval_delete     red     " 5. AUTH post-advance revalidation DELETED"
row m_auth_reval_minus1     red     " 6. AUTH revalidation length - 1"
row m_frag_read_2           red     " 7. FRAGMENT read 8 -> 2"
row m_frag_read_7           red     " 8. FRAGMENT read 8 -> 7"
row m_generic_reval_l3_zero red     " 9. GENERIC revalidation base l3_offset -> 0"
row m_auth_reval_l3_zero    red     "10. AUTH revalidation base l3_offset -> 0"
row m_stmt_outside_match    red     "11. statement inside the loop, outside the match"
row m_generic_adv_at_len4   red     "12. GENERIC advance +8 ONLY at HdrExtLen == 4"
row m_auth_adv_at_len2      red     "13. AUTH advance +4 ONLY at HdrExtLen == 2"
row m_frag_adv_on_reserved  red     "14. FRAGMENT advance 8 -> 7 ONLY when reserved != 0"
row m_generic_next_udp      red     "15. GENERIC carried next-header UDP propagated as TCP"
row m_generic_reval_routing red     "16. GENERIC revalidation skipped ONLY for Routing(43)"
# #6920: the two dimensions #4555 delivered. Expected reds below are MEASURED
# (the hostile gate on PR #6655 ran all three directly), not predicted.
#
# Row 19 is the one that matters most: it is the fail-OPEN direction — the shim
# resolving a chain userspace REFUSES — which is what would bite if someone
# later raised the cap without re-checking the verifier. The other two are
# fail-closed drift, where the shim gives up on a chain userspace still
# resolves, and a fast-path miss is the benign outcome.
row m_max_hdrs_6            red     "17. MAX_EXT_HDRS 7 -> 6 (fail-closed drift)"
row m_eh_class_narrow       red     "18. eh_class generic narrowed to {0,43,60} (pre-#4517)"
row m_max_hdrs_8            red     "19. MAX_EXT_HDRS 7 -> 8 (FAIL-OPEN direction)"
row m_semantically_null     survive "20. NEG-CTL semantically null rename (must survive)"

cp "${GOLD}" "${WALK}"
cmp -s "${GOLD}" "${WALK}" || fail "restore did not reproduce the pristine file"
rows_total=$((rows_total + 1))
if run "21. RESTORED"; then
  rows_passed=$((rows_passed + 1))
  row_names+=("21. RESTORED"); row_outcomes+=("PASS (green again)")
else
  rc=1
  row_names+=("21. RESTORED"); row_outcomes+=("FAIL (tree not green after restore)")
fi

echo "--- row accounting ---------------------------------------------------"
for i in "${!row_names[@]}"; do
  printf '%-56s %s\n' "${row_names[$i]}" "${row_outcomes[$i]}"
done
echo "rows passed: ${rows_passed}/${rows_total} (plus row 0 baseline and preflights P1/P2)"

# #6920: COMPLETION CHECK. The matrix must score every row it declared. Counting
# `row ... ` invocations from this file itself, rather than a hardcoded number,
# so adding a row cannot leave the expectation behind — the failure mode this
# very harness exists to prevent, one level up.
declared_rows=$(grep -cE '^row [A-Za-z0-9_]+ +(red|survive)([[:space:]]|$)' "$0")
declared_rows=$((declared_rows + 1))   # + the RESTORED row, which is not a `row` call
if [ "${rows_total}" -ne "${declared_rows}" ]; then
  echo "INCOMPLETE: ${rows_total} rows scored but ${declared_rows} declared — the run did not"
  echo "  reach every row. A partial matrix must never read as a clean one."
  rc=1
fi
if [ "${extractor_misses}" -ne 0 ]; then
  echo "EXTRACTOR ROT: ${extractor_misses} row(s) red with no extractable reason:"
  for r in "${extractor_miss_rows[@]}"; do echo "    ${r}"; done
  echo "  The rows still SCORED — their guard columns are what prove the guards fire —"
  echo "  but the reason extractor no longer matches the text it reads. Fix \`explain()\`."
  rc=1
fi
echo "=== acceptance $([ ${rc} -eq 0 ] && echo PASS || echo FAIL) ==="
exit ${rc}
