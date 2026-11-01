#!/bin/sh
# #18839: `make clean` must never delete the box-wide SHARED cargo target dir
# (/var/worktrees/.cache/cargo), the CARGO_TARGET_DIR default every worktree
# and lane on this host builds into. Hermetic: every cell is `make -n clean`
# (a dry run; nothing is deleted), so the only side effects are the Makefile's
# own parse-time `mkdir -p` of the scratch dirs.
#
# Cells:
#   1 default env: the dry run does not NAME the shared dir at all, and still
#     removes userspace-dp/target
#   2 a per-worktree CARGO_TARGET_DIR is removed
#   3 the shared dir spelled with a trailing slash is kept
#   4 a symlink to the shared dir is kept (resolved by realpath)
#   5 a PARENT of the shared dir is refused
#   6 a CHILD of the shared dir is refused
#   7 CLEAN_SHARED_CARGO=1 removes the shared dir, with a WARNING
#   8 CLEAN_SHARED_CARGO=1 does not unlock a parent
#   P positive control: the pre-#18839 recipe, run through the same detector,
#     names the shared dir (or cell 1 could not tell fixed from broken)
#
# Exit 0 all pass, 1 a cell failed, 77 make is missing.
set -u
command -v make >/dev/null 2>&1 || { echo "SKIP: make not found"; exit 77; }
cd "$(dirname "$0")/.." || exit 1
SHARED=/var/worktrees/.cache/cargo
WORK=$(mktemp -d "${TMPDIR:-/tmp}/cleansel.XXXXXX") || exit 1
trap 'rm -rf "$WORK"' EXIT
fails=0
pass() { echo "PASS: $*"; }
failc() { echo "FAIL: $*"; fails=$((fails + 1)); }

# dry <makefile> [VAR=value ...]: `make -n clean` with a clean environment.
dry() {
	mf=$1
	shift
	env -u CARGO_TARGET_DIR -u CLEAN_SHARED_CARGO -u MAKEFLAGS -u MFLAGS -u MAKELEVEL \
		"$@" make --no-print-directory -n -f "$mf" clean 2>&1
}
names_shared() { printf '%s\n' "$1" | grep -qF "$SHARED"; }
removes() { printf '%s\n' "$1" | grep -qE "^rm -rf $2/?\$"; }

out=$(dry Makefile)
if names_shared "$out"; then
	failc "1 default env: the dry run names $SHARED:"
	printf '%s\n' "$out" | grep -F "$SHARED" | sed 's/^/      /'
elif ! removes "$out" userspace-dp/target; then
	failc "1 default env: userspace-dp/target is no longer removed"
else
	pass "1 default env: $SHARED not named; userspace-dp/target removed"
fi

out=$(dry Makefile CARGO_TARGET_DIR="$WORK/wt-target")
if removes "$out" "$WORK/wt-target" && ! names_shared "$out"; then
	pass "2 a per-worktree CARGO_TARGET_DIR is removed"
else
	failc "2 per-worktree CARGO_TARGET_DIR=$WORK/wt-target: $(printf '%s' "$out" | tail -2)"
fi

out=$(dry Makefile CARGO_TARGET_DIR="$SHARED/")
if ! removes "$out" "$SHARED" && printf '%s\n' "$out" | grep -q "kept the box-wide shared"; then
	pass "3 the shared dir with a trailing slash is kept"
else
	failc "3 CARGO_TARGET_DIR=$SHARED/: $(printf '%s' "$out" | tail -2)"
fi

ln -s "$SHARED" "$WORK/shared-link"
out=$(dry Makefile CARGO_TARGET_DIR="$WORK/shared-link")
if ! removes "$out" "$WORK/shared-link" && printf '%s\n' "$out" | grep -q "kept the box-wide shared"; then
	pass "4 a symlink to the shared dir is kept"
else
	failc "4 CARGO_TARGET_DIR=<symlink to $SHARED>: $(printf '%s' "$out" | tail -2)"
fi

parent=$(dirname "$SHARED")
out=$(dry Makefile CARGO_TARGET_DIR="$parent")
if ! removes "$out" "$parent" && printf '%s\n' "$out" | grep -q "REFUSING"; then
	pass "5 a parent of the shared dir ($parent) is refused"
else
	failc "5 CARGO_TARGET_DIR=$parent: $(printf '%s' "$out" | tail -2)"
fi

child="$SHARED/release"
out=$(dry Makefile CARGO_TARGET_DIR="$child")
if ! removes "$out" "$child" && printf '%s\n' "$out" | grep -q "REFUSING"; then
	pass "6 a child of the shared dir ($child) is refused"
else
	failc "6 CARGO_TARGET_DIR=$child: $(printf '%s' "$out" | tail -2)"
fi

out=$(dry Makefile CLEAN_SHARED_CARGO=1)
if removes "$out" "$SHARED" && printf '%s\n' "$out" | grep -q "WARNING: CLEAN_SHARED_CARGO=1"; then
	pass "7 CLEAN_SHARED_CARGO=1 removes the shared dir, loudly"
else
	failc "7 CLEAN_SHARED_CARGO=1: $(printf '%s' "$out" | tail -2)"
fi

out=$(dry Makefile CLEAN_SHARED_CARGO=1 CARGO_TARGET_DIR="$parent")
if ! removes "$out" "$parent" && printf '%s\n' "$out" | grep -q "REFUSING"; then
	pass "8 CLEAN_SHARED_CARGO=1 does not unlock a parent"
else
	failc "8 CLEAN_SHARED_CARGO=1 CARGO_TARGET_DIR=$parent: $(printf '%s' "$out" | tail -2)"
fi

# P: rebuild the pre-#18839 recipe in a copy and require cell 1's detector to
# fire on it. The copy is read with -f from the repo root, so every relative
# path and parse-time $(shell) behaves exactly as for the real Makefile.
python3 - Makefile "$WORK/Makefile.pre18839" <<'PY' || { failc "P fixture: could not rebuild the pre-#18839 recipe"; }
import re, sys
src, dst = sys.argv[1:]
s = open(src).read()
m = re.search(r"\trm -rf userspace-dp/target\n# #18839:.*?\nendif\n(?=\n)", s, re.S)
if not m:
    sys.exit("guarded block not found")
s = s[:m.start()] + "\trm -rf $(CARGO_TARGET_DIR) userspace-dp/target\n" + s[m.end():]
open(dst, "w").write(s)
PY
if [ -f "$WORK/Makefile.pre18839" ]; then
	out=$(dry "$WORK/Makefile.pre18839")
	if names_shared "$out"; then
		pass "P positive control: the pre-#18839 recipe names $SHARED (cell 1 can see the defect)"
	else
		failc "P the pre-#18839 recipe did not name $SHARED; cell 1 cannot detect the defect"
	fi
fi

[ "$fails" -eq 0 ] && { echo "clean-shared-cargo selftest: all cells pass"; exit 0; }
echo "clean-shared-cargo selftest: $fails cell(s) failed"
exit 1
