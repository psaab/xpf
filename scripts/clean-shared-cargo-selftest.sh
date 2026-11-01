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
#   9 `/` is refused (a parent check of the form "$dir/%" cannot see it)
#  10 a value with whitespace is refused (rm would delete each word)
#  11 a set-but-empty value is refused, with text that says so
#  D  the dh path: dpkg-buildpackage runs `dh clean`, whose default
#     dh_auto_clean runs `make clean`. debian/rules must override it, and the
#     override must neither call `make clean` nor name the shared dir.
#  DP positive control for D: the same dh probe on a copy of debian/ without
#     the override must show dh_auto_clean
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

out=$(dry Makefile CARGO_TARGET_DIR=/)
if ! printf '%s\n' "$out" | grep -qE '^rm -rf /$' && printf '%s\n' "$out" | grep -q "REFUSING: CARGO_TARGET_DIR resolves to /"; then
	pass "9 CARGO_TARGET_DIR=/ is refused"
else
	failc "9 CARGO_TARGET_DIR=/: $(printf '%s' "$out" | tail -2)"
fi

out=$(dry Makefile CARGO_TARGET_DIR="$WORK/a docs")
if ! printf '%s\n' "$out" | grep -qE "^rm -rf $WORK/a" && printf '%s\n' "$out" | grep -q "contains whitespace"; then
	pass "10 a CARGO_TARGET_DIR with whitespace is refused"
else
	failc "10 CARGO_TARGET_DIR='$WORK/a docs': $(printf '%s' "$out" | tail -2)"
fi

out=$(dry Makefile CARGO_TARGET_DIR=)
if printf '%s\n' "$out" | grep -q "set but empty" && ! printf '%s\n' "$out" | grep -qE '^rm -rf *$'; then
	pass "11 a set-but-empty CARGO_TARGET_DIR is refused, and says so"
else
	failc "11 CARGO_TARGET_DIR=(empty): $(printf '%s' "$out" | tail -2)"
fi

# D: the dh path. `make -n -f debian/rules override_dh_auto_clean` must not
# call the Makefile clean or name the shared dir; when debhelper is present,
# `dh clean --no-act` must route through the override, not dh_auto_clean.
out=$(env -u MAKEFLAGS make --no-print-directory -n -f debian/rules override_dh_auto_clean 2>&1)
# debian/rules has a `%: dh $@` catch-all, so a missing override would still
# "succeed" here as `dh override_dh_auto_clean`: require the override's own line.
if [ $? -ne 0 ] || ! printf '%s\n' "$out" | grep -qx 'rm -f xpfd cli xpf-userspace-dp'; then
	failc "D debian/rules has no override_dh_auto_clean of its own: $(printf '%s' "$out" | tail -1)"
elif names_shared "$out" || printf '%s\n' "$out" | grep -qE '(^|[ /])make( -[^ ]+)* clean'; then
	failc "D the dh_auto_clean override still runs make clean or names $SHARED: $out"
else
	pass "D debian/rules overrides dh_auto_clean; the override runs no make clean"
fi
if command -v dh >/dev/null 2>&1; then
	seq=$(timeout 60 dh clean --no-act 2>&1)
	if printf '%s\n' "$seq" | grep -qx '[[:space:]]*debian/rules override_dh_auto_clean' &&
		! printf '%s\n' "$seq" | grep -qx '[[:space:]]*dh_auto_clean'; then
		pass "D dh clean routes through the override, not dh_auto_clean"
	else
		failc "D dh clean --no-act: $(printf '%s' "$seq" | tr '\n' ' ')"
	fi
	# DP: the same probe on a copy of debian/ WITHOUT the override.
	mkdir -p "$WORK/pkg"
	cp -a debian "$WORK/pkg/debian"
	python3 - "$WORK/pkg/debian/rules" <<'PY'
import re, sys
p = sys.argv[1]
s = open(p).read()
s2 = re.sub(r"^override_dh_auto_clean:\n(\t.*\n)*", "", s, flags=re.M)
if s2 == s:
    sys.exit("override not found")
open(p, "w").write(s2)
PY
	seq=$(cd "$WORK/pkg" && timeout 60 dh clean --no-act 2>&1)
	if printf '%s\n' "$seq" | grep -qx '[[:space:]]*dh_auto_clean'; then
		pass "DP positive control: without the override, dh clean runs dh_auto_clean (cell D can see the defect)"
	else
		failc "DP without the override dh clean did not show dh_auto_clean: $(printf '%s' "$seq" | tr '\n' ' ')"
	fi
else
	echo "NOTE: dh not installed; the dh clean --no-act probes (D, DP) were not run"
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
