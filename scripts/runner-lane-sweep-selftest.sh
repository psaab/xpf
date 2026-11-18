#!/bin/bash
# scripts/runner-lane-sweep-selftest.sh -- the whole-lane idle sweep
# (scripts/runner-lane-sweep.sh) on a fake /work. Hermetic: a scratch lane
# root, real processes of this test standing in for lane users.
#
# Lanes (the idle ones have every file and directory dated 7 h back):
#   active   one file written now                       -> kept
#   idle     everything 7 h old, no user                 -> removed
#   deepnew  7 h old except ONE deep file written now     -> kept (the NEWEST
#            file decides; a per-file age would delete the old ones under it)
#   cwdlane  7 h old, a process with its cwd inside       -> kept, logged
#   fdlane   7 h old, a process (cwd elsewhere) holding an
#            open fd on a file inside                     -> kept, logged
#   link     an old symlink to an idle directory outside  -> skipped; the
#            target is untouched
# --lane <name> --idle-s 0 (vm-test-run.sh --cleanup-on-success): removes a
# user-free lane at once, keeps one with a user.
# Mutations (each must flip a cell): the cwd check dropped, the fd check
# dropped, the idle check dropped, the newest-file check limited to the top
# level, the symlink check dropped.
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
subject="$here/runner-lane-sweep.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/runner-lane-sweep-selftest.XXXXXX")
pids=()
cleanup() {
	local p
	for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done
	wait 2>/dev/null
	rm -rf "$tmp"
}
trap cleanup EXIT

pass=0 fail=0
ok() { pass=$((pass + 1)); echo "PASS: $*"; }
bad() { fail=$((fail + 1)); echo "FAIL: $*"; }

age() { find "$1" -depth -exec touch -h -d '7 hours ago' {} +; }
lane() { mkdir -p "$1/src/pkg" "$1/target" && echo x >"$1/src/pkg/f" && echo y >"$1/target/obj"; }

# build <root>: the fixture lanes, users started fresh.
build() {
	local r=$1 p
	for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done
	wait 2>/dev/null
	pids=()
	mkdir -p "$r" "$tmp/outside"
	lane "$r/active"
	lane "$r/idle"; age "$r/idle"
	lane "$r/deepnew"; age "$r/deepnew"; echo new >"$r/deepnew/src/pkg/f"
	lane "$r/cwdlane"; age "$r/cwdlane"
	lane "$r/fdlane"; age "$r/fdlane"
	lane "$tmp/outside/idletarget"; age "$tmp/outside/idletarget"
	ln -sfn "$tmp/outside/idletarget" "$r/link"
	touch -h -d '7 hours ago' "$r/link"
	# The users' stdio goes to /dev/null: an inherited pipe would hold any
	# command substitution open until they exit.
	(cd "$r/cwdlane/src" && exec sleep 300) </dev/null >/dev/null 2>&1 &
	pids+=($!)
	(cd / && exec 3<"$r/fdlane/src/pkg/f" && exec sleep 300) </dev/null >/dev/null 2>&1 &
	pids+=($!)
	sleep 0.3
}

# verdict <root> <log>: one line naming every lane's fate, for comparison.
verdict() {
	local r=$1 l out=""
	for l in active idle deepnew cwdlane fdlane link; do
		if [[ -e "$r/$l" || -L "$r/$l" ]]; then out+="$l=kept "; else out+="$l=gone "; fi
	done
	[[ -f "$tmp/outside/idletarget/src/pkg/f" ]] && out+="target=intact" || out+="target=damaged"
	echo "$out"
}
want="active=kept idle=gone deepnew=kept cwdlane=kept fdlane=kept link=kept target=intact"

# sweep <subject> <tag>: build a fresh root and sweep it; the verdict lands in
# $got. It runs in THIS shell (not a command substitution) so the users it
# starts stay in $pids and are killed by the next build and on exit.
sweep() {
	local s=$1 tag=$2
	build "$tmp/$tag"
	bash "$s" --root "$tmp/$tag" --log "$tmp/$tag.log" >"$tmp/$tag.out" 2>&1
	got=$(verdict "$tmp/$tag")
}

sweep "$subject" base
if [[ "$got" == "$want" ]]; then
	ok "the sweep removes only the idle lane: $got"
else
	bad "the sweep: got [$got], want [$want]: $(tr '\n' '|' <"$tmp/base.out")"
fi
if grep -q 'removed idle ' "$tmp/base.log" && grep -q 'kept cwdlane: .*(cwd)' "$tmp/base.log" &&
	grep -q 'kept fdlane: .*(fd)' "$tmp/base.log" && grep -q 'skipped link: not a plain directory' "$tmp/base.log"; then
	ok "the log names the removal, both in-use reasons and the skipped symlink"
else
	bad "the log: $(tr '\n' '|' <"$tmp/base.log")"
fi
if ! compgen -G "$tmp/base/.xpf-sweep.*" >/dev/null; then
	ok "nothing is left renamed aside"
else
	bad "a .xpf-sweep.* directory was left behind"
fi

# Single-lane mode (vm-test-run.sh --cleanup-on-success).
build "$tmp/one"
bash "$subject" --root "$tmp/one" --lane active --idle-s 0 --log "$tmp/one.log" >/dev/null 2>&1
bash "$subject" --root "$tmp/one" --lane cwdlane --idle-s 0 --log "$tmp/one.log" >/dev/null 2>&1
if [[ ! -e "$tmp/one/active" && -d "$tmp/one/cwdlane" && -d "$tmp/one/idle" ]]; then
	ok "--lane --idle-s 0 removes a user-free lane at once, keeps a lane in use, touches no other lane"
else
	bad "--lane mode: $(verdict "$tmp/one")"
fi

# mutant <name> <sed> <expected changed verdict fragment>
mutant() {
	local name=$1 expr=$2 expect=$3 m="$tmp/m-$1.sh" got
	sed "$expr" "$subject" >"$m"
	if cmp -s "$subject" "$m"; then
		bad "mutation $name: the anchor was not found"
		return
	fi
	sweep "$m" "m-$name"
	if [[ "$got" == *"$expect"* ]]; then
		ok "mutation $name: the cell fails ($expect)"
	else
		bad "mutation $name: the verdict did not move: $got"
	fi
}
mutant no-cwd-check 's/^\t\tif \[\[ "\$t" == "\$dir" || "\$t" == "\$dir"\/\* \]\]; then$/\t\tif false; then/' "cwdlane=gone"
mutant no-fd-check 's/^\t\t\tif \[\[ "\$t" == "\$dir" || "\$t" == "\$dir"\/\* \]\]; then$/\t\t\tif false; then/' "fdlane=gone"
mutant no-idle-check 's/^\tif recent "\$dir"; then$/\tif false; then/' "active=gone"
mutant top-level-only 's/find "\$1" -xdev -newermt/find "$1" -maxdepth 1 -xdev -newermt/' "deepnew=gone"
mutant follows-symlinks 's/^\tif \[\[ -L "\$dir" || ! -d "\$dir" \]\]; then$/\tif [[ ! -d "$dir" ]]; then/' "link=gone"

echo "runner-lane-sweep selftest: ${pass} passed, ${fail} failed"
[[ "$fail" -eq 0 ]]
