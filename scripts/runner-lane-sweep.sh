#!/bin/bash
# scripts/runner-lane-sweep.sh -- remove IDLE test-runner lanes, whole lanes
# only (#19080 follow-up; runner disks hit 100% with 62 lanes on 2026-11-17).
#
# A lane is /work/<name> (scripts/vm-test-run.sh). One lane is removed only
# when BOTH hold:
#   - nothing under it, at any depth, was modified in the last --idle-s
#     seconds (default 21600, 6 h). It is the NEWEST file that decides, never a
#     per-file age: a per-file sweep (tmpfiles-style) deletes an old source
#     file from under an active build;
#   - no process has its cwd, or an open file descriptor, at or under it
#     (every /proc/<pid>/cwd and /proc/<pid>/fd/*; run as root to see all).
# A lane that is a symlink, not a directory, or has a mount point at or under
# it is skipped. Removal is two-step: the lane is renamed aside
# (<root>/.xpf-sweep.<name>.<pid>), checked for users AGAIN under the new name
# (a process that started between the check and the rename now shows up
# there), renamed back if one did, and otherwise deleted without crossing a
# filesystem boundary. Leftover .xpf-sweep.* directories are swept the same way.
#
# Every lane removed or kept-in-use is logged on stdout (journald under the
# timer) and appended to --log (default /var/log/xpf-lane-sweep.log).
#
# Installed on every runner by scripts/provision-testrunner.sh as
# /usr/local/sbin/xpf-lane-sweep with an hourly timer (xpf-lane-sweep.timer).
# scripts/vm-test-run.sh --cleanup-on-success runs it as
#   --lane <name> --idle-s 0
# which still refuses a lane with a user.
#
# Usage: runner-lane-sweep.sh [--root DIR] [--idle-s N] [--lane NAME]
#                             [--log FILE] [--dry-run]
set -uo pipefail

root=/work
idle_s=21600
only=""
log=/var/log/xpf-lane-sweep.log
dry=0
while [[ $# -gt 0 ]]; do
	case "$1" in
	--root) root=$2; shift 2 ;;
	--idle-s) idle_s=$2; shift 2 ;;
	--lane) only=$2; shift 2 ;;
	--log) log=$2; shift 2 ;;
	--dry-run) dry=1; shift ;;
	*) echo "runner-lane-sweep: unknown argument: $1" >&2; exit 2 ;;
	esac
done
[[ "$idle_s" =~ ^[0-9]+$ ]] || { echo "runner-lane-sweep: --idle-s must be a number of seconds" >&2; exit 2; }
if [[ -n "$only" && ( ! "$only" =~ ^[A-Za-z0-9._-]+$ || "$only" =~ ^\.+$ ) ]]; then
	echo "runner-lane-sweep: bad lane name: $only" >&2
	exit 2
fi
root=$(realpath -e -- "$root") || { echo "runner-lane-sweep: no lane root" >&2; exit 2; }

say() {
	local line
	line="runner-lane-sweep: $(date -u +%FT%TZ) $*"
	echo "$line"
	echo "$line" >>"$log" 2>/dev/null || true
}

# users <dir>: print the processes whose cwd or an open fd is at or under dir.
users() {
	local dir=$1 p pid f t
	for p in /proc/[0-9]*; do
		pid=${p#/proc/}
		[[ "$pid" == "$$" || "$pid" == "$BASHPID" ]] && continue
		t=$(readlink "$p/cwd" 2>/dev/null) || t=""
		if [[ "$t" == "$dir" || "$t" == "$dir"/* ]]; then
			echo "$pid(cwd)"
			continue
		fi
		for f in "$p"/fd/*; do
			t=$(readlink "$f" 2>/dev/null) || continue
			if [[ "$t" == "$dir" || "$t" == "$dir"/* ]]; then
				echo "$pid(fd)"
				break
			fi
		done
	done
}

# has_mount <dir>: a mount point at or under dir.
has_mount() {
	awk -v d="$1" '{ m = $5; gsub(/\\040/, " ", m); if (m == d || index(m, d "/") == 1) { found = 1; exit } } END { exit !found }' /proc/self/mountinfo
}

# recent <dir>: something under dir was modified in the last idle_s seconds.
# --idle-s 0 means "no idle requirement" (a file written this very second
# would otherwise count as newer than now).
recent() {
	[[ "$idle_s" -gt 0 ]] || return 1
	[[ -n "$(find "$1" -xdev -newermt "@$(($(date +%s) - idle_s))" -print -quit 2>/dev/null)" ]]
}

sweep_one() {
	local dir=$1 name aside who
	name=$(basename -- "$dir")
	if [[ -L "$dir" || ! -d "$dir" ]]; then
		say "skipped $name: not a plain directory"
		return 0
	fi
	if has_mount "$dir"; then
		say "skipped $name: a mount point is at or under it"
		return 0
	fi
	if recent "$dir"; then
		return 0
	fi
	who=$(users "$dir" | tr '\n' ' ')
	if [[ -n "$who" ]]; then
		say "kept $name: idle for ${idle_s}s but in use by ${who% }"
		return 0
	fi
	if [[ "$dry" -eq 1 ]]; then
		say "would remove $name (nothing modified for ${idle_s}s, no process cwd or fd under it)"
		return 0
	fi
	aside="$root/.xpf-sweep.${name#.xpf-sweep.}.$$"
	[[ "$dir" == "$aside" ]] || mv -T -- "$dir" "$aside" || { say "skipped $name: could not rename it aside"; return 0; }
	who=$(users "$aside" | tr '\n' ' ')
	if [[ -n "$who" ]]; then
		mv -T -- "$aside" "$dir" || say "WARNING: $name is in use and stays renamed as $aside"
		say "kept $name: a user appeared during removal (${who% })"
		return 0
	fi
	if rm -rf --one-file-system -- "$aside"; then
		say "removed $name (nothing modified for ${idle_s}s, no process cwd or fd under it)"
	else
		say "WARNING: could not fully remove $aside"
	fi
}

if [[ -n "$only" ]]; then
	[[ -e "$root/$only" || -L "$root/$only" ]] || exit 0
	sweep_one "$root/$only"
	exit 0
fi
shopt -s nullglob
for dir in "$root"/* "$root"/.xpf-sweep.*; do
	sweep_one "$dir"
done
exit 0
