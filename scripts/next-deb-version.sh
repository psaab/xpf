#!/bin/sh
# scripts/next-deb-version.sh -- allocate the next xpf deb version (#18645).
#
# WHAT IT DOES
#
#   Prints `0.0.<N>`, where N comes from a shared counter file that every lane
#   on this box allocates from:
#
#     /var/worktrees/.cache/deb-version-counter      (override: --counter FILE
#                                                     or XPF_DEB_VERSION_COUNTER)
#
#   Under an exclusive flock on <counter>.lock it reads the counter, raises it
#   to the highest version it can SEE (below), adds one, writes the result
#   atomically (temp file + mv in the same directory) and prints it. So two
#   allocations never return the same N, and each N is above every N returned
#   before it on this box.
#
#   Callers compose the full version, e.g. the campaign gate step:
#     DEB_N=$(scripts/next-deb-version.sh --git "$WT")
#     make -C "$WT" deb DEB_VERSION="$DEB_N+g$(git -C "$WT" rev-parse --short=12 HEAD)"
#   `make deb`'s own default (`0.0.<commit-count>+g<sha>`) is unchanged.
#
# WHY IT EXISTS
#
#   Lanes picked `0.0.NNNNN` by hand. Two lanes picked the same number, and a
#   lane that picked a number below what a cluster already ran built a deb apt
#   refuses as a downgrade, so it rebuilt. A stock build is no better: two
#   branches off the same master have the same commit count, and a branch off
#   an older master has a LOWER one than the master a merge-wave gate just
#   deployed.
#
# "THE HIGHEST VERSION SEEN" -- the counter is raised to at least:
#
#   * every `xpf_0.0.<N>...deb` under the scan globs (default: the dist-deb/
#     directories of the worktrees under /var/worktrees; override with
#     XPF_DEB_VERSION_SCAN, a space-separated glob list, or --no-scan);
#   * every --floor N and every --seen VERSION (`0.0.<N>[+...]`), e.g. a
#     version read off a cluster node with `dpkg-query -W -f '${Version}' xpf`;
#   * with --git DIR, the commit counts of DIR's HEAD and origin/master, i.e.
#     what a stock `make deb` of either would be numbered.
#
#   Versions outside the 0.0.N space (for example a hand-built 99.0.x) are not
#   ordered by this allocator; a node running one still sees 0.0.N as a
#   downgrade.
#
# FAILURE MODES IT REFUSES
#
#   * A counter file that exists but does not hold one decimal number is a
#     FATAL error, never a reset to zero: a reset would hand out numbers again.
#   * No flock(1), or a lock not acquired within 30 s, is FATAL.
#   * Every refusal leaves the counter unchanged.
#
# TEST HOOK
#
#   XPF_NEXT_DEB_VERSION_HOLD_S=<seconds> sleeps between the read and the write
#   while the lock is held, so the self-test can show that concurrent callers
#   serialise (and that a copy without the lock does not). It changes no value.
#
# USAGE
#   scripts/next-deb-version.sh [--counter FILE] [--git DIR] [--floor N]...
#                               [--seen VERSION]... [--no-scan]
#   Exit: 0 printed a version; 1 refused; 2 usage.
set -eu

COUNTER=${XPF_DEB_VERSION_COUNTER:-/var/worktrees/.cache/deb-version-counter}
SCAN=${XPF_DEB_VERSION_SCAN-"/var/worktrees/*/dist-deb/xpf_*.deb /var/worktrees/*/*/dist-deb/xpf_*.deb"}
GIT_DIRS=""
FLOORS=""
# The largest floor and where it came from, so a jump is never silent.
TOP=0
TOP_FROM=""

die() { echo "next-deb-version: $*" >&2; exit 1; }
usage() { echo "usage: next-deb-version.sh [--counter FILE] [--git DIR] [--floor N]... [--seen VERSION]... [--no-scan]" >&2; exit 2; }

is_num() { case "$1" in '' | *[!0-9]*) return 1 ;; esac; return 0; }

# add_floor <N> <source>
add_floor() {
	FLOORS="$FLOORS $1"
	if [ "$1" -gt "$TOP" ]; then
		TOP=$1
		TOP_FROM=$2
	fi
}

# n_of_version <version> -> N for `0.0.<N>` or `0.0.<N><non-digit>...`
n_of_version() {
	v=${1#0.0.}
	[ "$v" != "$1" ] || return 1
	n=${v%%[!0-9]*}
	is_num "$n" || return 1
	printf '%s\n' "$n"
}

while [ $# -gt 0 ]; do
	case "$1" in
	--counter) [ $# -ge 2 ] || usage; COUNTER=$2; shift 2 ;;
	--git) [ $# -ge 2 ] || usage; GIT_DIRS="$GIT_DIRS $2"; shift 2 ;;
	--floor) [ $# -ge 2 ] || usage; is_num "$2" || die "--floor '$2' is not a number"; add_floor "$2" "--floor $2"; shift 2 ;;
	--seen)
		[ $# -ge 2 ] || usage
		n=$(n_of_version "$2") || die "--seen '$2' is not a 0.0.N version"
		add_floor "$n" "--seen $2"
		shift 2
		;;
	--no-scan) SCAN=""; shift ;;
	-h | --help) sed -n '2,62p' "$0" 2>/dev/null || true; exit 0 ;;
	*) usage ;;
	esac
done

command -v flock >/dev/null 2>&1 || die "flock(1) not found (util-linux); refusing to allocate without a lock"

for d in $GIT_DIRS; do
	for rev in HEAD origin/master; do
		c=$(git -C "$d" rev-list --count "$rev" 2>/dev/null || true)
		if is_num "$c"; then add_floor "$c" "commit count of $rev in $d"; fi
	done
done

# The globs are expanded on purpose (word splitting + pathname expansion).
for g in $SCAN; do
	for f in $g; do
		[ -f "$f" ] || continue
		b=${f##*/}
		v=${b#xpf_}
		v=${v%%_*}
		n=$(n_of_version "$v") || continue
		add_floor "$n" "$f"
	done
done

dir=$(dirname -- "$COUNTER")
mkdir -p -- "$dir" || die "cannot create $dir"
LOCK="$COUNTER.lock"

# Everything below runs with fd 9 holding an exclusive lock.
exec 9>>"$LOCK" || die "cannot open lock $LOCK"
flock -w 30 9 || die "could not lock $LOCK within 30 s" # census-guard: lock

cur=0
if [ -e "$COUNTER" ]; then
	cur=$(tr -d ' \t\r\n' <"$COUNTER") || die "cannot read $COUNTER"
	if ! is_num "$cur"; then # census-guard: malformed-counter
		die "counter $COUNTER holds '$cur', not a number; refusing (a reset would reissue versions). Fix it by hand to at least the highest version in use."
	fi
fi

next=$cur
for f in $FLOORS; do # census-guard: floor
	if [ "$f" -gt "$next" ]; then next=$f; fi
done
next=$((next + 1))
if [ "$next" -gt $((cur + 1)) ]; then
	echo "next-deb-version: counter $cur raised to $((next - 1)) by: $TOP_FROM" >&2
fi

if [ -n "${XPF_NEXT_DEB_VERSION_HOLD_S:-}" ]; then
	sleep "$XPF_NEXT_DEB_VERSION_HOLD_S"
fi

tmp="$COUNTER.tmp.$$"
printf '%s\n' "$next" >"$tmp" || { rm -f -- "$tmp"; die "cannot write $tmp"; }
mv -f -- "$tmp" "$COUNTER" || { rm -f -- "$tmp"; die "cannot replace $COUNTER"; }

printf '0.0.%s\n' "$next"
