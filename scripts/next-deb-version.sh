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
#   to the FLOOR (below), adds one, writes the result atomically (temp file + mv
#   in the same directory) and prints it. Two allocations never return the
#   same N, and each N is above every N this counter returned before.
#
#   Callers compose the full version, e.g. the campaign gate step:
#     DEB_N=$(scripts/next-deb-version.sh --git "$WT")
#     make -C "$WT" deb DEB_VERSION="$DEB_N+g$(git -C "$WT" rev-parse --short=12 HEAD)"
#   `make deb`'s own default (`0.0.<commit-count>+g<sha>`) is unchanged.
#
# WHY IT EXISTS
#
#   Lanes picked `0.0.NNNNN` by hand. Two lanes picked the same number, and a
#   lane whose number was below what a node already ran built a deb that apt
#   refuses as a downgrade (`apt-get install -y` without --allow-downgrades),
#   so it rebuilt.
#
# THE FLOOR IS WHAT IS DEPLOYED, NOT WHAT IS ON DISK
#
#   An allocation must beat the version the target node RUNS. It must not be
#   pushed up by a deb that merely exists: a stray hand-built 0.0.99999 in some
#   worktree would otherwise make the first allocation 0.0.100000, and once one
#   node ran that, every lane's ordinary 0.0.268xx build would be a downgrade
#   there and every gate would stall. So the floor is the highest of:
#
#   * the xpf version INSTALLED on each lab node: `dpkg-query -W xpf` on the
#     six nodes loss/tcp/udp x fw0/fw1 (DEFAULT_NODES below, kept equal to the
#     three test/incus/*-userspace-cluster.env files by the self-test;
#     override XPF_DEB_VERSION_NODES). Read-only, with a timeout per node, run
#     before the lock is taken. When the counter does not exist yet, MARGIN
#     (default 100, XPF_DEB_VERSION_MARGIN) is added, so the first numbers
#     clear builds that are hand-picked a little above what is deployed;
#   * an explicit floor: --floor N, or XPF_DEB_VERSION_FLOOR;
#   * --seen VERSION (a 0.0.N version known to be in use) and, with --git DIR,
#     the commit counts of DIR's HEAD and origin/master (what a stock
#     `make deb` of either would be numbered);
#   * the counter itself.
#
#   Debs on disk under /var/worktrees are NOT a floor. One at or above the
#   allocation is reported on stderr, because deploying it would make the
#   allocation a downgrade on that node (XPF_DEB_VERSION_SCAN: the globs to
#   check; empty disables the warning).
#
# REFUSALS (each leaves the counter unchanged; exit 1)
#
#   * Creating the counter without a trusted floor: when no counter exists, it
#     refuses unless every probed node answered or an explicit floor was
#     given. Starting at 0.0.1 would be a downgrade on every node.
#   * A JUMP: an allocation more than MAX_JUMP (default 1000,
#     XPF_DEB_VERSION_MAX_JUMP) above the reference (the deployed maximum
#     plus margin, or the explicit floor, or the counter when neither is
#     known) needs --force-jump. That catches a bogus --seen, or a counter far
#     ahead of anything deployed, before it strands every node.
#   * --claim VERSION at or below the counter or a deployed version. A
#     hand-picked number is accepted only above both, and it is then written
#     into the counter so no allocation can reissue it.
#   * A counter file that exists but does not hold one decimal number (junk,
#     or EMPTY after a crash or a full disk). It is never reset: a reset
#     would hand the numbers out again.
#   * No flock(1), or the lock not acquired within 30 s.
#
#   A node running a version outside the 0.0.N space (for example a
#   hand-built 99.0.x) is reported on stderr: no 0.0.N can upgrade it.
#
# MIGRATION
#
#   Until this script is on master, lanes hand-pick. Once it lands, every
#   cluster deploy allocates. The first run creates the counter above the
#   deployed maximum plus MARGIN. A lane that still holds a hand-picked
#   build registers it with --claim, which refuses it if the number is at or
#   below the counter; such a build has to be rebuilt with an allocated
#   version.
#
# TEST HOOKS
#
#   XPF_DEB_VERSION_PROBE_CMD=<command>  replaces the node probe. It must print
#     one `<node> <version|unknown>` line per node. Empty means "no nodes".
#   XPF_NEXT_DEB_VERSION_HOLD_S=<seconds> sleeps between the read and the
#     write while the lock is held, so the self-test can show that concurrent
#     callers serialise. It changes no value.
#
# USAGE
#   scripts/next-deb-version.sh [--counter FILE] [--git DIR] [--floor N]...
#       [--seen VERSION]... [--claim VERSION] [--force-jump] [--no-probe]
#   Exit: 0 printed a version; 1 refused; 2 usage.
set -eu

DEFAULT_NODES="loss:xpf-userspace-fw0 loss:xpf-userspace-fw1 tcp:xpf-tcp-fw0 tcp:xpf-tcp-fw1 udp:xpf-udp-fw0 udp:xpf-udp-fw1"
NODES=${XPF_DEB_VERSION_NODES:-$DEFAULT_NODES}
COUNTER=${XPF_DEB_VERSION_COUNTER:-/var/worktrees/.cache/deb-version-counter}
SCAN=${XPF_DEB_VERSION_SCAN-"/var/worktrees/*/dist-deb/xpf_*.deb /var/worktrees/*/*/dist-deb/xpf_*.deb"}
MARGIN=${XPF_DEB_VERSION_MARGIN:-100}
MAX_JUMP=${XPF_DEB_VERSION_MAX_JUMP:-1000}
PROBE_TIMEOUT=${XPF_DEB_VERSION_PROBE_TIMEOUT:-15}

GIT_DIRS=""
EXPLICIT=""   # explicit floors (--floor, XPF_DEB_VERSION_FLOOR)
SEEN=""       # --seen and --git floors
CLAIM=""
FORCE_JUMP=0
PROBE=1

die() { echo "next-deb-version: $*" >&2; exit 1; }
warn() { echo "next-deb-version: $*" >&2; }
usage() { echo "usage: next-deb-version.sh [--counter FILE] [--git DIR] [--floor N]... [--seen VERSION]... [--claim VERSION] [--force-jump] [--no-probe]" >&2; exit 2; }

is_num() { case "$1" in '' | *[!0-9]*) return 1 ;; esac; return 0; }

# n_of_version <version> -> N for `0.0.<N>` or `0.0.<N><non-digit>...`
n_of_version() {
	v=${1#0.0.}
	[ "$v" != "$1" ] || return 1
	n=${v%%[!0-9]*}
	is_num "$n" || return 1
	printf '%s\n' "$n"
}

# max_of <list> -> the largest number in a space-separated list (empty -> "")
max_of() {
	m=""
	for x in $1; do
		if [ -z "$m" ] || [ "$x" -gt "$m" ]; then m=$x; fi
	done
	printf '%s' "$m"
}

for v in ${XPF_DEB_VERSION_FLOOR:-}; do
	is_num "$v" || die "XPF_DEB_VERSION_FLOOR='$v' is not a number"
	EXPLICIT="$EXPLICIT $v"
done

while [ $# -gt 0 ]; do
	case "$1" in
	--counter) [ $# -ge 2 ] || usage; COUNTER=$2; shift 2 ;;
	--git) [ $# -ge 2 ] || usage; GIT_DIRS="$GIT_DIRS $2"; shift 2 ;;
	--floor) [ $# -ge 2 ] || usage; is_num "$2" || die "--floor '$2' is not a number"; EXPLICIT="$EXPLICIT $2"; shift 2 ;;
	--seen)
		[ $# -ge 2 ] || usage
		n=$(n_of_version "$2") || die "--seen '$2' is not a 0.0.N version"
		SEEN="$SEEN $n"
		shift 2
		;;
	--claim)
		[ $# -ge 2 ] || usage
		CLAIM=$(n_of_version "$2") || die "--claim '$2' is not a 0.0.N version"
		shift 2
		;;
	--force-jump) FORCE_JUMP=1; shift ;;
	--no-probe) PROBE=0; shift ;;
	-h | --help) sed -n '2,97p' "$0" 2>/dev/null || true; exit 0 ;;
	*) usage ;;
	esac
done

for x in $MARGIN $MAX_JUMP; do is_num "$x" || die "margin/max-jump '$x' is not a number"; done
command -v flock >/dev/null 2>&1 || die "flock(1) not found (util-linux); refusing to allocate without a lock"

for d in $GIT_DIRS; do
	for rev in HEAD origin/master; do
		c=$(git -C "$d" rev-list --count "$rev" 2>/dev/null || true)
		if is_num "$c"; then SEEN="$SEEN $c"; fi
	done
done

# ── what is DEPLOYED (read-only; before the lock) ──
probe_nodes() {
	if [ "${XPF_DEB_VERSION_PROBE_CMD+set}" = set ]; then
		[ -z "$XPF_DEB_VERSION_PROBE_CMD" ] || sh -c "$XPF_DEB_VERSION_PROBE_CMD"
		return 0
	fi
	for ref in $NODES; do
		v=$(timeout "$PROBE_TIMEOUT" incus exec -n "$ref" -- dpkg-query -W -f '${Version}' xpf 2>/dev/null || true)
		printf '%s %s\n' "$ref" "${v:-unknown}"
	done
}
DEPLOYED=""
UNKNOWN=""
N_NODES=0
if [ "$PROBE" -eq 1 ]; then
	PROBED=$(probe_nodes)
	# A redirected loop runs in this shell, so its assignments persist.
	while read -r ref ver; do
		[ -n "$ref" ] || continue
		N_NODES=$((N_NODES + 1))
		if [ -z "$ver" ] || [ "$ver" = unknown ]; then
			UNKNOWN="$UNKNOWN $ref"
		elif n=$(n_of_version "$ver"); then
			DEPLOYED="$DEPLOYED $n" # census-guard: deployed
		else
			warn "$ref runs xpf $ver, outside the 0.0.N space: no 0.0.N allocation can upgrade it"
		fi
	done <<EOF_PROBE
$PROBED
EOF_PROBE
	if [ "$N_NODES" -eq 0 ]; then UNKNOWN=" (no nodes)"; fi
	if [ -n "$UNKNOWN" ]; then warn "could not read the deployed version on:$UNKNOWN"; fi
fi

dir=$(dirname -- "$COUNTER")
mkdir -p -- "$dir" || die "cannot create $dir"
LOCK="$COUNTER.lock"

# Everything below runs with fd 9 holding an exclusive lock.
exec 9>>"$LOCK" || die "cannot open lock $LOCK"
flock -w 30 9 || die "could not lock $LOCK within 30 s" # census-guard: lock

have_counter=0
cur=0
if [ -e "$COUNTER" ]; then
	have_counter=1
	cur=$(tr -d ' \t\r\n' <"$COUNTER") || die "cannot read $COUNTER"
	if ! is_num "$cur"; then # census-guard: malformed-counter
		die "counter $COUNTER holds '$cur', not a number; refusing (a reset would reissue versions). Fix it by hand to at least the highest version in use."
	fi
fi

dep_max=$(max_of "$DEPLOYED")
exp_max=$(max_of "$EXPLICIT")
dep_floor=""
if [ -n "$dep_max" ]; then
	dep_floor=$dep_max
	# The margin applies only when the counter is created; after that the
	# counter itself is ahead of the hand-picked builds it was clearing.
	if [ "$have_counter" -eq 0 ]; then dep_floor=$((dep_max + MARGIN)); fi
fi

# Creating the counter needs a TRUSTED floor: every probed node answered, or
# an explicit one. Otherwise the first number could be a downgrade somewhere.
if [ "$have_counter" -eq 0 ] && [ -z "$exp_max" ]; then # census-guard: init-floor
	if [ "$PROBE" -eq 0 ] || [ -n "$UNKNOWN" ] || [ -z "$dep_max" ]; then
		die "no counter at $COUNTER and no trusted floor: the deployed version was not read on every node (${UNKNOWN:-probe disabled}). Pass --floor N or XPF_DEB_VERSION_FLOOR=N (at least the highest version any node runs)."
	fi
fi

# The reference the jump guard measures from.
ref=$(max_of "$dep_floor $exp_max")
[ -n "$ref" ] || ref=$cur

base=$(max_of "$cur $dep_floor $exp_max $SEEN")
if [ -n "$CLAIM" ]; then
	if [ "$CLAIM" -le "$base" ]; then # census-guard: claim
		die "--claim 0.0.$CLAIM refused: it is at or below the counter/deployed floor ($base). A hand-picked number must be above every allocation and every deployed version; rebuild with an allocated version."
	fi
	next=$CLAIM
else
	next=$((base + 1))
fi

if [ "$next" -gt $((ref + MAX_JUMP)) ] && [ "$FORCE_JUMP" -eq 0 ]; then # census-guard: jump
	die "refusing to allocate 0.0.$next: more than $MAX_JUMP above the reference $ref (counter $cur, deployed ${dep_max:-unknown}, explicit floor ${exp_max:-none}, seen/git $(max_of "$SEEN")). Once a node ran it, every ordinary build would be a downgrade there. Pass --force-jump only if that is intended."
fi

if [ -n "${XPF_NEXT_DEB_VERSION_HOLD_S:-}" ]; then
	sleep "$XPF_NEXT_DEB_VERSION_HOLD_S"
fi

tmp="$COUNTER.tmp.$$"
printf '%s\n' "$next" >"$tmp" || { rm -f -- "$tmp"; die "cannot write $tmp"; }
mv -f -- "$tmp" "$COUNTER" || { rm -f -- "$tmp"; die "cannot replace $COUNTER"; }

# Stray debs on disk: never a floor, only a warning.
stray=""
stray_n=0
for g in $SCAN; do
	for f in $g; do
		[ -f "$f" ] || continue
		b=${f##*/}
		v=${b#xpf_}
		v=${v%%_*}
		n=$(n_of_version "$v") || continue
		if [ "$n" -ge "$next" ]; then
			stray_n=$((stray_n + 1))
			[ -n "$stray" ] || stray=$f
		fi
	done
done
if [ "$stray_n" -gt 0 ]; then
	warn "warning: $stray_n deb(s) on disk at or above 0.0.$next (e.g. $stray). They are NOT a floor; deploying one makes this allocation a downgrade on that node."
fi

printf '0.0.%s\n' "$next"
