#!/usr/bin/env bash
# Self-test for scripts/next-deb-version.sh (#18645).
#
# Hermetic: a private counter, fixture deb names and a throwaway git repo under
# a mktemp -d. It never touches the shared counter
# (/var/worktrees/.cache/deb-version-counter): every call passes --counter, and
# XPF_DEB_VERSION_COUNTER points into the work dir as a second fence.
#
# The property that matters, concurrent callers never sharing a number, cannot
# be shown by a passing run alone: a racy allocator usually passes when the
# callers happen not to overlap. So the concurrency cell holds the lock open
# (XPF_NEXT_DEB_VERSION_HOLD_S) to force every caller to overlap, and a mutant
# with the flock removed must produce duplicates under the same load. A mutant
# that does not flip its cell is an ESCAPE and fails this self-test.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ALLOC="${SCRIPT_DIR}/next-deb-version.sh"

PASS=0
FAIL=0
ok()  { echo "  ok   — $*"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL — $*" >&2; FAIL=$((FAIL + 1)); }

[[ -f "$ALLOC" ]] || { echo "FATAL: allocator not found at $ALLOC" >&2; exit 1; }
command -v flock >/dev/null 2>&1 || { echo "SKIP: flock(1) not installed" >&2; exit 77; }

if [[ -z "${TMPDIR:-}" ]]; then mkdir -p /var/worktrees/.cache/tmpdir; fi
WORK="$(mktemp -d "${TMPDIR:-/var/worktrees/.cache/tmpdir}/next-deb-version-selftest.XXXXXX")" \
	|| { echo "FATAL: cannot create work dir" >&2; exit 2; }
[[ -n "$WORK" && -d "$WORK" ]] || { echo "FATAL: work dir not created: '$WORK'" >&2; exit 2; }
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT
export XPF_DEB_VERSION_COUNTER="$WORK/never-used-counter"
export XPF_DEB_VERSION_SCAN=""

mutant() {
	local name=$1
	shift
	local out="$WORK/mutant-$name.sh" e
	cp "$ALLOC" "$out"
	for e in "$@"; do
		sed -i "$e" "$out"
	done
	if cmp -s "$ALLOC" "$out"; then
		bad "mutation '$name' changed NOTHING (a census-guard tag moved)"
	fi
	echo "$out"
}

# concurrent <script> <counter> <n> <hold> -> the n allocated versions, sorted
concurrent() {
	local script=$1 counter=$2 n=$3 hold=$4 i
	rm -rf "$WORK/out"
	mkdir -p "$WORK/out"
	for i in $(seq 1 "$n"); do
		XPF_NEXT_DEB_VERSION_HOLD_S=$hold sh "$script" --counter "$counter" --no-scan \
			>"$WORK/out/$i" 2>/dev/null &
	done
	wait
	cat "$WORK/out"/* | sort -t. -k3,3n
}

# ── cell C: concurrent allocations are unique and gap-free ────────────────
N=8
got=$(concurrent "$ALLOC" "$WORK/c-conc" "$N" 0.2)
uniq_n=$(printf '%s\n' "$got" | sort -u | grep -c . || true)
want=$(for i in $(seq 1 "$N"); do echo "0.0.$i"; done)
if [[ "$uniq_n" -eq "$N" && "$got" == "$want" && "$(cat "$WORK/c-conc")" == "$N" ]]; then
	ok "concurrent: $N overlapping callers got $N distinct versions 0.0.1..0.0.$N, counter left at $N"
else
	bad "concurrent: expected 0.0.1..0.0.$N once each; got: $(printf '%s ' $got)"
fi
M_LOCK="$(mutant no-lock '/census-guard: lock$/s/^flock -w 30 9 || die .*/true/')"
got=$(concurrent "$M_LOCK" "$WORK/c-nolock" "$N" 0.2)
uniq_n=$(printf '%s\n' "$got" | sort -u | grep -c . || true)
if [[ "$uniq_n" -lt "$N" ]]; then
	ok "concurrent mutation: without the flock the same load hands out duplicates ($uniq_n distinct of $N)"
else
	bad "concurrent mutation ESCAPED: $N distinct versions without the lock, so the cell cannot see a race"
fi

# ── cell M: sequential allocations are strictly increasing ────────────────
prev=0
mono=1
for _ in 1 2 3 4 5; do
	v=$(sh "$ALLOC" --counter "$WORK/c-seq" --no-scan) || mono=0
	n=${v#0.0.}
	[[ "$n" -gt "$prev" ]] || mono=0
	prev=$n
done
if [[ $mono -eq 1 && "$prev" -eq 5 ]]; then
	ok "monotonic: five sequential calls return 0.0.1..0.0.5"
else
	bad "monotonic: sequence broke (last $prev)"
fi

# ── cell F: initialised above the highest version SEEN ────────────────────
mkdir -p "$WORK/wt-a/dist-deb" "$WORK/wt-b/dist-deb"
: >"$WORK/wt-a/dist-deb/xpf_0.0.500+gabcdef012345_amd64.deb"
: >"$WORK/wt-b/dist-deb/xpf_0.0.480+g0123456789ab.dirty_amd64.deb"
: >"$WORK/wt-b/dist-deb/xpf_99.0.5+selftest_amd64.deb"
: >"$WORK/wt-b/dist-deb/xpf-appliance_0.0.900_all.deb"
v=$(XPF_DEB_VERSION_SCAN="$WORK/*/dist-deb/xpf_*.deb" sh "$ALLOC" --counter "$WORK/c-scan" 2>"$WORK/scan.err")
if [[ "$v" == "0.0.501" ]] && grep -q 'xpf_0.0.500' "$WORK/scan.err"; then
	ok "floor (scan): the first allocation is above the highest 0.0.N deb on disk (0.0.501), ignores 99.0.x and the appliance deb, and names its source"
else
	bad "floor (scan): expected 0.0.501 with its source named; got '$v' / $(cat "$WORK/scan.err")"
fi
M_FLOOR="$(mutant no-floor '/census-guard: floor$/s/for f in $FLOORS; do/for f in ; do/')"
v=$(XPF_DEB_VERSION_SCAN="$WORK/*/dist-deb/xpf_*.deb" sh "$M_FLOOR" --counter "$WORK/c-scan-m" 2>/dev/null)
if [[ "$v" != "0.0.501" ]]; then
	ok "floor mutation: ignoring the floors allocates $v, a downgrade, so the cell has power"
else
	bad "floor mutation ESCAPED: still 0.0.501 without the floors"
fi

v=$(sh "$ALLOC" --counter "$WORK/c-seen" --no-scan --seen 0.0.700+g1234 --floor 650)
if [[ "$v" == "0.0.701" ]]; then
	ok "floor (--seen/--floor): a version read off a node raises the counter (0.0.701)"
else
	bad "floor (--seen/--floor): expected 0.0.701, got '$v'"
fi

echo 1000 >"$WORK/c-high"
v=$(sh "$ALLOC" --counter "$WORK/c-high" --no-scan --floor 10)
if [[ "$v" == "0.0.1001" ]]; then
	ok "floor below counter: a lower floor never lowers the counter (0.0.1001)"
else
	bad "floor below counter: expected 0.0.1001, got '$v'"
fi

if command -v git >/dev/null 2>&1; then
	G="$WORK/repo"
	git init -q "$G" && for i in 1 2 3; do
		git -C "$G" -c user.name=t -c user.email=t@t commit -q --allow-empty -m "c$i"
	done
	v=$(sh "$ALLOC" --counter "$WORK/c-git" --no-scan --git "$G" 2>/dev/null)
	if [[ "$v" == "0.0.4" ]]; then
		ok "floor (--git): a stock build's number (the commit count, 3) is below the allocation (0.0.4)"
	else
		bad "floor (--git): expected 0.0.4, got '$v'"
	fi
else
	echo "  skip — floor (--git): git not installed"
fi

# ── cell X: a malformed counter is refused, never reset ───────────────────
# Two shapes: junk, and an EMPTY file (a counter truncated by a full disk or
# a crash mid-write). The empty one is the dangerous one: shell arithmetic
# reads an empty value as 0, so without the check the counter silently
# restarts at 1 and reissues every version.
for shape in junk empty; do
	if [[ $shape == junk ]]; then echo "not-a-number" >"$WORK/c-bad"; else : >"$WORK/c-bad"; fi
	before=$(cat "$WORK/c-bad")
	if sh "$ALLOC" --counter "$WORK/c-bad" --no-scan >/dev/null 2>"$WORK/bad.err"; then
		bad "malformed counter ($shape): the allocator accepted it"
	elif [[ "$(cat "$WORK/c-bad")" == "$before" ]] && grep -q 'refusing' "$WORK/bad.err"; then
		ok "malformed counter ($shape): refused, and the counter file is unchanged"
	else
		bad "malformed counter ($shape): refused but the file changed or the reason is missing"
	fi
done
M_BAD="$(mutant accept-bad-counter '/census-guard: malformed-counter$/s/if ! is_num "$cur"; then/if false; then/')"
: >"$WORK/c-bad-m"
if v=$(sh "$M_BAD" --counter "$WORK/c-bad-m" --no-scan 2>/dev/null); then
	ok "malformed counter mutation: without the check an empty counter silently restarts at $v, so the cell has power"
else
	bad "malformed counter mutation ESCAPED: the mutant still refuses an empty counter"
fi

# The second fence: nothing above wrote the env-default counter.
if [[ ! -e "$XPF_DEB_VERSION_COUNTER" ]]; then
	ok "isolation: no call fell back to the default counter path"
else
	bad "isolation: a call wrote $XPF_DEB_VERSION_COUNTER"
fi

echo ""
echo "next-deb-version-selftest: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
