#!/usr/bin/env bash
# Self-test for scripts/next-deb-version.sh (#18645).
#
# Hermetic: a private counter, a stub in place of the node probe, fixture deb
# names and a throwaway git repo under a mktemp -d. It never touches the shared
# counter (/var/worktrees/.cache/deb-version-counter) and never reaches a lab
# node: every call passes --counter, XPF_DEB_VERSION_COUNTER points into the
# work dir as a second fence, and XPF_DEB_VERSION_PROBE_CMD is ALWAYS set.
#
# Each verdict is a cell plus a MUTATION of the line tagged `census-guard:
# <name>` that must flip it; a mutant that does not flip is an ESCAPE and fails
# this self-test. The concurrency cell holds the lock open
# (XPF_NEXT_DEB_VERSION_HOLD_S) so every caller overlaps: a racy allocator
# usually passes when callers happen not to overlap.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
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
unset XPF_DEB_VERSION_FLOOR XPF_DEB_VERSION_NODES XPF_DEB_VERSION_MARGIN XPF_DEB_VERSION_MAX_JUMP
# The stub probe: prints $WORK/deployed (one `<node> <version|unknown>` per line).
: >"$WORK/deployed"
export XPF_DEB_VERSION_PROBE_CMD="cat $WORK/deployed"
deployed() { printf '%s\n' "$@" >"$WORK/deployed"; }

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

# alloc <script> <counter> [args...] -> stdout in OUT, stderr in ERR, rc in RC
alloc() {
	local script=$1 counter=$2
	shift 2
	OUT=$(sh "$script" --counter "$counter" "$@" 2>"$WORK/err")
	RC=$?
	ERR=$(cat "$WORK/err")
}

# concurrent <script> <counter> <n> <hold> -> the n allocated versions, sorted
concurrent() {
	local script=$1 counter=$2 n=$3 hold=$4 i
	rm -rf "$WORK/out"
	mkdir -p "$WORK/out"
	for i in $(seq 1 "$n"); do
		XPF_NEXT_DEB_VERSION_HOLD_S=$hold sh "$script" --counter "$counter" \
			>"$WORK/out/$i" 2>/dev/null &
	done
	wait
	cat "$WORK/out"/* | sort -t. -k3,3n
}

# ── cell C: concurrent allocations are unique and gap-free ────────────────
deployed
N=8
echo 0 >"$WORK/c-conc"
got=$(concurrent "$ALLOC" "$WORK/c-conc" "$N" 0.2)
uniq_n=$(printf '%s\n' "$got" | sort -u | grep -c . || true)
want=$(for i in $(seq 1 "$N"); do echo "0.0.$i"; done)
if [[ "$uniq_n" -eq "$N" && "$got" == "$want" && "$(cat "$WORK/c-conc")" == "$N" ]]; then
	ok "concurrent: $N overlapping callers got $N distinct versions 0.0.1..0.0.$N, counter left at $N"
else
	bad "concurrent: expected 0.0.1..0.0.$N once each; got: $(printf '%s ' $got)"
fi
M_LOCK="$(mutant no-lock '/census-guard: lock$/s/^flock -w 30 9 || die .*/true/')"
echo 0 >"$WORK/c-nolock"
got=$(concurrent "$M_LOCK" "$WORK/c-nolock" "$N" 0.2)
uniq_n=$(printf '%s\n' "$got" | sort -u | grep -c . || true)
if [[ "$uniq_n" -lt "$N" ]]; then
	ok "concurrent mutation: without the flock the same load hands out duplicates ($uniq_n distinct of $N)"
else
	bad "concurrent mutation ESCAPED: $N distinct versions without the lock, so the cell cannot see a race"
fi

# ── cell M: sequential allocations are strictly increasing ────────────────
echo 0 >"$WORK/c-seq"
prev=0
mono=1
for _ in 1 2 3 4 5; do
	alloc "$ALLOC" "$WORK/c-seq"
	n=${OUT#0.0.}
	[[ $RC -eq 0 && "$n" -gt "$prev" ]] || mono=0
	prev=$n
done
if [[ $mono -eq 1 && "$prev" -eq 5 ]]; then
	ok "monotonic: five sequential calls return 0.0.1..0.0.5"
else
	bad "monotonic: sequence broke (last '$prev')"
fi

# ── cell D: the floor is what is DEPLOYED (plus the margin, at creation) ──
deployed "loss:fw0 0.0.26810+ga09bf21815d1" "loss:fw1 0.0.26810+ga09bf21815d1" \
	"tcp:fw0 0.0.26809+g3541ebf7743b" "udp:fw0 0.0.26621+g080b228b37d1"
alloc "$ALLOC" "$WORK/c-dep"
first=$OUT
alloc "$ALLOC" "$WORK/c-dep"
if [[ "$first" == "0.0.26911" && "$OUT" == "0.0.26912" ]]; then
	ok "deployed floor: a new counter starts at the deployed max + margin + 1 (0.0.26911); the margin applies once (next 0.0.26912)"
else
	bad "deployed floor: expected 0.0.26911 then 0.0.26912, got '$first' then '$OUT'"
fi
M_DEP="$(mutant ignore-deployed '/census-guard: deployed$/s/DEPLOYED="$DEPLOYED $n"/:/')"
alloc "$M_DEP" "$WORK/c-dep-m"
if [[ "$OUT" != "0.0.26911" ]]; then
	ok "deployed floor mutation: ignoring the probe no longer yields 0.0.26911 (rc=$RC), so the cell has power"
else
	bad "deployed floor mutation ESCAPED"
fi

# ── cell S: a stray deb on disk is NOT a floor, only a warning ────────────
# The defect this replaces: a hand-built 0.0.99999 in a worktree made the
# first allocation 0.0.100000, and every ordinary build a downgrade after it.
mkdir -p "$WORK/wt-a/dist-deb" "$WORK/wt-b/dist-deb"
: >"$WORK/wt-a/dist-deb/xpf_0.0.99999+gdisc16109.dirty_amd64.deb"
: >"$WORK/wt-b/dist-deb/xpf_0.0.26700+gabcdef012345_amd64.deb"
OUT=$(XPF_DEB_VERSION_SCAN="$WORK/*/dist-deb/xpf_*.deb" sh "$ALLOC" --counter "$WORK/c-stray" 2>"$WORK/err")
RC=$?
ERR=$(cat "$WORK/err")
if [[ $RC -eq 0 && "$OUT" == "0.0.26911" && "$ERR" == *"xpf_0.0.99999"*"NOT a floor"* ]]; then
	ok "stray deb: 0.0.99999 on disk leaves the allocation at 0.0.26911 and is reported as NOT a floor"
else
	bad "stray deb: expected 0.0.26911 plus a warning naming the stray; got '$OUT' rc=$RC / $ERR"
fi
M_STRAY="$(mutant stray-silent 's/^if \[ "$stray_n" -gt 0 \]; then/if false; then/')"
ERR=$(XPF_DEB_VERSION_SCAN="$WORK/*/dist-deb/xpf_*.deb" sh "$M_STRAY" --counter "$WORK/c-stray-m" 2>&1 >/dev/null)
if [[ "$ERR" != *"NOT a floor"* ]]; then
	ok "stray deb mutation: without the warning the stray goes unreported, so the cell has power"
else
	bad "stray deb mutation ESCAPED"
fi

# ── cell J: a jump above floor + MAX_JUMP is refused without --force-jump ─
echo 50000 >"$WORK/c-jump"
alloc "$ALLOC" "$WORK/c-jump"
if [[ $RC -ne 0 && "$ERR" == *"refusing to allocate 0.0.50001"*"--force-jump"* && "$(cat "$WORK/c-jump")" == 50000 ]]; then
	ok "jump: a counter 23190 above the deployed 0.0.26810 is refused, and the counter is unchanged"
else
	bad "jump: expected a refusal and an unchanged counter; got '$OUT' rc=$RC / $ERR"
fi
alloc "$ALLOC" "$WORK/c-jump" --force-jump
if [[ $RC -eq 0 && "$OUT" == "0.0.50001" ]]; then
	ok "jump: --force-jump allocates it (0.0.50001)"
else
	bad "jump: --force-jump should allocate 0.0.50001, got '$OUT' rc=$RC"
fi
echo 26912 >"$WORK/c-seen"
alloc "$ALLOC" "$WORK/c-seen" --seen 0.0.99999
if [[ $RC -ne 0 && "$ERR" == *"refusing to allocate 0.0.100000"* ]]; then
	ok "jump: --seen 0.0.99999 (the stray, fed in as a floor) is refused rather than allocating 0.0.100000"
else
	bad "jump: expected --seen 0.0.99999 to be refused; got '$OUT' rc=$RC"
fi
alloc "$ALLOC" "$WORK/c-seen" --seen 0.0.27000+gx
if [[ $RC -eq 0 && "$OUT" == "0.0.27001" ]]; then
	ok "jump: a --seen within MAX_JUMP raises the counter (0.0.27001)"
else
	bad "jump: expected 0.0.27001, got '$OUT' rc=$RC"
fi
M_JUMP="$(mutant no-jump-guard '/census-guard: jump$/s/if \[ "$next" -gt $((ref + MAX_JUMP)) \] && \[ "$FORCE_JUMP" -eq 0 \]; then/if false; then/')"
echo 50000 >"$WORK/c-jump-m"
alloc "$M_JUMP" "$WORK/c-jump-m"
if [[ $RC -eq 0 ]]; then
	ok "jump mutation: without the guard the jump is allocated ($OUT), so the cell has power"
else
	bad "jump mutation ESCAPED: still refused"
fi

# ── cell I: creating the counter needs a TRUSTED floor ────────────────────
deployed "loss:fw0 unknown" "loss:fw1 unknown"
alloc "$ALLOC" "$WORK/c-init-none"
if [[ $RC -ne 0 && "$ERR" == *"no trusted floor"* && ! -e "$WORK/c-init-none" ]]; then
	ok "init: no node readable and no explicit floor is refused (no counter created)"
else
	bad "init: expected a refusal; got '$OUT' rc=$RC"
fi
deployed "loss:fw0 0.0.26810+gx" "udp:fw1 unknown"
alloc "$ALLOC" "$WORK/c-init-partial"
if [[ $RC -ne 0 && "$ERR" == *"udp:fw1"* ]]; then
	ok "init: one unreadable node refuses creation and names the node"
else
	bad "init: expected a refusal naming udp:fw1; got '$OUT' rc=$RC"
fi
alloc "$ALLOC" "$WORK/c-init-partial" --floor 26900
if [[ $RC -eq 0 && "$OUT" == "0.0.26911" ]]; then
	ok "init: an explicit --floor lets it start (max(26810+100, 26900)+1 = 0.0.26911)"
else
	bad "init: expected 0.0.26911 with --floor 26900, got '$OUT' rc=$RC"
fi
deployed
OUT=$(XPF_DEB_VERSION_FLOOR=30000 sh "$ALLOC" --counter "$WORK/c-init-env" 2>/dev/null)
if [[ "$OUT" == "0.0.30001" ]]; then
	ok "init: XPF_DEB_VERSION_FLOOR=30000 with no nodes starts at 0.0.30001"
else
	bad "init: expected 0.0.30001 from XPF_DEB_VERSION_FLOOR, got '$OUT'"
fi
deployed "loss:fw0 unknown"
alloc "$ALLOC" "$WORK/c-init-partial"
if [[ $RC -eq 0 && "$OUT" == "0.0.26912" && "$ERR" == *"could not read"* ]]; then
	ok "after creation: an unreadable node only warns; the counter is the floor (0.0.26912)"
else
	bad "after creation: expected 0.0.26912 with a warning, got '$OUT' rc=$RC"
fi
M_INIT="$(mutant no-init-guard '/census-guard: init-floor$/s/if \[ "$have_counter" -eq 0 \] && \[ -z "$exp_max" \]; then/if false; then/')"
deployed "loss:fw0 unknown"
alloc "$M_INIT" "$WORK/c-init-m"
if [[ $RC -eq 0 ]]; then
	ok "init mutation: without the guard an unread lab starts the counter at $OUT, a downgrade everywhere"
else
	bad "init mutation ESCAPED: still refused"
fi

# ── cell K: --claim refuses a hand-picked number at or below the counter ──
deployed "loss:fw0 0.0.26810+gx"
echo 26911 >"$WORK/c-claim"
alloc "$ALLOC" "$WORK/c-claim" --claim 0.0.26850+gdeadbeef
if [[ $RC -ne 0 && "$ERR" == *"--claim 0.0.26850 refused"* && "$(cat "$WORK/c-claim")" == 26911 ]]; then
	ok "claim: a hand-picked 0.0.26850 at or below the counter (26911) is refused"
else
	bad "claim: expected a refusal; got '$OUT' rc=$RC / $ERR"
fi
alloc "$ALLOC" "$WORK/c-claim" --claim 0.0.27000
c_after=$(cat "$WORK/c-claim")
alloc "$ALLOC" "$WORK/c-claim"
if [[ "$c_after" == 27000 && "$OUT" == "0.0.27001" ]]; then
	ok "claim: a number above both is reserved in the counter, so the next allocation is 0.0.27001"
else
	bad "claim: expected the counter at 27000 then 0.0.27001; got '$c_after' then '$OUT'"
fi
M_CLAIM="$(mutant no-claim-guard '/census-guard: claim$/s/if \[ "$CLAIM" -le "$base" \]; then/if false; then/')"
echo 26911 >"$WORK/c-claim-m"
alloc "$M_CLAIM" "$WORK/c-claim-m" --claim 0.0.26850
if [[ $RC -eq 0 ]]; then
	ok "claim mutation: without the guard the at-or-below number is accepted, so the cell has power"
else
	bad "claim mutation ESCAPED: still refused"
fi

# ── cell N: a node outside the 0.0.N space is reported ────────────────────
deployed "lab:fw0 99.0.5+selftest" "lab:fw1 0.0.26810+gx"
alloc "$ALLOC" "$WORK/c-odd"
if [[ $RC -eq 0 && "$ERR" == *"lab:fw0 runs xpf 99.0.5+selftest, outside the 0.0.N space"* ]]; then
	ok "non-0.0 node: a node running 99.0.x is reported (no 0.0.N can upgrade it)"
else
	bad "non-0.0 node: expected the warning; got rc=$RC / $ERR"
fi

# ── cell G: --git folds in the commit counts ──────────────────────────────
if command -v git >/dev/null 2>&1; then
	G="$WORK/repo"
	git init -q "$G" && for i in 1 2 3; do
		git -C "$G" -c user.name=t -c user.email=t@t commit -q --allow-empty -m "c$i"
	done
	deployed
	echo 0 >"$WORK/c-git"
	alloc "$ALLOC" "$WORK/c-git" --git "$G"
	if [[ "$OUT" == "0.0.4" ]]; then
		ok "--git: a stock build's number (the commit count, 3) is below the allocation (0.0.4)"
	else
		bad "--git: expected 0.0.4, got '$OUT' rc=$RC"
	fi
else
	echo "  skip — --git: git not installed"
fi

# ── cell X: a malformed counter is refused, never reset ───────────────────
# Two shapes: junk, and an EMPTY file (truncated by a full disk or a crash
# mid-write). Shell arithmetic reads an empty value as 0, so without the check
# the counter silently restarts and reissues every version.
deployed "loss:fw0 0.0.26810+gx"
for shape in junk empty; do
	if [[ $shape == junk ]]; then echo "not-a-number" >"$WORK/c-bad"; else : >"$WORK/c-bad"; fi
	before=$(cat "$WORK/c-bad")
	alloc "$ALLOC" "$WORK/c-bad"
	if [[ $RC -ne 0 && "$(cat "$WORK/c-bad")" == "$before" && "$ERR" == *"refusing"* ]]; then
		ok "malformed counter ($shape): refused, and the counter file is unchanged"
	else
		bad "malformed counter ($shape): expected a refusal with the file unchanged; got '$OUT' rc=$RC"
	fi
done
M_BAD="$(mutant accept-bad-counter '/census-guard: malformed-counter$/s/if ! is_num "$cur"; then/if false; then/')"
: >"$WORK/c-bad-m"
alloc "$M_BAD" "$WORK/c-bad-m" --floor 0
if [[ $RC -eq 0 ]]; then
	ok "malformed counter mutation: without the check an empty counter silently restarts at $OUT, so the cell has power"
else
	bad "malformed counter mutation ESCAPED: the mutant still refuses an empty counter"
fi

# ── cell L: the default node list is the three cluster env files' nodes ───
want_nodes=""
for c in loss tcp udp; do
	env="$REPO_ROOT/test/incus/$c-userspace-cluster.env"
	r=$(sed -n 's/^INCUS_REMOTE="\(.*\)"$/\1/p' "$env")
	v0=$(sed -n 's/^VM0="\(.*\)"$/\1/p' "$env")
	v1=$(sed -n 's/^VM1="\(.*\)"$/\1/p' "$env")
	want_nodes="$want_nodes $r:$v0 $r:$v1"
done
have_nodes=$(sed -n 's/^DEFAULT_NODES="\(.*\)"$/\1/p' "$ALLOC")
if [[ "$(echo $want_nodes)" == "$have_nodes" && -n "$have_nodes" ]]; then
	ok "node list: DEFAULT_NODES equals the six loss/tcp/udp fw0/fw1 nodes in the env files ($have_nodes)"
else
	bad "node list: DEFAULT_NODES '$have_nodes' != env files '$(echo $want_nodes)'"
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
