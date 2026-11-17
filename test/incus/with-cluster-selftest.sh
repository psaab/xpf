#!/usr/bin/env bash
#
# #1875 — dry-run contention matrix for the shared-cluster lock cell
# (plan §9.2). Exercises with-cluster.sh + cluster-lock.sh against a
# PRIVATE lock path under /tmp — never touches the real
# `/var/worktrees/.cache/tmpdir/xpf-cluster.lock`, no cluster access, safe to run anywhere.
#
#   ./test/incus/with-cluster-selftest.sh
#
# Exits 0 with "ALL n CASES PASS" or non-zero naming the failed case.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WC="${SCRIPT_DIR}/with-cluster.sh"

T=$(mktemp -d /tmp/xpf-lock-selftest.XXXXXX)
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin"
cat >"$T/bin/incus" <<'STUB'
#!/usr/bin/env bash
if [[ "$1" == list ]]; then
	if [[ "${2:-}" == *: ]]; then name="${3:-}"; else name="${2#*:}"; fi
	printf '[{"name":"%s","type":"virtual-machine"}]\n' "$name"
fi
if [[ "$*" == *"/proc/sys/kernel/random/boot_id"* ]]; then
	printf '00000000-0000-0000-0000-000000000001\n'
fi
exit 0
STUB
chmod +x "$T/bin/incus"
PATH="$T/bin:$PATH"
export PATH
export XPF_CLUSTER_LOCK="$T/lock"
# #10126 keeps the persistent epoch sidecar separate from the lock
# inode so legacy `9>` probes cannot erase it.
export XPF_CLUSTER_EPOCH="$T/epoch"
# Hermetic: never probe a real cluster for build identity (the lock cell
# samples it at acquire/release; these cases are about the LOCK).
export XPF_CLUSTER_BUILD_PROBE=0
export XPF_CLUSTER_OWNER="$T/owner"

PASS=0
ok()   { PASS=$((PASS + 1)); echo "PASS ($PASS): $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

# Wait (bounded) for a condition.
waitfor() { # waitfor <seconds> <desc> <cmd...>
	local n=$(( $1 * 10 )) desc="$2"; shift 2
	while (( n-- > 0 )); do
		if "$@" 2>/dev/null; then return 0; fi
		sleep 0.1
	done
	fail "timeout waiting for: $desc"
}

# ── (a) holder blocks a second cell; waiter prints the named-holder report
"$WC" "case-a holder" -- bash -c 'echo started >"'"$T"'/a.start"; sleep 6' &
A_PID=$!
waitfor 5 "cell A started" test -f "$T/a.start"
set +e
XPF_CLUSTER_LOCK_TIMEOUT=1 "$WC" "case-a waiter" -- true >"$T/a.out" 2>&1
A_RC=$?
set -e
[[ $A_RC -eq 75 ]] || fail "(a) waiter expected timeout exit 75, got $A_RC"
grep -q "case-a holder" "$T/a.out" || fail "(a) waiter report missing holder purpose"
grep -q "held by pid" "$T/a.out" || fail "(a) waiter report missing holder pid"
ok "waiter blocks and reports holder pid+purpose, timeout honors XPF_CLUSTER_LOCK_TIMEOUT"
wait "$A_PID" || true

# ── (b) kill -9 of the wrapper (the SOLE fd-9 holder) plus its direct
#        children releases the lock immediately. Deeper grandchildren
#        may survive as orphans, but they run with fd 9 closed and can
#        never hold the lock — wrapper death IS lock release.
"$WC" "case-b victim" -- bash -c 'echo started >"'"$T"'/b.start"; sleep 60' &
B_PID=$!
waitfor 5 "cell B started" test -f "$T/b.start"
pkill -9 -P "$B_PID" 2>/dev/null || true
kill -9 "$B_PID" 2>/dev/null || true
wait "$B_PID" 2>/dev/null || true
XPF_CLUSTER_LOCK_TIMEOUT=35 "$WC" "case-b reclaim" -- true \
	|| fail "(b) lock not reclaimable after kill -9 of holder"
ok "kill -9 of the wrapper releases the lock (no orphan holder)"

# ── (c) nested cell is reentrant; outer owner metadata survives the
#        inner cell's exit (acquired-only trap rule)
"$WC" "case-c outer" -- bash -c '
	"'"$WC"'" "case-c inner" -- true || exit 40
	[ -f "'"$T"'/owner" ] || exit 41          # inner exit must NOT remove owner
	grep -q "case-c outer" "'"$T"'/owner" || exit 42
' || fail "(c) nested reentrancy / owner-preservation failed (rc=$?)"
[[ ! -f "$T/owner" ]] || fail "(c) outer cell did not clean owner on exit"
ok "nested cell runs lock-free; inner exit preserves outer owner metadata"

# ── (d) forged/stale markers are rejected (acquire proceeds normally)
# d1: live but non-ancestor pid
sleep 30 & NONANC=$!
XPF_CLUSTER_LOCK_HELD="$XPF_CLUSTER_LOCK:$NONANC" "$WC" "case-d1" -- true \
	|| fail "(d1) live non-ancestor marker did not degrade to acquire"
kill "$NONANC" 2>/dev/null || true
# d2: dead pid (spawn+reap a short-lived sleep)
sleep 0.01 & DEAD=$!; wait "$DEAD" || true
XPF_CLUSTER_LOCK_HELD="$XPF_CLUSTER_LOCK:$DEAD" "$WC" "case-d2" -- true \
	|| fail "(d2) dead-pid marker did not degrade to acquire"
# d3: mismatched lock path with a real ancestor pid ($$ IS our ancestor)
XPF_CLUSTER_LOCK_HELD="/tmp/some-other.lock:$$" "$WC" "case-d3" -- true \
	|| fail "(d3) wrong-path marker did not degrade to acquire"
# d4: garbage marker
XPF_CLUSTER_LOCK_HELD="garbage" "$WC" "case-d4" -- true \
	|| fail "(d4) garbage marker did not degrade to acquire"
ok "forged/stale/wrong-path/garbage markers all rejected; acquire proceeds"

# ── (e) stale + corrupt owner files never crash or block an acquire
echo "999999999 2020-01-01T00:00:00 nobody dead-branch 1:1 stale" >"$XPF_CLUSTER_OWNER"
"$WC" "case-e stale" -- true || fail "(e) stale owner file broke acquire"
printf '\0\0garbage\n' >"$XPF_CLUSTER_OWNER"
"$WC" "case-e corrupt" -- true || fail "(e) corrupt owner file broke acquire"
: >"$XPF_CLUSTER_OWNER"
"$WC" "case-e empty" -- true || fail "(e) empty owner file broke acquire"
ok "stale/corrupt/empty owner files tolerated under set -euo pipefail"

# ── (f) exit-status propagation + owner cleanup on failure
set +e
"$WC" "case-f" -- bash -c 'exit 3'
F_RC=$?
set -e
[[ $F_RC -eq 3 ]] || fail "(f) expected exit 3, got $F_RC"
[[ ! -f "$XPF_CLUSTER_OWNER" ]] || fail "(f) owner file leaked after failing cell"
ok "cell exit status propagates (3) and owner file is cleaned"

# ── (g) split-mutex: rm the lock while held → fail-closed abort naming inodes
"$WC" "case-g holder" -- bash -c 'echo started >"'"$T"'/g.start"; sleep 8' &
G_PID=$!
waitfor 5 "cell G started" test -f "$T/g.start"
OLD_INO=$(stat -c %d:%i "$XPF_CLUSTER_LOCK")
rm -f "$XPF_CLUSTER_LOCK"        # the documented NEVER-do — simulate it
set +e
"$WC" "case-g intruder" -- true >"$T/g.out" 2>&1
G_RC=$?
set -e
[[ $G_RC -eq 70 ]] || fail "(g) expected split-mutex abort 70, got $G_RC (out: $(cat "$T/g.out"))"
grep -q "SPLIT MUTEX" "$T/g.out" || fail "(g) abort missing SPLIT MUTEX diagnosis"
grep -q "$OLD_INO" "$T/g.out" || fail "(g) abort does not name the held inode"
wait "$G_PID" || true
# After the real holder exits, acquire on the new inode must succeed
# (dead recorded pid → stale metadata path).
"$WC" "case-g reclaim" -- true || fail "(g) post-holder reclaim failed"
ok "rm-while-held fails closed with SPLIT MUTEX diagnosis; reclaim works after holder exits"

# ── (h) marker + XPF_CLUSTER_SKIP_BUILD survive the EXACT
#        cluster-setup.sh sg re-exec shape: the same ${!BPFRX_@}/${!XPF_@}
#        forwarding loop, the same rebuilt-%q-command-string boundary,
#        and real `sg` when this host has the incus-admin group
#        (bash -c stands in otherwise). This pins the
#        deadlock/double-build regression path (Codex code-r1 F3).
# shellcheck disable=SC2016  # single quotes deliberate: expansion happens inside the cell
# #19165: a nested cell may not switch the cluster env, so the forwarded
# BPFRX_CLUSTER_ENV is the enclosing cell's own (a real file), not a fake one.
H_ENV="$(cd "${SCRIPT_DIR}/../.." && pwd)/test/incus/udp-userspace-cluster.env"
BPFRX_CLUSTER_ENV="$H_ENV" "$WC" "case-h outer" -- env XPF_CLUSTER_SKIP_BUILD=1 bash -c '
	# Replicate cluster-setup.sh lines 39-60 verbatim: dynamic prefix
	# forwarding + printf %q command rebuild + group re-exec.
	local_env=""
	for _v in "${!BPFRX_@}" "${!XPF_@}"; do
		local_env+="${_v}=$(printf "%q" "${!_v}") "
	done
	inner="${local_env}$(printf "%q " "'"$WC"'" case-h-inner -- bash -c "[ \"\${XPF_CLUSTER_SKIP_BUILD:-}\" = 1 ] && [ \"\${BPFRX_CLUSTER_ENV:-}\" = '"$H_ENV"' ]")"
	if command -v sg >/dev/null 2>&1 && id -nG | grep -qw incus-admin; then
		sg incus-admin -c "$inner"
	else
		bash -c "$inner"
	fi
' || fail "(h) marker/skip-build/env did not survive the sg-shaped forwarding re-exec"
ok "marker + skip-build survive the real \${!XPF_@} forwarding loop across the sg boundary"

# ── (i) builtins cannot subvert the cell: `exec` is not an external
#        command, the cell fails (127) without releasing early or
#        leaking owner metadata (env -- contract, Codex code-r1 F1)
set +e
"$WC" "case-i builtin" -- exec true 2>/dev/null
I_RC=$?
set -e
[[ $I_RC -eq 127 ]] || fail "(i) builtin cell expected 127, got $I_RC"
[[ ! -f "$XPF_CLUSTER_OWNER" ]] || fail "(i) owner file leaked after builtin rejection"
"$WC" "case-i reclaim" -- true || fail "(i) lock not clean after builtin rejection"
ok "shell builtins are rejected (127) without breaking the lock or leaking owner state"

# ── (j) timeout normalization: leading-zero values are base-10, not a
#        silent octal arithmetic error (Codex code-r1 F2); absurd
#        values degrade to wait-forever instead of overflowing
"$WC" "case-j holder" -- bash -c 'echo started >"'"$T"'/j.start"; sleep 4' &
J_PID=$!
waitfor 5 "cell J started" test -f "$T/j.start"
set +e
XPF_CLUSTER_LOCK_TIMEOUT=08 "$WC" "case-j octal" -- true >"$T/j.out" 2>&1
J_RC=$?
set -e
# "08" must behave as 8 seconds: holder exits at ~4s, so the waiter
# ACQUIRES (rc 0) — an octal error would have produced arithmetic
# noise; a disabled timeout is indistinguishable here, so also check
# no arithmetic error text leaked.
[[ $J_RC -eq 0 ]] || fail "(j) leading-zero timeout broke acquire (rc=$J_RC)"
grep -qi "value too great\|arithmetic" "$T/j.out" && fail "(j) octal arithmetic error leaked"
wait "$J_PID" || true
XPF_CLUSTER_LOCK_TIMEOUT=99999999999999999999 "$WC" "case-j huge" -- true \
	|| fail "(j) absurd timeout value broke acquire"
ok "timeout env normalizes base-10 and degrades absurd values safely"

# ── #19165: a lock tuple and a cluster env that name different clusters are
#    refused before the lock is taken, and the command never runs. A matched
#    pair runs; a private lock path (no cluster) is not checked.
mkdir -p "$T/k"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
set +e
XPF_CLUSTER_LOCK="$T/k/xpf-cluster-udp.lock" XPF_CLUSTER_OWNER="$T/k/owner" XPF_CLUSTER_EPOCH="$T/k/epoch" \
	BPFRX_CLUSTER_ENV="${REPO_ROOT}/test/incus/loss-userspace-cluster.env" \
	"$WC" "case-k mismatch" -- touch "$T/k/ran" >"$T/k.out" 2>&1
K_RC=$?
set -e
[[ $K_RC -eq 2 && ! -e "$T/k/ran" ]] || fail "(k) udp lock + loss env: expected refusal (2) with the command not run, got rc=$K_RC ran=$([[ -e "$T/k/ran" ]] && echo yes || echo no): $(tr '\n' '|' <"$T/k.out")"
grep -q 'REFUSED: the lock tuple is the udp cluster.*resolve INCUS_REMOTE=loss' "$T/k.out" || fail "(k) the refusal does not name both clusters: $(tr '\n' '|' <"$T/k.out")"
[[ ! -s "$T/k/owner" ]] || fail "(k) the refused cell wrote an owner file: it took the lock"
XPF_CLUSTER_LOCK="$T/k/xpf-cluster-udp.lock" XPF_CLUSTER_OWNER="$T/k/owner" XPF_CLUSTER_EPOCH="$T/k/epoch" \
	BPFRX_CLUSTER_ENV="${REPO_ROOT}/test/incus/udp-userspace-cluster.env" \
	"$WC" "case-k matched" -- touch "$T/k/ran" >"$T/k2.out" 2>&1 || fail "(k) udp lock + udp env was refused: $(tr '\n' '|' <"$T/k2.out")"
[[ -e "$T/k/ran" ]] || fail "(k) udp lock + udp env: the command did not run"
ok "a lock tuple and a cluster env naming different clusters are refused before the lock (#19165); a matched pair runs"

# ── #19165 fold (Codex on b7g, N2): the RESOLVED targets are checked, not
#    only the env label. (l) The udp env and udp lock with an explicit
#    FW0=loss:... (cluster-env.sh keeps a qualified override) is refused, the
#    command not run; an explicit udp: override runs. (m) A nested cell (the
#    reentrant path, under its ancestor's udp lock) that overrides FW0 to loss
#    is refused too.
mkdir -p "$T/l"
UDP_ENV="${REPO_ROOT}/test/incus/udp-userspace-cluster.env"
set +e
XPF_CLUSTER_LOCK="$T/l/xpf-cluster-udp.lock" XPF_CLUSTER_OWNER="$T/l/owner" XPF_CLUSTER_EPOCH="$T/l/epoch" \
	BPFRX_CLUSTER_ENV="$UDP_ENV" FW0=loss:xpf-userspace-fw0 \
	"$WC" "case-l override" -- touch "$T/l/ran" >"$T/l.out" 2>&1
L_RC=$?
set -e
[[ $L_RC -eq 2 && ! -e "$T/l/ran" ]] || fail "(l) udp lock + udp env + FW0=loss:...: expected refusal (2) with the command not run, got rc=$L_RC: $(tr '\n' '|' <"$T/l.out")"
grep -q 'REFUSED: the lock tuple is the udp cluster.*FW0=loss:xpf-userspace-fw0 is on the loss cluster' "$T/l.out" || fail "(l) the refusal does not name the target: $(tr '\n' '|' <"$T/l.out")"
[[ ! -s "$T/l/owner" ]] || fail "(l) the refused cell wrote an owner file: it took the lock"
XPF_CLUSTER_LOCK="$T/l/xpf-cluster-udp.lock" XPF_CLUSTER_OWNER="$T/l/owner" XPF_CLUSTER_EPOCH="$T/l/epoch" \
	BPFRX_CLUSTER_ENV="$UDP_ENV" FW0=udp:xpf-udp-fw0 \
	"$WC" "case-l same-cluster override" -- touch "$T/l/ran" >"$T/l2.out" 2>&1 || fail "(l) an explicit udp: override under the udp lock was refused: $(tr '\n' '|' <"$T/l2.out")"
[[ -e "$T/l/ran" ]] || fail "(l) the explicit udp: override did not run"
rm -f "$T/l/ran"
set +e
XPF_CLUSTER_LOCK="$T/l/xpf-cluster-udp.lock" XPF_CLUSTER_OWNER="$T/l/owner" XPF_CLUSTER_EPOCH="$T/l/epoch" \
	BPFRX_CLUSTER_ENV="$UDP_ENV" \
	"$WC" "case-m outer" -- bash -c 'FW0=loss:xpf-userspace-fw0 "$0" "case-m inner" -- touch "$1/ran"; echo $? >"$1/inner.rc"' "$WC" "$T/l" >"$T/m.out" 2>&1
M_RC=$?
set -e
[[ $M_RC -eq 0 && "$(cat "$T/l/inner.rc" 2>/dev/null)" == 2 && ! -e "$T/l/ran" ]] || fail "(m) a nested cell overriding FW0 to loss under the outer udp lock: expected the inner refused (2) and nothing run, got outer=$M_RC inner=$(cat "$T/l/inner.rc" 2>/dev/null): $(tr '\n' '|' <"$T/m.out")"
grep -q 'FW0=loss:xpf-userspace-fw0 is on the loss cluster' "$T/m.out" || fail "(m) the nested refusal does not name the target: $(tr '\n' '|' <"$T/m.out")"
ok "resolved FW0/FW1 are checked against the lock's cluster (#19165, Codex on b7g N2): an explicit loss: override is refused, also on the reentrant path; a same-cluster override runs"

# ── #19165 total target rule (Codex on b7g/b7h: N2, N7, N8). wc_run <tag>
#    <env> <lock-cluster> [VAR=val ...] -- <cmd...>: one cell under a cluster
#    lock tuple in $T/<tag>, output in $T/<tag>.out, status printed.
wc_run() {
	local tag=$1 envf=$2 cl=$3; shift 3
	local -a vars=()
	while [[ $# -gt 0 && "$1" != -- ]]; do vars+=("$1"); shift; done
	shift
	mkdir -p "$T/$tag"
	set +e
	env "${vars[@]}" XPF_CLUSTER_LOCK="$T/$tag/xpf-cluster-${cl}.lock" XPF_CLUSTER_OWNER="$T/$tag/owner" \
		XPF_CLUSTER_EPOCH="$T/$tag/epoch" BPFRX_CLUSTER_ENV="$envf" "$WC" "case-$tag" -- "$@" >"$T/$tag.out" 2>&1
	echo $?
	set -e
}
LOSS_ENV="${REPO_ROOT}/test/incus/loss-userspace-cluster.env"
# (n) the resolver-reset shape: the outer udp cell's command sources the loss
#     env, then nests with BPFRX_CLUSTER_ENV back on udp: refused.
rc=$(wc_run n "$UDP_ENV" udp -- bash -c 'export BPFRX_CLUSTER_ENV="$3"; source "$4/cluster-env.sh" >/dev/null; BPFRX_CLUSTER_ENV="$2" "$0" "case-n inner" -- touch "$1/ran"; echo $? >"$1/inner.rc"' "$WC" "$T/n" "$UDP_ENV" "$LOSS_ENV" "$SCRIPT_DIR")
[[ $rc -eq 0 && "$(cat "$T/n/inner.rc" 2>/dev/null)" == 2 && ! -e "$T/n/ran" ]] && grep -q "a nested cell's targets are not the set its enclosing cell validated" "$T/n.out" ||
	fail "(n) resolver-reset nested cell: rc=$rc inner=$(cat "$T/n/inner.rc" 2>/dev/null): $(tr '\n' '|' <"$T/n.out")"
# (o) N2, a BARE override. Non-nested: allowed, and the command sees it
#     QUALIFIED (it runs with the resolved values). Nested: refused.
rc=$(wc_run o "$UDP_ENV" udp FW1=xpf-udp-fw1 -- bash -c 'printf "%s %s %s\n" "$FW1" "$INCUS_REMOTE" "${#XPF_CLUSTER_TARGETS_DIGEST}" >"$0/seen"' "$T/o")
[[ $rc -eq 0 && "$(cat "$T/o/seen" 2>/dev/null)" == "udp:xpf-udp-fw1 udp 64" ]] ||
	fail "(o) a bare FW1 override, non-nested: rc=$rc seen=[$(cat "$T/o/seen" 2>/dev/null)], want the qualified value and a digest: $(tr '\n' '|' <"$T/o.out")"
rc=$(wc_run o2 "$UDP_ENV" udp -- bash -c 'FW1=xpf-udp-fw1 "$0" "case-o2 inner" -- touch "$1/ran"; echo $? >"$1/inner.rc"' "$WC" "$T/o2")
[[ $rc -eq 0 && "$(cat "$T/o2/inner.rc" 2>/dev/null)" == 2 && ! -e "$T/o2/ran" ]] && grep -q "a nested cell's targets are not the set .*(FW1=xpf-udp-fw1)" "$T/o2.out" ||
	fail "(o) a bare FW1 override, nested: inner=$(cat "$T/o2/inner.rc" 2>/dev/null): $(tr '\n' '|' <"$T/o2.out")"
# (p) N7, CLUSTER_LAN_HOST on loss under the udp lock: refused, non-nested
#     and nested.
rc=$(wc_run p "$UDP_ENV" udp CLUSTER_LAN_HOST=loss:cluster-userspace-host -- touch "$T/p/ran")
[[ $rc -eq 2 && ! -e "$T/p/ran" ]] && grep -q 'CLUSTER_LAN_HOST=loss:cluster-userspace-host is on the loss cluster' "$T/p.out" ||
	fail "(p) CLUSTER_LAN_HOST on loss, non-nested: rc=$rc: $(tr '\n' '|' <"$T/p.out")"
rc=$(wc_run p2 "$UDP_ENV" udp -- bash -c 'CLUSTER_LAN_HOST=loss:cluster-userspace-host "$0" "case-p2 inner" -- touch "$1/ran"; echo $? >"$1/inner.rc"' "$WC" "$T/p2")
[[ "$(cat "$T/p2/inner.rc" 2>/dev/null)" == 2 && ! -e "$T/p2/ran" ]] ||
	fail "(p) CLUSTER_LAN_HOST on loss, nested: inner=$(cat "$T/p2/inner.rc" 2>/dev/null): $(tr '\n' '|' <"$T/p2.out")"
# (q) N8, an inherited INCUS_REMOTE=loss with the udp FW0/FW1 and env:
#     refused (the env file would overwrite it only in the resolver).
rc=$(wc_run q "$UDP_ENV" udp -- bash -c 'INCUS_REMOTE=loss "$0" "case-q inner" -- touch "$1/ran"; echo $? >"$1/inner.rc"' "$WC" "$T/q")
[[ "$(cat "$T/q/inner.rc" 2>/dev/null)" == 2 && ! -e "$T/q/ran" ]] && grep -q "a nested cell's targets are not the set .*(INCUS_REMOTE=loss)" "$T/q.out" ||
	fail "(q) inherited INCUS_REMOTE=loss, nested: inner=$(cat "$T/q/inner.rc" 2>/dev/null): $(tr '\n' '|' <"$T/q.out")"
# (r) a ref that resolves BARE under a remote env (DMZ_TARGET_REF keeps an
#     override as given): refused, it would address the default remote.
rc=$(wc_run r "$UDP_ENV" udp DMZ_TARGET_REF=xpf-zone-matrix-dmz -- touch "$T/r/ran")
[[ $rc -eq 2 && ! -e "$T/r/ran" ]] && grep -q 'DMZ_TARGET_REF=xpf-zone-matrix-dmz resolves bare' "$T/r.out" ||
	fail "(r) a bare DMZ_TARGET_REF: rc=$rc: $(tr '\n' '|' <"$T/r.out")"
# (s) controls: a qualified same-cluster override runs, non-nested and
#     nested; a plain nested cell runs.
rc=$(wc_run s "$UDP_ENV" udp CLUSTER_LAN_HOST=udp:cluster-udp-host -- bash -c '"$0" "case-s inner" -- touch "$1/ran"' "$WC" "$T/s")
[[ $rc -eq 0 && -e "$T/s/ran" ]] || fail "(s) qualified same-cluster override + nested: rc=$rc: $(tr '\n' '|' <"$T/s.out")"
# (u) the STRIPPED shape (cluster-setup.sh's sg re-exec forwards only
#     BPFRX_*/XPF_*): a nested cell with no target variables re-resolves and
#     runs when it resolves the enclosing cell's set; with the env switched to
#     loss it is refused.
rc=$(wc_run u "$UDP_ENV" udp -- bash -c 'fwd=(); for v in "${!BPFRX_@}" "${!XPF_@}"; do fwd+=("$v=${!v}"); done
	env -i HOME="$HOME" PATH="$PATH" "${fwd[@]}" "$0" "case-u inner" -- touch "$1/ran"; echo $? >"$1/inner.rc"
	env -i HOME="$HOME" PATH="$PATH" "${fwd[@]}" BPFRX_CLUSTER_ENV="$2" "$0" "case-u loss" -- touch "$1/loss-ran"; echo $? >"$1/loss.rc"' "$WC" "$T/u" "$LOSS_ENV")
[[ "$(cat "$T/u/inner.rc" 2>/dev/null)" == 0 && -e "$T/u/ran" && "$(cat "$T/u/loss.rc" 2>/dev/null)" == 2 && ! -e "$T/u/loss-ran" ]] ||
	fail "(u) stripped nested env: inner=$(cat "$T/u/inner.rc" 2>/dev/null) loss=$(cat "$T/u/loss.rc" 2>/dev/null): $(tr '\n' '|' <"$T/u.out")"
# (u2) under a lock that names no cluster (no remote check applies), the
#      digest alone must refuse a stripped nested cell that switches env.
rc=$(wc_run u2 "$UDP_ENV" private -- bash -c 'fwd=(); for v in "${!BPFRX_@}" "${!XPF_@}"; do fwd+=("$v=${!v}"); done
	env -i HOME="$HOME" PATH="$PATH" "${fwd[@]}" BPFRX_CLUSTER_ENV="$2" "$0" "case-u2 inner" -- touch "$1/ran"; echo $? >"$1/inner.rc"' "$WC" "$T/u2" "$LOSS_ENV")
[[ "$(cat "$T/u2/inner.rc" 2>/dev/null)" == 2 && ! -e "$T/u2/ran" ]] && grep -q "a nested cell's targets are not the set" "$T/u2.out" ||
	fail "(u2) stripped nested env switch under a private lock: inner=$(cat "$T/u2/inner.rc" 2>/dev/null): $(tr '\n' '|' <"$T/u2.out")"
# (t) census: every variable cluster-env.sh exports with a remote-qualified
#     value, and every *_REF / *_NAME, is in with-cluster.sh's target set.
set_line=$(sed -n 's/^XPF_CLUSTER_TARGET_VARS="\(.*\)"$/\1/p' "$WC")
for envf in "$LOSS_ENV" "${REPO_ROOT}/test/incus/tcp-userspace-cluster.env" "$UDP_ENV"; do
	outside=$(env -i HOME="$HOME" PATH="$PATH" BPFRX_CLUSTER_ENV="$envf" bash -c '
		source "$1/cluster-env.sh" >/dev/null 2>&1
		for v in $(compgen -e); do
			case "${!v}" in loss:*|tcp:*|udp:*) echo "$v" ;; esac
			case "$v" in *_REF|*_NAME|FW[0-9]|CLUSTER_LAN_HOST|INCUS_REMOTE) echo "$v" ;; esac
		done' _ "$SCRIPT_DIR" | sort -u | while read -r v; do [[ " $set_line " == *" $v "* ]] || echo "$v"; done)
	[[ -z "$outside" ]] || fail "(t) $(basename "$envf") exports instance/remote variables outside the target set: $outside"
done
[[ -n "$set_line" ]] || fail "(t) cannot read XPF_CLUSTER_TARGET_VARS from with-cluster.sh"
ok "#19165 total target rule: resolver-reset (n), bare override (o; qualified when run, refused nested), CLUSTER_LAN_HOST on loss (p), inherited INCUS_REMOTE (q), bare ref (r), same-cluster controls (s), stripped sg-shaped env (u), target-set census (t)"

echo "ALL ${PASS} CASES PASS"
