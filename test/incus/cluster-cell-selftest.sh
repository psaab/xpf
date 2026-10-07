#!/usr/bin/env bash
#
# #4020 — self-test for the destructive-smoke lock preamble
# (test/incus/cluster-cell.sh, helper xpf_enter_destructive_cluster_cell).
#
# Two halves, both runnable ANYWHERE — no incus, no cluster, no network,
# and NEVER touching the real /tmp/xpf-cluster.lock (a PRIVATE lock path
# under a temp dir is used throughout):
#
#   STATIC   — every DESTRUCTIVE HA smoke script routes through the
#              #1875 lock cell (sources cluster-cell.sh AND calls
#              xpf_enter_destructive_cluster_cell in its preamble). This
#              is the RED-on-revert guard: reverting #4020 drops the
#              wiring and this half fails, naming the unprotected script.
#              Read-only test-connectivity.sh must stay lock-free.
#
#   BEHAVIORAL — the helper actually serializes: a standalone run
#              acquires the lock and runs its body; a second concurrent
#              run QUEUES (blocks) behind the held lock instead of
#              colliding; and a run already inside a with-cluster.sh
#              cell runs lock-free (reentrant, no deadlock).
#
# Usage: ./test/incus/cluster-cell-selftest.sh   (rc 0 = all pass)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WC="${SCRIPT_DIR}/with-cluster.sh"

PASS=0
ok()   { PASS=$((PASS + 1)); echo "PASS ($PASS): $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

waitfor() { # waitfor <seconds> <desc> <cmd...>
	local n=$(( $1 * 10 )) desc="$2"; shift 2
	while (( n-- > 0 )); do
		if "$@" 2>/dev/null; then return 0; fi
		sleep 0.1
	done
	fail "timeout waiting for: $desc"
}

# ── STATIC: every destructive smoke script routes through the lock ────
#
# These are the scripts whose Makefile targets reboot / force-stop /
# fail over / restart a node on the SHARED loss cluster. Each MUST
# source cluster-cell.sh and call the entry helper in its preamble.
#
# #6936: the set is now DERIVED, not enumerated. It used to be the
# hardcoded list below, which is a floor rather than a census: a NEW
# destructive smoke is covered only if whoever wrote it also remembered
# to add its name here, and a guard that has to be told about its own
# subject is the shape that let test-fbf-steering.sh go ungated (#7798).
# The detector that decides "is line N a node mutation" already existed
# further down for the ordering assertion; running it over every
# test-*.sh makes it decide membership too.
#
# KNOWN_DESTRUCTIVE stays as a FLOOR assertion in the other direction:
# each named script must still be DETECTED as destructive, so a
# regression in the detector (a changed heredoc shape, a renamed verb)
# reports as a missing script rather than as a silently empty scan.
KNOWN_DESTRUCTIVE=(
	test-failover.sh
	test-ha-crash.sh
	test-double-failover.sh
	test-stress-failover.sh
	test-chained-crash.sh
	test-active-active.sh
	test-restart-connectivity.sh
	test-private-rg.sh
)

# xpf_first_mutation_line <script> — prints the first non-comment line number
# that reboots / force-stops / fails over / restarts a node, or the literal
# NONE when the script does none of those. `failover reset` is skipped: it
# clears a manual latch and moves nothing.
#
# FAIL-CLOSED, deliberately. The obvious form is `awk ... || true`, printing
# the line number or nothing — but then "this script performs no node
# mutation" and "awk did not run" are the SAME empty string, and the second
# one silently DROPS a destructive script out of the scanned set. This is now
# the predicate that decides membership, so a fail-open detector would quietly
# stop guarding scripts rather than say so.
#
# That is not hypothetical: during #6936 one run of this file reported
# test-private-rg.sh as "not matched" while the machine was saturated by a
# concurrent `go test ./...`, and every re-run under a quiet machine passed.
# With the old fail-open form the failure is not diagnosable after the fact —
# an awk that could not fork is indistinguishable from a clean non-match — so
# the shape is fixed rather than the (unreproducible) instance explained.
# An empty return now means the helper itself failed, and callers fail on it.
xpf_first_mutation_line() {
	local out
	out="$(awk '
		/^[[:space:]]*#/ { next }
		/failover reset/ { next }
		/incus (stop|start|restart) |sysrq|systemctl (stop|restart)|request chassis cluster failover redundancy-group/ { print NR; found = 1; exit }
		END { if (!found) print "NONE" }
	' "$1")" || return 1
	[[ -n "$out" ]] || return 1
	printf '%s\n' "$out"
}

DESTRUCTIVE=()
for p in "${SCRIPT_DIR}"/test-*.sh; do
	[[ -f "$p" ]] || continue
	_mut="$(xpf_first_mutation_line "$p")" \
		|| fail "static: the destructive-script detector could not read $(basename "$p") — refusing to treat an unread script as non-destructive"
	[[ "$_mut" == NONE ]] && continue
	DESTRUCTIVE+=("$(basename "$p")")
done
(( ${#DESTRUCTIVE[@]} > 0 )) \
	|| fail "static: the destructive-script detector matched 0 of $(ls -1 "${SCRIPT_DIR}"/test-*.sh | wc -l) test-*.sh scripts — a scan that reaches nothing passes clean while guarding nothing"
for known in "${KNOWN_DESTRUCTIVE[@]}"; do
	[[ -f "${SCRIPT_DIR}/${known}" ]] || fail "static: missing destructive smoke script $known"
	# Pure-bash membership. `printf ... | grep -q` would be the idiomatic form,
	# but `grep -q` exits at the first match and SIGPIPEs the writer, which
	# under `set -o pipefail` reports the WRITER's failure — the exact shape
	# that broke the instance-liveness check in test-host-inbound.sh. It was
	# NOT observed to fire on a list this short; the pipe is avoided on
	# principle, not on evidence.
	_found=no
	for d in "${DESTRUCTIVE[@]}"; do [[ "$d" == "$known" ]] && _found=yes; done
	[[ "$_found" == yes ]] \
		|| fail "static: $known is a known destructive smoke but the detector did not match it — the detector regressed, and every UNLISTED destructive script it also stopped matching is now unguarded"
done
ok "static: detector matched ${#DESTRUCTIVE[@]} destructive test-*.sh scripts (covers all ${#KNOWN_DESTRUCTIVE[@]} known ones)"

for s in "${DESTRUCTIVE[@]}"; do
	p="${SCRIPT_DIR}/${s}"
	[[ -f "$p" ]] || fail "static: missing destructive smoke script $s"
	# The wiring must sit in the preamble (first 60 lines), BEFORE any
	# incus mutation — assert both the source and the call are present
	# and appear before the first destructive incus/systemctl op.
	head_n="$(head -n 60 "$p")"
	# Literal match of the source line — the ${...} must NOT expand.
	# shellcheck disable=SC2016
	grep -q 'source "\${_CELL_DIR}/cluster-cell.sh"' <<<"$head_n" \
		|| fail "static: $s does not source cluster-cell.sh in its preamble (#4020 lock dropped?)"
	call_line=$(grep -n 'xpf_enter_destructive_cluster_cell' "$p" | head -1 | cut -d: -f1)
	[[ -n "$call_line" ]] \
		|| fail "static: $s never calls xpf_enter_destructive_cluster_cell (#4020 lock dropped?)"
	# First line that reboots / force-stops / fails over / restarts a
	# node. The lock call must precede it so we never mutate the shared
	# cluster before acquiring the lock. Skip comment lines so a "Phase
	# 1: incus stop --force" doc line is not mistaken for a real op.
	mut_line=$(xpf_first_mutation_line "$p") \
		|| fail "static: the destructive-script detector could not read $s"
	[[ "$mut_line" == NONE ]] && mut_line=""
	if [[ -n "$mut_line" ]]; then
		(( call_line < mut_line )) \
			|| fail "static: $s mutates the cluster (line $mut_line) before taking the lock (line $call_line)"
	fi
	ok "static: $s takes the #1875 lock (line $call_line) before any node mutation"
done

# Read-only connectivity test must NOT take the cluster lock (the lock
# header forbids read-only verbs from holding it — e.g. interactive ssh).
if grep -q 'cluster-cell.sh' "${SCRIPT_DIR}/test-connectivity.sh"; then
	fail "static: read-only test-connectivity.sh must not take the cluster lock"
fi
ok "static: read-only test-connectivity.sh stays lock-free"

# #9922 F-158: lock-free does NOT mean lock-blind. When the read-only gate
# samples the SHARED cluster it must probe lock idleness (fail-fast VOID
# on contention) instead of holding the lock.
if ! grep -q 'cluster-lock\.sh' "${SCRIPT_DIR}/test-connectivity.sh"; then
	fail "static: test-connectivity.sh must source cluster-lock.sh for the F-158 idleness probe"
fi
ok "static: test-connectivity.sh sources cluster-lock.sh (idleness probe, not a lock cell)"
# The probe must live in test_cluster (the shared-cluster sampler), not in
# test_standalone (dedicated local instances need no probe).
if ! sed -n '/^test_cluster() {/,/^}/p' "${SCRIPT_DIR}/test-connectivity.sh" | grep -q 'xpf_assert_cluster_lock_idle'; then
	fail "static: test-connectivity.sh test_cluster must call the F-158 lock-idleness probe"
fi
ok "static: test-connectivity.sh test_cluster calls the lock-idleness probe"
# The probe must NOT live in test_standalone (dedicated local instances
# need no probe — pin probe-free so a copy-paste never adds contention
# VOIDs to a lane that can never contend).
if sed -n '/^test_standalone() {/,/^}/p' "${SCRIPT_DIR}/test-connectivity.sh" | grep -q 'xpf_assert_cluster_lock_idle'; then
	fail "static: test-connectivity.sh test_standalone must not call the F-158 lock-idleness probe"
fi
ok "static: test-connectivity.sh test_standalone stays probe-free"

# ── BEHAVIORAL: private lock path + fake incus, no cluster ────────────
T=$(mktemp -d /tmp/xpf-cell-selftest.XXXXXX)
trap 'rm -rf "$T"' EXIT
export XPF_CLUSTER_LOCK="$T/lock"
# #10126 keeps the persistent epoch sidecar separate from the lock
# inode so legacy `9>` probes cannot erase it.
export XPF_CLUSTER_EPOCH="$T/epoch"
# Hermetic: never probe a real cluster for build identity (the lock cell
# samples it at acquire/release; these cases are about the LOCK).
export XPF_CLUSTER_BUILD_PROBE=0
export XPF_CLUSTER_OWNER="$T/owner"

# Fake `incus` on PATH: succeeds so the helper's incus-admin sg branch
# is never taken (keeps the test hermetic — no group juggling, no real
# incus). The helper then exercises the pure lock-cell logic.
mkdir -p "$T/bin"
cat >"$T/bin/incus" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
chmod +x "$T/bin/incus"
export PATH="$T/bin:$PATH"

# #11581 Groups 10–12: execute the REAL test_cluster function with an incus
# command stub. The checks validate emitted verdicts and warning text; no live
# cluster or network is contacted.
CONNECTIVITY_FUNCTION="${T}/connectivity-test-cluster.sh"
python3 - "${SCRIPT_DIR}/test-connectivity.sh" "$CONNECTIVITY_FUNCTION" <<'PY'
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
match = re.search(r"^test_cluster\(\) \{\n.*?^\}\n", source, re.M | re.S)
if not match:
    raise SystemExit("cannot extract test_cluster for Group 10–12 behavior tests")
pathlib.Path(sys.argv[2]).write_text(match.group(0), encoding="utf-8")
PY
CONNECTIVITY_RUNNER="${T}/connectivity-group-runner.sh"
cat >"$CONNECTIVITY_RUNNER" <<'RUNNER'
#!/usr/bin/env bash
set -euo pipefail
source "$2/ha-assurance-lib.sh"
source "$1"
SCRIPT_DIR="$2"
FW0=fw0 FW1=fw1 CLUSTER_LAN_HOST=lan
WAN_GW4=10.0.0.1 LAN_HOST_IP=172.16.80.10 LAN_VIP4=172.16.80.1
LAN_VIP6=2001:559:8585:80::1 IPERF_TARGET4=1.1.1.1
IPERF_TARGET6=2606:4700:4700::1111
PASS=0 FAIL=0 VOID=0
info() { :; }
pass() { printf '  PASS  %s\n' "$*"; PASS=$((PASS + 1)); }
fail() { printf '  FAIL  %s\n' "$*"; FAIL=$((FAIL + 1)); }
void() { printf '  VOID  %s\n' "$*"; VOID=$((VOID + 1)); }
skip() { printf '  SKIP  %s\n' "$*"; }
assurance_verdict() {
	case "$1" in
	0) pass "$2" ;;
	1) fail "$2" ;;
	*) void "$2" ;;
	esac
}
instance_running() { return 0; }
xpf_assert_cluster_lock_idle() { :; }
service_check() { :; }
ping_test() { :; }
ping6_test() { :; }
mtr_test() { :; }
internet_test() { :; }
incus() {
	local command="$*"
	printf '%s\n' "$command" >>"$INCUS_TRACE"
	case "$command" in
	*"which iperf3"*) return 1 ;;
	*"ping -c 1 -W 2 -t 1 1.1.1.1"*)
		if [[ "$TEST_MODE" == ttl-void ]]; then
			printf 'ping: command not found\n'
			return 2
		elif [[ "$TEST_MODE" == ttl-fail ]]; then
			printf '1 packets transmitted, 1 received, 0%% packet loss\n'
		else
			printf 'From 10.0.0.1 icmp_seq=1 Time to live exceeded\n'
		fi
		;;
	*"ping -6 -c 1 -W 2 -t 1 2607:f8b0:4005:814::200e"*)
		printf 'From 2001:db8::1 icmp_seq=1 Time exceeded: Hop limit\n'
		;;
	*"mtr 1.1.1.1 --report --report-cycles=1"*)
		if [[ "$TEST_MODE" == mtr4-fail ]]; then
			printf ' 1.|-- 10.0.0.1 0.0%% 1 1.0 1.0 1.0 1.0 0.0\n 2.|-- ??? 100.0%% 1 0.0 0.0 0.0 0.0 0.0\n'
		else
			printf ' 1.|-- 10.0.0.1 0.0%% 1 1.0 1.0 1.0 1.0 0.0\n 2.|-- 1.1.1.1 0.0%% 1 1.0 1.0 1.0 1.0 0.0\n'
		fi
		;;
	*"mtr -6 2607:f8b0:4005:814::200e --report --report-cycles=1"*)
		printf ' 1.|-- 2001:db8::1 0.0%% 1 1.0 1.0 1.0 1.0 0.0\n 2.|-- ??? 100.0%% 1 0.0 0.0 0.0 0.0 0.0\n'
		;;
	*"ip route get 172.16.80.200"*)
		if [[ "$TEST_MODE" == route-void ]]; then
			printf 'route query failed\n'
			return 2
		elif [[ "$TEST_MODE" == route-local-fail ]]; then
			printf 'local 172.16.80.200 dev lo src 172.16.80.200\n'
		else
			printf '172.16.80.200 dev eth0 src 10.0.0.1\n'
		fi
		;;
	*"ip -6 route get 2001:559:8585:80::200"*)
		printf '2001:559:8585:80::200 dev eth0 src 2001:db8::1\n'
		;;
	*"ping -c 2 -W 1 172.16.80.200"*)
		if [[ "$TEST_MODE" == ping-fail ]]; then
			printf '2 packets transmitted, 0 received, 100%% packet loss\n'
			return 1
		fi
		printf '2 packets transmitted, 2 received, 0%% packet loss\n'
		;;
	*"ping -6 -c 2 -W 1 2001:559:8585:80::200"*)
		printf '2 packets transmitted, 2 received, 0%% packet loss\n'
		;;
	*"ip neigh show 172.16.80.200 dev "*)
		printf '172.16.80.200 lladdr 00:11:22:33:44:55 REACHABLE\n'
		;;
	*"ip -6 neigh show 2001:559:8585:80::200 dev "*)
		if [[ "$TEST_MODE" == neighbor-fail ]]; then
			printf '2001:559:8585:80::200 lladdr 00:11:22:33:44:66 STALE\n'
		else
			printf '2001:559:8585:80::200 lladdr 00:11:22:33:44:55 STALE\n'
		fi
		;;
	*)
		printf 'unexpected incus command: %s\n' "$command" >&2
		return 95
		;;
	esac
}
test_cluster
printf 'COUNTS PASS=%s FAIL=%s VOID=%s\n' "$PASS" "$FAIL" "$VOID"
RUNNER
chmod +x "$CONNECTIVITY_RUNNER"

run_connectivity_case() {
	local mode="$1" counts="$2" output trace neighbor_count trace_contents
	trace="${T}/connectivity-${mode}.trace"
	if ! output="$(TEST_MODE="$mode" INCUS_TRACE="$trace" \
		"$CONNECTIVITY_RUNNER" "$CONNECTIVITY_FUNCTION" "$SCRIPT_DIR" 2>&1)"; then
		fail "Group 10–12 ${mode}: test_cluster execution failed: ${output}"
	fi
	[[ "$output" == *"COUNTS ${counts}"* ]] \
		|| fail "Group 10–12 ${mode}: expected COUNTS ${counts}; got ${output}"
	[[ "$output" != *"unexpected incus command"* ]] \
		|| fail "Group 10–12 ${mode}: unexpected or mutating incus command"
	neighbor_count="$(grep -c 'neigh show' "$trace" || true)"
	if [[ "$mode" == route-void || "$mode" == route-local-fail ]]; then
		[[ "$neighbor_count" == 1 ]] \
			|| fail "Group 10–12 ${mode}: expected one route-scoped neighbor read, got ${neighbor_count}"
	else
		[[ "$neighbor_count" == 2 ]] \
			|| fail "Group 10–12 ${mode}: expected two route-scoped neighbor reads, got ${neighbor_count}"
	fi
	trace_contents="$(<"$trace")"
	[[ "$trace_contents" != *"ip neigh replace"* && "$trace_contents" != *"ip neigh add"* \
		&& "$trace_contents" != *"ip neigh del"* && "$trace_contents" != *"ip neigh flush"* ]] \
		|| fail "Group 10–12 ${mode}: neighbor mutation command observed"
	case "$mode" in
	happy)
		[[ "$output" == *"PASS  cluster: Group11 IPv6 MTR"*"warning destination unresolved"* ]] \
			|| fail "Group 11 IPv6 no-hop warning was not emitted as a PASS cell"
		;;
	ttl-fail) [[ "$output" == *"FAIL  cluster: Group10 IPv4 TTL=1"* ]] || fail "TTL echo-only output was not a measured FAIL" ;;
	ttl-void) [[ "$output" == *"VOID  cluster: Group10 IPv4 TTL=1"* ]] || fail "missing TTL output was not VOID" ;;
	mtr4-fail) [[ "$output" == *"FAIL  cluster: Group11 IPv4 MTR"* ]] || fail "unresolved IPv4 MTR destination was not a measured FAIL" ;;
	ping-fail) [[ "$output" == *"FAIL  cluster: Group12 IPv4 controlled reachability"* ]] || fail "zero controlled-ping replies were not a measured FAIL" ;;
	neighbor-fail) [[ "$output" == *"FAIL  cluster: Group12 read-only neighbor identity"* ]] || fail "neighbor MAC mismatch was not a measured FAIL" ;;
	route-void)
		[[ "$output" == *"VOID  cluster: Group12 IPv4 route"* \
			&& "$output" == *"VOID  cluster: Group12 read-only neighbor identity"* ]] \
			|| fail "unreadable route evidence did not VOID route and neighbor checks"
		;;
	route-local-fail) [[ "$output" == *"FAIL  cluster: Group12 IPv4 route"* ]] || fail "local route was not a measured FAIL" ;;
	esac
	ok "test_cluster Groups 10–12 behavior: ${mode}"
}
run_connectivity_case happy "PASS=9 FAIL=0 VOID=0"
run_connectivity_case ttl-fail "PASS=8 FAIL=1 VOID=0"
run_connectivity_case ttl-void "PASS=8 FAIL=0 VOID=1"
run_connectivity_case mtr4-fail "PASS=8 FAIL=1 VOID=0"
run_connectivity_case ping-fail "PASS=8 FAIL=1 VOID=0"
run_connectivity_case neighbor-fail "PASS=8 FAIL=1 VOID=0"
run_connectivity_case route-void "PASS=7 FAIL=0 VOID=2"
run_connectivity_case route-local-fail "PASS=7 FAIL=1 VOID=1"
ok "Groups 10–12 issue read-only route-scoped neighbor queries only"

# Fixture: a stand-in destructive script. Enters the cell, then (with
# the lock held transitively) records that it started and optionally
# lingers so a concurrent run can observe the held lock.
FIX="$T/fixture.sh"
cat >"$FIX" <<STUB
#!/usr/bin/env bash
set -euo pipefail
_CELL_DIR="${SCRIPT_DIR}"
# shellcheck source=/dev/null
source "\${_CELL_DIR}/cluster-cell.sh"
xpf_enter_destructive_cluster_cell "fixture \$*" "\$0" "\$@"
echo started >"\${FIX_START}"
sleep "\${FIX_SLEEP:-0}"
STUB
chmod +x "$FIX"

# (a) standalone run acquires the lock and runs its body.
FIX_START="$T/a.start" FIX_SLEEP=0 "$FIX" || fail "(a) standalone fixture failed"
[[ -f "$T/a.start" ]] || fail "(a) fixture body did not run under the lock"
[[ ! -f "$XPF_CLUSTER_OWNER" ]] || fail "(a) owner file leaked after standalone run"
ok "standalone destructive run acquires the lock and runs its body"

# (b) a second run QUEUES behind a held lock instead of colliding.
FIX_START="$T/b.start" FIX_SLEEP=6 "$FIX" &
B_HOLDER=$!
waitfor 5 "holder fixture started" test -f "$T/b.start"
set +e
FIX_START="$T/b2.start" FIX_SLEEP=0 XPF_CLUSTER_LOCK_TIMEOUT=1 "$FIX" >"$T/b2.out" 2>&1
B2_RC=$?
set -e
[[ $B2_RC -eq 75 ]] \
	|| fail "(b) concurrent run expected to queue+timeout (75), got $B2_RC — did it collide?"
[[ ! -f "$T/b2.start" ]] || fail "(b) queued run ran its body despite a held lock (collision!)"
grep -q "fixture" "$T/b2.out" || fail "(b) waiter did not report the holding fixture cell"
wait "$B_HOLDER" || true
ok "concurrent destructive run queues behind a held lock (no collision)"

# (c) reentrant: inside a with-cluster.sh cell the fixture runs
#     lock-free (marker held) — no second acquire, no deadlock.
set +e
FIX_START="$T/c.start" FIX_SLEEP=0 timeout 20 "$WC" "outer cell" -- "$FIX" >"$T/c.out" 2>&1
C_RC=$?
set -e
[[ $C_RC -eq 0 ]] || fail "(c) reentrant fixture inside a cell failed/deadlocked (rc=$C_RC)"
[[ -f "$T/c.start" ]] || fail "(c) reentrant fixture body did not run"
ok "destructive run inside a with-cluster.sh cell runs lock-free (reentrant, no deadlock)"
# ── BEHAVIORAL F-158/#10126: the idleness probe itself, not just its
# wiring ──────────────────────────────────────────────────────────────
# The static greps above pin that test_cluster CALLS
# xpf_assert_cluster_lock_idle, but a `return 0` no-op passes every grep
# (RED-demonstrated via a SCRIPT_DIR overlay: stubbed probe still ALL
# PASS). These cells source the REAL cluster-lock.sh and eval-extract the
# REAL probe from test-connectivity.sh, then exercise the original edge
# branches, RED/GREEN whole-window proof, endpoint overlap, no-lock
# cleanliness, and epoch publication failure modes hermetically against
# the PRIVATE $XPF_CLUSTER_LOCK and $XPF_CLUSTER_EPOCH.
# shellcheck source=test/incus/cluster-lock.sh
source "${SCRIPT_DIR}/cluster-lock.sh"
_F158_SRC="$(sed -n '/^xpf_assert_cluster_lock_idle() {/,/^}/p' "${SCRIPT_DIR}/test-connectivity.sh")"
[[ -n "$_F158_SRC" ]] || fail "F-158: could not extract xpf_assert_cluster_lock_idle from test-connectivity.sh (sed range empty — helper renamed?)"
eval "$_F158_SRC"

# A literal pre-#10126 copy is kept only as a RED witness: it polls
# flock at each endpoint and has no epoch snapshot. The whole-window
# cell below must pass through this helper before the repaired probe is
# shown to void the same overlap.
eval '
xpf_assert_cluster_lock_idle_pre10126() {
	local phase="$1"
	[[ "$FW0" == *:* ]] || return 0
	if xpf_cluster_lock_held; then
		return 0
	fi
	if ! ( flock -n 9 || exit 1 ) 9>"$XPF_CLUSTER_LOCK"; then
		echo "VOID: shared-cluster lock ${XPF_CLUSTER_LOCK} is held by another lane at connectivity ${phase} probe" >&2
		exit 77
	fi
}
'
declare -F xpf_assert_cluster_lock_idle_pre10126 >/dev/null \
	|| fail "F-158 RED witness helper did not define"
declare -F xpf_assert_cluster_lock_idle >/dev/null || fail "F-158: eval-extracted probe did not define xpf_assert_cluster_lock_idle"

# waitfor expects its command to SUCCEED, so the lock-state predicates
# are phrased as successes (held-now inverts the non-blocking flock).
_xpf_lock_held_now() { ! flock -n "$XPF_CLUSTER_LOCK" true 2>/dev/null; }
_xpf_lock_idle_now() { flock -n "$XPF_CLUSTER_LOCK" true 2>/dev/null; }
# flock(1) FILE COMMAND forks the command as a child that inherits the
# lock fd — killing the parent alone leaves the child holding (observed:
# after `kill $flock_pid` the lock still reports held). Capture the child
# BEFORE killing the parent (afterwards it reparents and `pgrep -P` finds
# nothing), reap both, then wait for idle before the next cell runs.
_xpf_kill_flock_holder() { # <flock-pid>
	local _h="$1" _c _children
	_children="$(pgrep -P "$_h" 2>/dev/null || true)"
	kill "$_h" 2>/dev/null || true
	for _c in $_children; do
		kill "$_c" 2>/dev/null || true
	done
	wait "$_h" 2>/dev/null || true
	waitfor 5 "flock holder released the lock" _xpf_lock_idle_now
}

touch "$XPF_CLUSTER_LOCK"
unset XPF_CLUSTER_LOCK_HELD || true
unset FW0 || true

# F-158 (a): held lock + remote FW0 + no marker → VOID 77.
flock "$XPF_CLUSTER_LOCK" sleep 30 </dev/null >/dev/null 2>&1 &
_F158_HOLDER=$!
waitfor 5 "F-158 (a) background holder holds the lock" _xpf_lock_held_now
set +e
( export FW0="loss:fw0"; xpf_assert_cluster_lock_idle "start" ) >"$T/f158-a.out" 2>&1
_F158_RC=$?
set -e
_xpf_kill_flock_holder "$_F158_HOLDER"
unset XPF_CLUSTER_LOCK_HELD || true
[[ $_F158_RC -eq 77 ]] || fail "F-158 (a) held lock + remote FW0 expected VOID 77, got $_F158_RC (a no-op probe returns 0)"
grep -q "VOID" "$T/f158-a.out" || fail "F-158 (a) VOID message missing from probe output"
ok "F-158 (a) held lock + remote FW0 voids with 77"

# F-158 (b): idle lock + remote FW0 → rc 0.
unset XPF_CLUSTER_LOCK_HELD || true
_xpf_lock_idle_now || fail "F-158 (b) lock not idle before probe (holder leaked?)"
set +e
( export FW0="loss:fw0"; xpf_assert_cluster_lock_idle "start" ) >"$T/f158-b.out" 2>&1
_F158_RC=$?
set -e
unset XPF_CLUSTER_LOCK_HELD || true
[[ $_F158_RC -eq 0 ]] || fail "F-158 (b) idle lock + remote FW0 expected 0, got $_F158_RC"
ok "F-158 (b) idle lock + remote FW0 passes with 0"

# F-158 (e) RED: the pre-#10126 polling probes miss a complete
# with-cluster acquire+release between START and END. This is the
# hermetic pre-fix witness required by #10126.
export FW0="loss:fw0"
unset XPF_CLUSTER_LOCK_HELD || true
xpf_assert_cluster_lock_idle_pre10126 "start"
FIX_START="$T/f158-whole-red.start" FIX_SLEEP=1 "$FIX" >"$T/f158-whole-red.out" 2>&1 &
_F158_RED_PID=$!
waitfor 5 "F-158 (e) RED whole-window holder started" test -f "$T/f158-whole-red.start"
wait "$_F158_RED_PID" || fail "F-158 (e) RED fixture cell failed"
set +e
xpf_assert_cluster_lock_idle_pre10126 "end" >"$T/f158-whole-red-probe.out" 2>&1
_F158_RED_RC=$?
set -e
[[ $_F158_RED_RC -eq 0 ]] \
	|| fail "F-158 (e) RED pre-fix whole-window probe unexpectedly voided (rc=$_F158_RED_RC)"
ok "F-158 (e) RED pre-fix polling probes miss whole-window acquire+release"

# F-158 (e2): a legacy endpoint probe that truncates the lock inode
# must not erase the persistent acquisition witness.
_F158_LEGACY_EPOCH_BEFORE=$(cat "$XPF_CLUSTER_EPOCH" 2>/dev/null || true)
xpf_assert_cluster_lock_idle_pre10126 "start"
_F158_LEGACY_EPOCH_AFTER=$(cat "$XPF_CLUSTER_EPOCH" 2>/dev/null || true)
[[ "$_F158_LEGACY_EPOCH_AFTER" == "$_F158_LEGACY_EPOCH_BEFORE" ]] \
	|| fail "F-158 (e2) legacy 9> probe changed the epoch sidecar"
ok "F-158 (e2) legacy lock probe cannot erase persistent epoch"

# F-158 (f) GREEN: the repaired owner-epoch endpoint comparison voids
# the identical whole-window overlap, even though the lock is idle again
# at END. Keep START, holder, release, and END in one shell so the
# snapshot variables are the real probe's state.
set +e
(
	export FW0="loss:fw0"
	unset XPF_CLUSTER_LOCK_HELD || true
	xpf_assert_cluster_lock_idle "start"
	FIX_START="$T/f158-whole-green.start" FIX_SLEEP=1 "$FIX" >"$T/f158-whole-green.out" 2>&1 &
	_F158_GREEN_PID=$!
	waitfor 5 "F-158 (f) GREEN whole-window holder started" test -f "$T/f158-whole-green.start"
	wait "$_F158_GREEN_PID"
	xpf_assert_cluster_lock_idle "end"
) >"$T/f158-whole-green-probe.out" 2>&1
_F158_GREEN_RC=$?
set -e
[[ $_F158_GREEN_RC -eq 77 ]] \
	|| fail "F-158 (f) GREEN whole-window epoch probe expected VOID 77, got $_F158_GREEN_RC"
grep -q "owner epoch/identity changed" "$T/f158-whole-green-probe.out" \
	|| fail "F-158 (f) GREEN epoch-change VOID diagnostic missing"
ok "F-158 (f) GREEN owner epoch catches whole-window acquire+release"

# F-158 (g): endpoint overlap remains fail-fast. The holder starts
# only after START has completed, then END runs while it owns the lock.
(
	export FW0="loss:fw0"
	unset XPF_CLUSTER_LOCK_HELD || true
	xpf_assert_cluster_lock_idle "start"
	: >"$T/f158-edge.ready"
	waitfor 5 "F-158 (g) probe handoff" test -f "$T/f158-edge.go"
	xpf_assert_cluster_lock_idle "end"
) >"$T/f158-edge.out" 2>&1 &
_F158_EDGE_PROBE=$!
waitfor 5 "F-158 (g) START probe completed" test -f "$T/f158-edge.ready"
flock "$XPF_CLUSTER_LOCK" sleep 30 </dev/null >/dev/null 2>&1 &
_F158_EDGE_HOLDER=$!
waitfor 5 "F-158 (g) edge holder owns lock" _xpf_lock_held_now
touch "$T/f158-edge.go"
set +e
wait "$_F158_EDGE_PROBE"
_F158_EDGE_RC=$?
set -e
_xpf_kill_flock_holder "$_F158_EDGE_HOLDER"
[[ $_F158_EDGE_RC -eq 77 ]] \
	|| fail "F-158 (g) END edge overlap expected VOID 77, got $_F158_EDGE_RC"
grep -q "held by another lane" "$T/f158-edge.out" \
	|| fail "F-158 (g) END edge VOID diagnostic missing"
ok "F-158 (g) END edge overlap still voids with 77"

# F-158 (h): no lock activity across the window remains clean.
set +e
(
	export FW0="loss:fw0"
	unset XPF_CLUSTER_LOCK_HELD || true
	xpf_assert_cluster_lock_idle "start"
	xpf_assert_cluster_lock_idle "end"
) >"$T/f158-no-lock.out" 2>&1
_F158_NOLOCK_RC=$?
set -e
[[ $_F158_NOLOCK_RC -eq 0 ]] \
	|| fail "F-158 (h) no-lock window expected clean rc 0, got $_F158_NOLOCK_RC"
ok "F-158 (h) no-lock window stays clean (no false positive)"

# F-158 (h2): a read-side failure must not collapse to empty==empty.
# Selective cat failure makes END reject the otherwise unchanged epoch.
mkdir "$T/selective-cat-bin"
cat >"$T/selective-cat-bin/cat" <<'EOF'
#!/bin/sh
if [ "${1:-}" = "$XPF_CLUSTER_EPOCH" ]; then
	exit 1
fi
exec /bin/cat "$@"
EOF
chmod 755 "$T/selective-cat-bin/cat"
set +e
( export PATH="$T/selective-cat-bin:$PATH"; xpf_assert_cluster_lock_idle "start" ) \
	>"$T/f158-unreadable-epoch-start.out" 2>&1
_F158_UNREADABLE_EPOCH_START_RC=$?
set -e
[[ $_F158_UNREADABLE_EPOCH_START_RC -eq 77 ]] \
	|| fail "F-158 (h2) unreadable epoch START expected VOID 77, got $_F158_UNREADABLE_EPOCH_START_RC"
grep -q "epoch .*unreadable at connectivity START" "$T/f158-unreadable-epoch-start.out" \
	|| fail "F-158 (h2) unreadable epoch START diagnostic missing"
xpf_assert_cluster_lock_idle "start"
set +e
( export PATH="$T/selective-cat-bin:$PATH"; xpf_assert_cluster_lock_idle "end" ) \
	>"$T/f158-unreadable-epoch.out" 2>&1
_F158_UNREADABLE_EPOCH_RC=$?
set -e
[[ $_F158_UNREADABLE_EPOCH_RC -eq 77 ]] \
	|| fail "F-158 (h2) unreadable epoch expected VOID 77, got $_F158_UNREADABLE_EPOCH_RC"
grep -q "epoch .*unreadable at connectivity END" "$T/f158-unreadable-epoch.out" \
	|| fail "F-158 (h2) unreadable epoch diagnostic missing"
ok "F-158 (h2) unreadable epoch fails closed instead of empty==empty"

# F-158 (i): the witness uses a pre-existing mode-0666 inode and
# atomic replacement in a non-sticky state directory. This is the
# permission shape required for cross-user operation; this unprivileged
# selftest cannot chown a file to a second UID, so it does not misreport
# same-owner coverage as a different-owner proof.
chmod 0666 "$XPF_CLUSTER_EPOCH"
_F158_EPOCH_BEFORE=$(cat "$XPF_CLUSTER_EPOCH" 2>/dev/null || true)
FIX_START="$T/f158-perm.start" FIX_SLEEP=0 "$FIX" >"$T/f158-perm.out" 2>&1 \
	|| fail "F-158 (i) writable epoch permission-shaped fixture failed"
_F158_EPOCH_AFTER=$(cat "$XPF_CLUSTER_EPOCH" 2>/dev/null || true)
[[ "$(stat -c %a "$XPF_CLUSTER_EPOCH")" == 666 ]] \
	|| fail "F-158 (i) epoch witness is not mode 0666 for cross-user replacement"
[[ "$_F158_EPOCH_AFTER" != "$_F158_EPOCH_BEFORE" ]] \
	|| fail "F-158 (i) writable epoch did not publish a new acquisition token"
ok "F-158 (i) existing mode-0666 epoch atomically replaces acquisition token"

# F-158 (i2): a second cooperating publisher must not chmod an already
# mode-0777 shared state directory it does not own. A selective chmod
# shim fails only for that directory; the bump must skip chmod and run.
mkdir "$T/epoch-shared"
chmod 0777 "$T/epoch-shared"
mkdir "$T/dir-chmod-bin"
cat >"$T/dir-chmod-bin/chmod" <<'EOF'
#!/bin/sh
if [ "${2:-}" = "$XPF_CLUSTER_EPOCH_STATE_DIR" ]; then
	exit 1
fi
exec /bin/chmod "$@"
EOF
chmod 755 "$T/dir-chmod-bin/chmod"
set +e
PATH="$T/dir-chmod-bin:$PATH" \
	XPF_CLUSTER_EPOCH_STATE_DIR="$T/epoch-shared" \
	XPF_CLUSTER_EPOCH="$T/epoch-shared/epoch" \
	FIX_START="$T/f158-shared.start" FIX_SLEEP=0 \
	"$FIX" >"$T/f158-shared.out" 2>&1
_F158_SHARED_RC=$?
set -e
[[ $_F158_SHARED_RC -eq 0 ]] \
	|| fail "F-158 (i2) pre-0777 shared state expected success, got $_F158_SHARED_RC"
[[ "$(stat -c %a "$T/epoch-shared")" == 777 ]] \
	|| fail "F-158 (i2) shared state mode changed"
[[ "$(stat -c %a "$T/epoch-shared/epoch")" == 666 ]] \
	|| fail "F-158 (i2) shared epoch was not published mode 0666"
[[ -e "$T/f158-shared.start" ]] \
	|| fail "F-158 (i2) shared-state fixture body did not run"
ok "F-158 (i2) pre-0777 shared state skips foreign chmod and publishes"

# F-158 (j): an invalid sidecar parent is fail-closed — with-cluster
# refuses to run the destructive body rather than reopening the
# whole-window hole. A regular file in the parent position makes
# mkdir/mktemp fail with ENOTDIR independent of UID privileges.
printf 'not-a-directory\n' >"$T/epoch-deny"
set +e
XPF_CLUSTER_EPOCH="$T/epoch-deny/epoch" FIX_START="$T/f158-deny.start" \
	FIX_SLEEP=0 "$FIX" >"$T/f158-deny.out" 2>&1
_F158_DENY_RC=$?
set -e
rm -f "$T/epoch-deny"
[[ $_F158_DENY_RC -eq 73 ]] \
	|| fail "F-158 (j) invalid epoch parent expected lock-cell refusal 73, got $_F158_DENY_RC"
[[ ! -e "$T/f158-deny.start" ]] \
	|| fail "F-158 (j) invalid epoch parent let destructive fixture body run"
grep -q "cannot create state directory" "$T/f158-deny.out" \
	|| fail "F-158 (j) refusal diagnostic missing"
ok "F-158 (j) invalid epoch parent refuses cell before body"

# F-158 (j2): if chmod cannot make the temporary sidecar cross-user
# readable, publication fails closed before the destructive body. The
# fake chmod is deterministic and does not depend on host privileges.
mkdir "$T/no-chmod-bin"
printf '#!/bin/sh\nexit 1\n' >"$T/no-chmod-bin/chmod"
"$(command -v chmod)" 755 "$T/no-chmod-bin/chmod"
set +e
PATH="$T/no-chmod-bin:$PATH" XPF_CLUSTER_EPOCH="$T/epoch-chmod-deny" \
	FIX_START="$T/f158-chmod-deny.start" FIX_SLEEP=0 \
	"$FIX" >"$T/f158-chmod-deny.out" 2>&1
_F158_CHMOD_DENY_RC=$?
set -e
[[ $_F158_CHMOD_DENY_RC -eq 73 ]] \
	|| fail "F-158 (j2) chmod failure expected lock-cell refusal 73, got $_F158_CHMOD_DENY_RC"
[[ ! -e "$T/f158-chmod-deny.start" ]] \
	|| fail "F-158 (j2) chmod failure let destructive fixture body run"
grep -q "cannot make temporary epoch cross-user readable" "$T/f158-chmod-deny.out" \
	|| fail "F-158 (j2) chmod failure diagnostic missing"
ok "F-158 (j2) chmod failure refuses cell before body"
# F-158 (j3): an epoch path that is itself a directory is fail-closed;
# mv must never place the temporary token inside that directory.
mkdir "$T/epoch-path-dir"
set +e
XPF_CLUSTER_EPOCH="$T/epoch-path-dir" FIX_START="$T/f158-dir.start" \
	FIX_SLEEP=0 "$FIX" >"$T/f158-dir.out" 2>&1
_F158_DIR_RC=$?
set -e
[[ $_F158_DIR_RC -eq 73 ]] \
	|| fail "F-158 (j3) directory epoch path expected refusal 73, got $_F158_DIR_RC"
[[ ! -e "$T/f158-dir.start" ]] \
	|| fail "F-158 (j3) directory epoch path let destructive fixture body run"
grep -q "epoch sidecar path .* is a directory" "$T/f158-dir.out" \
	|| fail "F-158 (j3) directory epoch refusal diagnostic missing"
ok "F-158 (j3) directory epoch path refuses cell before body"
# F-158 (c): held lock + bare FW0 → rc 0 (dedicated local instance no
# other lane touches — the probe must not fire).
unset XPF_CLUSTER_LOCK_HELD || true

flock "$XPF_CLUSTER_LOCK" sleep 30 </dev/null >/dev/null 2>&1 &
_F158_HOLDER=$!
waitfor 5 "F-158 (c) background holder holds the lock" _xpf_lock_held_now
set +e
( export FW0="xpf-fw0"; xpf_assert_cluster_lock_idle "start" ) >"$T/f158-c.out" 2>&1
_F158_RC=$?
set -e
_xpf_kill_flock_holder "$_F158_HOLDER"
unset XPF_CLUSTER_LOCK_HELD || true
[[ $_F158_RC -eq 0 ]] || fail "F-158 (c) held lock + bare FW0 expected 0 (probe must not fire), got $_F158_RC"
ok "F-158 (c) held lock + bare FW0 skips the probe with 0"

# F-158 (d): held lock + VALID marker → rc 0 (own cell — probing our own
# ancestor's lock must not self-report contention).
unset XPF_CLUSTER_LOCK_HELD || true
exec 9>"$XPF_CLUSTER_LOCK" || fail "F-158 (d) could not open private lock on fd 9"
flock -n 9 || { exec 9>&-; fail "F-158 (d) could not acquire private lock for marker test"; }
export XPF_CLUSTER_LOCK_HELD="${XPF_CLUSTER_LOCK}:$$"
# Sanity: the marker must validate before the probe runs. $$ in the
# probing subshell below is still this shell's pid, so the ancestry walk
# matches on its first step — valid per xpf_cluster_lock_held's
# self-inclusive check, mirroring a with-cluster.sh cell where the holder
# is a live ancestor of the probing process.
xpf_cluster_lock_held || { exec 9>&-; unset XPF_CLUSTER_LOCK_HELD || true; fail "F-158 (d) marker ${XPF_CLUSTER_LOCK_HELD:-?} did not validate as held"; }
set +e
( export FW0="loss:fw0"; xpf_assert_cluster_lock_idle "start" ) >"$T/f158-d.out" 2>&1
_F158_RC=$?
set -e
exec 9>&-
unset XPF_CLUSTER_LOCK_HELD || true
unset FW0 || true
[[ $_F158_RC -eq 0 ]] || fail "F-158 (d) held lock + valid marker expected 0 (own cell), got $_F158_RC"
ok "F-158 (d) held lock + valid marker skips the probe with 0"

# #11581 M3.3.5: static placement pin. Every test_cluster result cell must be
# between START and END; direct and shared PASS/FAIL/VOID emitters all count.
xpf_connectivity_cells_bracketed() {
	local script="$1" cluster start_count end_count start_line end_line before after cell_call_pattern
	cluster="$(sed -n '/^test_cluster() {/,/^}/p' "$script")" || return 1
	[[ -n "$cluster" ]] || return 1
	start_count="$(grep -Ec '^[[:space:]]*xpf_assert_cluster_lock_idle "start"$' <<<"$cluster" || true)"
	end_count="$(grep -Ec '^[[:space:]]*xpf_assert_cluster_lock_idle "end"$' <<<"$cluster" || true)"
	[[ "$start_count" == 1 && "$end_count" == 1 ]] || return 1
	start_line="$(grep -nE '^[[:space:]]*xpf_assert_cluster_lock_idle "start"$' <<<"$cluster" | cut -d: -f1)"
	end_line="$(grep -nE '^[[:space:]]*xpf_assert_cluster_lock_idle "end"$' <<<"$cluster" | cut -d: -f1)"
	(( start_line < end_line )) || return 1
	before="$(sed -n "1,$((start_line - 1))p" <<<"$cluster")"
	after="$(sed -n "$((end_line + 1)),\$p" <<<"$cluster")"
	cell_call_pattern='^[[:space:]]*(pass|fail|void|assurance_verdict)[[:space:]]+'
	if grep -Eq "$cell_call_pattern" <<<"$before"; then
		return 1
	fi
	if grep -Eq "$cell_call_pattern" <<<"$after"; then
		return 1
	fi
}

xpf_connectivity_cells_bracketed "${SCRIPT_DIR}/test-connectivity.sh" \
	|| fail "static: test_cluster cells must all lie between F-158 START and END (no cell after END)"
ok "static: all test_cluster cells are inside the F-158 START/END window"

# RED controls: inject both the shared verdict wrapper and direct VOID
# emitter immediately after END; each must be rejected. Source stays intact.
xpf_connectivity_post_end_red() {
	local description="$1" synthetic_call="$2" fixture="$T/test-connectivity-post-end.sh"
	awk -v call="$synthetic_call" '
		{ print }
		/^[[:space:]]*xpf_assert_cluster_lock_idle "end"$/ { print "\t" call }
	' "${SCRIPT_DIR}/test-connectivity.sh" >"$fixture"
	if xpf_connectivity_cells_bracketed "$fixture"; then
		fail "static RED: no-new-cell-after-END pin accepted synthetic ${description}"
	fi
	ok "static RED: no-new-cell-after-END pin rejects synthetic ${description}"
}
xpf_connectivity_post_end_red "assurance verdict cell" 'assurance_verdict "synthetic post-END cell" 1 "failure"'
xpf_connectivity_post_end_red "direct VOID cell" 'void "synthetic post-END VOID"'


# Invoke the actual smoke-cells adapter on captured precedence transcripts.
# The adapter's missing-summary branch must remain VOID even when an earlier
# standalone or cluster FAIL line is preserved for forensic detail.
xpf_check_precedence_adapter() {
	local name="$1" expected_rc="$2" rc="$3" summary="$4" verdict="$5" cause="$6" log="$7"
	local adapted actual_verdict
	[[ "$rc" == "$expected_rc" ]] || fail "$name: expected exit $expected_rc, got $rc"
	if [[ "$summary" == yes ]]; then
		grep -Eq '[0-9]+ passed, [0-9]+ failed' "$log" \
			|| fail "$name: expected a printed summary"
	else
		if grep -Eq '[0-9]+ passed, [0-9]+ failed' "$log"; then
			fail "$name: summary printed despite expected no-summary abort"
		fi
	fi
	grep -q '^[[:space:]]*FAIL[[:space:]]' "$log" \
		|| fail "$name: preceding measured FAIL detail was not preserved"
	grep -Fq "$cause" "$log" || fail "$name: VOID cause line missing ('$cause')"
	adapted="$(bash "${SCRIPT_DIR}/harness-result.sh" adapt smoke-cells "$rc" "$log")" \
		|| fail "$name: real smoke-cells adapter invocation failed"
	actual_verdict="${adapted%%$'\t'*}"
	[[ "$actual_verdict" == "$verdict" ]] \
		|| fail "$name: adapter verdict expected $verdict, got $actual_verdict ($adapted)"
}

# (a) Ordinary later VOID does not erase a measured FAIL. The real adapter
# must read the printed failure summary as FAIL despite the retained VOID line.
_F158_M3_A_LOG="$T/f158-m3-a.out"
printf '%s\n' \
	'  FAIL  connectivity: measured cell violation' \
	'VOID: ordinary capture for a later cell is unavailable' \
	'  Results: 0 passed, 1 failed, 0 skipped' >"$_F158_M3_A_LOG"
xpf_check_precedence_adapter "M3 (a) ordinary FAIL then ordinary VOID" \
	1 1 yes FAIL "VOID: ordinary capture" "$_F158_M3_A_LOG"
ok "M3 (a) ordinary FAIL then later ordinary VOID stays FAIL through smoke-cells adapter"

# (b) MODE=cluster: a real cluster-cell FAIL is printed after START, then
# the hermetic fixture acquires/releases the private lock and changes epoch.
# The real END probe must abort 77 before a summary, and the adapter must VOID.
_F158_M3_B_LOG="$T/f158-m3-b.out"
set +e
(
	export FW0="loss:fw0"
	unset XPF_CLUSTER_LOCK_HELD || true
	xpf_assert_cluster_lock_idle "start"
	printf '%s\n' '  FAIL  cluster: measured sample violation'
	FIX_START="$T/f158-m3-b-holder.start" FIX_SLEEP=0 "$FIX" \
		>"$T/f158-m3-b-holder.out" 2>&1
	xpf_assert_cluster_lock_idle "end"
	printf '%s\n' '  Results: 0 passed, 1 failed, 0 skipped'
	exit 1
) >"$_F158_M3_B_LOG" 2>&1
_F158_M3_B_RC=$?
set -e
[[ $_F158_M3_B_RC -eq 77 ]] \
	|| fail "M3 (b) expected END invalidation rc 77, got $_F158_M3_B_RC"
xpf_check_precedence_adapter "M3 (b) cluster END invalidation" \
	77 "$_F158_M3_B_RC" no VOID "owner epoch/identity changed during connectivity sampling window" "$_F158_M3_B_LOG"
ok "M3 (b) cluster FAIL then END epoch invalidation is exit-77/no-summary/VOID"

# (c) MODE=all: preserve a standalone FAIL, then refuse START because another
# lane holds the private lock. This is invocation VOID, not contamination of
# the standalone sample.
_F158_M3_C_LOG="$T/f158-m3-c.out"
unset XPF_CLUSTER_LOCK_HELD || true
flock "$XPF_CLUSTER_LOCK" sleep 30 </dev/null >/dev/null 2>&1 &
_F158_M3_C_HOLDER=$!
waitfor 5 "M3 (c) START contention holder owns the private lock" _xpf_lock_held_now
set +e
(
	export FW0="loss:fw0"
	unset XPF_CLUSTER_LOCK_HELD || true
	printf '%s\n' '  FAIL  standalone: measured cell violation'
	xpf_assert_cluster_lock_idle "start"
	printf '%s\n' '  Results: 0 passed, 1 failed, 0 skipped'
	exit 1
) >"$_F158_M3_C_LOG" 2>&1
_F158_M3_C_RC=$?
set -e
_xpf_kill_flock_holder "$_F158_M3_C_HOLDER"
[[ $_F158_M3_C_RC -eq 77 ]] \
	|| fail "M3 (c) expected START refusal rc 77, got $_F158_M3_C_RC"
xpf_check_precedence_adapter "M3 (c) MODE=all START refusal" \
	77 "$_F158_M3_C_RC" no VOID "held by another lane at connectivity start probe" "$_F158_M3_C_LOG"
ok "M3 (c) MODE=all standalone FAIL then START refusal is exit-77/no-summary/VOID"

# (d) MODE=all: preserve a standalone FAIL, pass START, then change the
# private epoch during the cluster window. END invalidation suppresses the
# common summary and the real adapter records invocation VOID.
_F158_M3_D_LOG="$T/f158-m3-d.out"
set +e
(
	export FW0="loss:fw0"
	unset XPF_CLUSTER_LOCK_HELD || true
	printf '%s\n' '  FAIL  standalone: measured cell violation'
	xpf_assert_cluster_lock_idle "start"
	FIX_START="$T/f158-m3-d-holder.start" FIX_SLEEP=0 "$FIX" \
		>"$T/f158-m3-d-holder.out" 2>&1
	xpf_assert_cluster_lock_idle "end"
	printf '%s\n' '  Results: 0 passed, 1 failed, 0 skipped'
	exit 1
) >"$_F158_M3_D_LOG" 2>&1
_F158_M3_D_RC=$?
set -e
[[ $_F158_M3_D_RC -eq 77 ]] \
	|| fail "M3 (d) expected END invalidation rc 77, got $_F158_M3_D_RC"
xpf_check_precedence_adapter "M3 (d) MODE=all END invalidation" \
	77 "$_F158_M3_D_RC" no VOID "owner epoch/identity changed during connectivity sampling window" "$_F158_M3_D_LOG"
ok "M3 (d) MODE=all standalone FAIL then END invalidation is exit-77/no-summary/VOID"

# RED-before control for (b): same START/FAIL/END flow without epoch change.
# END must pass through, the common summary must print, and the adapter must
# retain the measured FAIL instead of reporting VOID.
_F158_M3_B_CONTROL_LOG="$T/f158-m3-b-control.out"
set +e
(
	export FW0="loss:fw0"
	unset XPF_CLUSTER_LOCK_HELD || true
	xpf_assert_cluster_lock_idle "start"
	printf '%s\n' '  FAIL  cluster: measured sample violation'
	xpf_assert_cluster_lock_idle "end"
	printf '%s\n' '  Results: 0 passed, 1 failed, 0 skipped'
	exit 1
) >"$_F158_M3_B_CONTROL_LOG" 2>&1
_F158_M3_B_CONTROL_RC=$?
set -e
[[ $_F158_M3_B_CONTROL_RC -eq 1 ]] \
	|| fail "M3 (b) no-contention control expected measured-failure rc 1, got $_F158_M3_B_CONTROL_RC"
grep -Eq '[0-9]+ passed, [0-9]+ failed' "$_F158_M3_B_CONTROL_LOG" \
	|| fail "M3 (b) no-contention control lost its summary"
if grep -q '^VOID:' "$_F158_M3_B_CONTROL_LOG"; then
	fail "M3 (b) no-contention control unexpectedly printed a VOID cause"
fi
grep -q '^[[:space:]]*FAIL[[:space:]]' "$_F158_M3_B_CONTROL_LOG" \
	|| fail "M3 (b) no-contention control lost its measured FAIL detail"
_F158_M3_B_CONTROL_ADAPTED="$(bash "${SCRIPT_DIR}/harness-result.sh" adapt smoke-cells \
	"$_F158_M3_B_CONTROL_RC" "$_F158_M3_B_CONTROL_LOG")" \
	|| fail "M3 (b) no-contention control real adapter invocation failed"
[[ "${_F158_M3_B_CONTROL_ADAPTED%%$'\t'*}" == FAIL ]] \
	|| fail "M3 (b) no-contention control should remain FAIL, got $_F158_M3_B_CONTROL_ADAPTED"
ok "RED-before (b) control: unchanged epoch permits END, summary, and adapter FAIL"

echo "ALL ${PASS} CASES PASS"
