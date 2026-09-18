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

echo "ALL ${PASS} CASES PASS"
