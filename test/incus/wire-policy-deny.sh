#!/usr/bin/env bash
# wire_policy_deny gate — #9531 (ZPV-01).
#
# Proves the TRANSIT composition the unit tests structurally cannot: a live
# daemon configured through the CLI enforces a no-permit-rule drop on the
# wire. The fixture NARROWS the baseline lan→wan allow-all so the probe
# 5-tuple falls to default-deny with NO permit rule (the normative §3 shape —
# not an explicit DENY), while a near-miss control flow on the SAME pair
# (differing ONLY in dst port) stays explicitly permitted. Peer-side capture
# must show zero probe frames and a full control burst, or the gate is red.
#
# Usage:
#   ./test/incus/wire-policy-deny.sh                  # live gate (lock cell)
#   ./test/incus/wire-policy-deny.sh --fixture <tsv>  # hermetic verdict proof
#   ./test/incus/wire-policy-deny.sh --selftest       # hermetic cell matrix
#
# Exit: 0 PASS, 1 FAIL, 2 VOID, 3 refused precondition.
#
# Live topology (loss userspace cluster): prober = CLUSTER_LAN_HOST, sink +
# capture point = the VLAN-80 mouse target (incus-managed, tcpdump on the
# receiving interface is true peer-side wire truth). The external iperf
# target has no management path and is never used here.

set -uo pipefail

# ── mode dispatch precedes the lock cell (§4 lock-ordering) ──────────
MODE=live
FIXTURE=""
for arg in "$@"; do
	case "$arg" in
	-h | --help)
		sed -n '1,20p' "$0"
		exit 0
		;;
	--fixture)
		MODE=fixture
		;;
	--selftest)
		MODE=selftest
		;;
	-*)
		echo "unknown flag: $arg" >&2
		exit 2
		;;
	*)
		if [[ "$MODE" == "fixture" && -z "$FIXTURE" ]]; then
			FIXTURE="$arg"
		else
			echo "unexpected argument: $arg" >&2
			exit 2
		fi
		;;
	esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/incus/wire-gate-lib.sh
source "${SCRIPT_DIR}/wire-gate-lib.sh"

if [[ "$MODE" == "selftest" ]]; then
	# Hermetic matrix over the shared verdict core. Each row feeds one
	# input shape and asserts the exact line + exit code.
	pass=0
	fail=0
	cell() { # cell <label> <want_verdict> <want_rc> -- <counts...>
		local label="$1" want_v="$2" want_rc="$3"
		shift 3
		[[ "${1:-}" == "--" ]] && shift
		local out rc v
		out=$(wire_deny_verdict "$@")
		rc=$?
		v=$(awk '{print $3}' <<<"$out")
		if [[ "$v" == "$want_v" && "$rc" == "$want_rc" && "$out" == WIRE_GATE\ wire_policy_deny\ * ]]; then
			echo "  PASS  $label"
			pass=$((pass + 1))
		else
			echo "  FAIL  $label (got '$out' rc=$rc)"
			fail=$((fail + 1))
		fi
	}
	cell "good transcript maps to PASS" PASS 0 -- 1000 0 1000 1000 0
	cell "permit-all leak maps to FAIL" FAIL 1 -- 1000 41 1000 1000 0
	cell "missing control maps to VOID capture-blind" VOID 2 -- 1000 0 1000 0 0
	cell "short burst maps to VOID under-sampled" VOID 2 -- 500 0 1000 1000 0
	cell "short control offer maps to VOID under-sampled" VOID 2 -- 1000 0 500 500 0
	cell "broken checksum maps to FAIL" FAIL 1 -- 1000 0 1000 1000 2
	cell "non-numeric input maps to VOID harness-void" VOID 2 -- x 0 1000 1000 0
	cell "leak wins over missing control" FAIL 1 -- 1000 5 1000 0 0
	echo "  wire-policy-deny selftest: $pass passed, $fail failed"
	[[ "$fail" -eq 0 ]] || exit 1
	[[ "$pass" -gt 0 ]] || {
		echo "FAIL: zero cells ran"
		exit 1
	}
	exit 0
fi

if [[ "$MODE" == "fixture" ]]; then
	[[ -n "$FIXTURE" ]] || {
		echo "usage: $0 --fixture <transcript.tsv>" >&2
		exit 2
	}
	parsed=$(wire_parse_transcript "$FIXTURE") || {
		printf 'WIRE_GATE wire_policy_deny VOID reason=harness-void probe_offered=0 probe_leaked=0 control_offered=0 control_observed=0 cksum_bad=0\n'
		exit 2
	}
	# shellcheck disable=SC2034
	eval "$parsed" || {
		printf 'WIRE_GATE wire_policy_deny VOID reason=harness-void probe_offered=0 probe_leaked=0 control_offered=0 control_observed=0 cksum_bad=0\n'
		exit 2
	}
	po=${probe_offered:-} pl=${probe_leaked:-} co=${control_offered:-}
	cb=${control_observed:-} ck=${cksum_bad:-0}
	if [[ -z "$po" || -z "$pl" || -z "$co" || -z "$cb" ]]; then
		printf 'WIRE_GATE wire_policy_deny VOID reason=harness-void probe_offered=0 probe_leaked=0 control_offered=0 control_observed=0 cksum_bad=0\n'
		exit 2
	fi
	wire_deny_verdict "$po" "$pl" "$co" "$cb" "$ck"
	exit $?
fi

# ── live gate (destructive lock cell) ────────────────────────────────
_CELL_DIR="$SCRIPT_DIR"
# shellcheck source=test/incus/cluster-cell.sh
source "${_CELL_DIR}/cluster-cell.sh"
xpf_enter_destructive_cluster_cell "wire-policy-deny $*" "$0" "$@"

# shellcheck source=test/incus/cluster-env.sh
source "${SCRIPT_DIR}/cluster-env.sh"

FROM_ZONE="${FROM_ZONE:-lan}"
TO_ZONE="${TO_ZONE:-wan}"
# Probe/control UDP ports. Same protocol, same pair — the ONLY difference is
# the dst port the narrowed policy keys on (the §2.2 near-miss rule).
PROBE_PORT="${PROBE_PORT:-54901}"
CONTROL_PORT="${CONTROL_PORT:-54902}"
# Burst sizes: probe at the §2 drop floor exactly (1000 offered, zero must
# emerge — no margin games on the deny leg). Control over-offered separately.
BURST="${BURST:-1000}"
# Control is over-offered (1500 vs the 1000-observed floor) so routine path
# loss cannot manufacture a capture-blind VOID. Must stay even (split runs).
CONTROL_BURST="${CONTROL_BURST:-1500}"
SINK="${SINK:-${MOUSE_TARGET_V4:-172.16.80.201}}"
APP_NAME="wire-9531-ctl"
SET_NAME="wire-9531-set"
SG="sg incus-admin -c"
CLI=/usr/local/sbin/cli
PROBER_SRC="${SCRIPT_DIR}/wire_probe_burst.py"
REMOTE_PROBE="/tmp/xpf-wire_probe_burst.py"
# Per-step wall-clock deadlines (plan §5b: expiry ⇒ VOID row-timeout).
STEP_TIMEOUT="${STEP_TIMEOUT:-120}"

# Provisional verdict bookkeeping (COMPUTE → restore → PRINT).
PROV_VERDICT=""
PROV_METRICS=""
RESTORE_CLEAN=1

run_cli() { $SG "incus exec $NODE -- bash -lc 'cli'" 2>&1; }
NODE="${NODE:-$FW0}"


# emit <verdict> <reason> <metrics> — the single PRINT point for live runs.
emit() {
	printf 'WIRE_GATE wire_policy_deny %s reason=%s %s\n' "$1" "$2" "$3"
}

# early_void <slug> — pre-measurement refusal: empty metrics map, which the
# emitter permits on VOID rows. Exit 3 (refused) so the wrapper records
# VOID via the line, rc 2 via the contract.
early_void() {
	emit VOID "$1" ""
	exit 3
}

# policy_lines — display-set lines for the zone-pair stanza; validity is
# checked by callers (non-empty + stanza anchor), never assumed.
policy_lines() {
	printf 'show configuration security policies from-zone %s to-zone %s | display set\nexit\n' \
		"$FROM_ZONE" "$TO_ZONE" | run_cli
}

echo "=== wire_policy_deny: transit no-permit-rule drop on the wire ==="
echo "node=$NODE lan_host=$CLUSTER_LAN_HOST sink=$SINK probe_udp=$PROBE_PORT control_udp=$CONTROL_PORT"

# ── Phase 0: preconditions (every one diagnostic-preserving) ─────────
echo "--- preconditions ---"
POLines="$(policy_lines)"
if [[ -z "$POLines" ]]; then
	echo "REFUSE: policy stanza unreadable (empty cli output)"
	early_void env-void
fi
if ! grep -q "policy allow-all" <<<"$POLines"; then
	echo "REFUSE: baseline policy allow-all not found in $FROM_ZONE->$TO_ZONE"
	early_void env-void
fi
if grep -q "$APP_NAME\|$SET_NAME" <<<"$POLines"; then
	echo "REFUSE: stale wire-9531 fixture already present (a killed prior run left it)"
	early_void env-void
fi
echo "baseline allow-all: PRESENT, no stale fixture"

if ! $SG "incus exec $CLUSTER_LAN_HOST -- ping -c2 -W2 $SINK" >/dev/null 2>&1; then
	echo "REFUSE: lan host cannot reach sink $SINK"
	early_void no-prober
fi
echo "lan->sink reachability: OK"
# Capture-point fixture: the sink must be an incus-managed container carrying
# tcpdump, or this row has no peer-side oracle (VOID no-prober, never PASS).
if ! $SG "incus exec $SINK -- sh -c 'command -v tcpdump'" >/dev/null 2>&1; then
	# $SINK may be an IP, not an instance name — resolve via the mouse target
	# name when the bare exec fails.
	MOUSE_REF="${MOUSE_TARGET_NAME:-loss:xpf-mouse-target}"
	if ! $SG "incus exec $MOUSE_REF -- sh -c 'command -v tcpdump'" >/dev/null 2>&1; then
		echo "REFUSE: no managed capture point (tcpdump missing on sink $SINK / $MOUSE_REF)"
		early_void no-prober
	fi
	SINK_EXEC="$MOUSE_REF"
else
	SINK_EXEC="$SINK"
fi
echo "capture point: $SINK_EXEC (tcpdump present)"
if [[ ! -f "$PROBER_SRC" ]]; then
	echo "REFUSE: prober missing: $PROBER_SRC"
	early_void harness-void
fi
$SG "incus exec $CLUSTER_LAN_HOST -- rm -f $REMOTE_PROBE" >/dev/null 2>&1 || true
if ! $SG "incus file push --mode 0755 $PROBER_SRC ${CLUSTER_LAN_HOST}${REMOTE_PROBE}" >/dev/null 2>&1; then
	echo "REFUSE: could not push prober to $CLUSTER_LAN_HOST"
	early_void harness-void
fi

# Baseline config snapshot for the post-run diff.
BASELINE_SNAP="$(mktemp "${TMPDIR:-/var/tmp}/xpf-wire-baseline.XXXXXX")"
trap 'rm -f "$BASELINE_SNAP"' EXIT
printf '%s\n' "$POLines" >"$BASELINE_SNAP"

# Same-path baseline (plan §5b(1)/Codex-r4): P and control must BOTH forward
# pre-fixture on the tested path, or neither the verdict nor the restore
# comparison means anything.
echo "--- same-path baseline burst (pre-fixture) ---"
# Capture runs in the background: a foreground `tcpdump -c` would wait for
# packets the burst has not sent yet. tcpdump prints `IP a.b.c.d.p > w.x.y.z.q:`
# with the dst port BEFORE the `UDP` token, hence the `\.port:` patterns.
BASE_CAPLOG="$(mktemp "${TMPDIR:-/var/tmp}/xpf-wire-basecap.XXXXXX")"
$SG "incus exec $SINK_EXEC -- timeout $STEP_TIMEOUT tcpdump -i any -n udp and dst host $SINK and '(' dst port $PROBE_PORT or dst port $CONTROL_PORT ')'" >"$BASE_CAPLOG" 2>&1 &
BASE_CAP_PID=$!
sleep 3
if ! $SG "incus exec $CLUSTER_LAN_HOST -- timeout $STEP_TIMEOUT python3 $REMOTE_PROBE --dst $SINK --probe-port $PROBE_PORT --control-port $CONTROL_PORT --count 30 --rate 100" >/dev/null 2>&1; then
	kill "$BASE_CAP_PID" 2>/dev/null || true
	wait "$BASE_CAP_PID" 2>/dev/null || true
	rm -f "$BASE_CAPLOG"
	echo "REFUSE: baseline burst failed to send"
	early_void harness-void
fi
sleep 2
kill "$BASE_CAP_PID" 2>/dev/null || true
wait "$BASE_CAP_PID" 2>/dev/null || true
if ! grep -qE "\.${PROBE_PORT}:" "$BASE_CAPLOG"; then
	rm -f "$BASE_CAPLOG"
	echo "REFUSE: baseline probe did not emerge pre-fixture (path not forwarding)"
	early_void env-void
fi
if ! grep -qE "\.${CONTROL_PORT}:" "$BASE_CAPLOG"; then
	rm -f "$BASE_CAPLOG"
	echo "REFUSE: baseline control did not emerge pre-fixture (path not forwarding)"
	early_void env-void
fi
rm -f "$BASE_CAPLOG"
echo "same-path baseline: probe + control both forward pre-fixture"

echo "--- fixture: narrow allow-all to the control app (commit confirmed) ---"
FIXTURE_CMDS="configure
set applications application $APP_NAME protocol udp destination-port $CONTROL_PORT
set applications application-set $SET_NAME application $APP_NAME
delete security policies from-zone $FROM_ZONE to-zone $TO_ZONE policy allow-all match application
set security policies from-zone $FROM_ZONE to-zone $TO_ZONE policy allow-all match application $SET_NAME
commit check"
# Run the check to a FILE first, then grep the file: a streaming
# `... | tee log | grep -q` gate once misfired live on output that
# demonstrably contained the success line (pipe-reader race), and a commit
# gate must not depend on pipe timing.
printf '%s\nexit\n' "$FIXTURE_CMDS" | run_cli > /tmp/xpf-wire-fixture-check.log 2>&1
if ! grep -q "check succeeds" /tmp/xpf-wire-fixture-check.log; then
	echo "--- commit check output ---"
	cat /tmp/xpf-wire-fixture-check.log 2>/dev/null | tail -5
	echo "VOID: fixture failed commit check (harness-side syntax problem)"
	PROV_VERDICT="VOID"
	PROV_METRICS="probe_offered=0 probe_leaked=0 control_offered=0 control_observed=0 cksum_bad=0"
	RESTORE_CLEAN=1
	emit VOID harness-void "$PROV_METRICS"
	exit 2
fi
# Negative control (fail-on-bad acceptance): WIRE_BROKEN_FIXTURE=1 skips the
# narrowing commit, leaving baseline permit-all in place while the gate
# measures exactly as usual. The probe MUST then emerge peer-side and the
# verdict MUST be FAIL — exercising the live probe→capture→verdict path
# against a genuinely permitted flow. Test-harness flag only; the dataplane
# is untouched.
if [[ -n "${WIRE_BROKEN_FIXTURE:-}" ]]; then
	echo "NEGATIVE CONTROL: skipping narrowing commit (permit-all stays)"
else
	printf 'configure\nset applications application %s protocol udp destination-port %s\nset applications application-set %s application %s\ndelete security policies from-zone %s to-zone %s policy allow-all match application\nset security policies from-zone %s to-zone %s policy allow-all match application %s\ncommit confirmed 2\nexit\n' \
		"$APP_NAME" "$CONTROL_PORT" "$SET_NAME" "$APP_NAME" \
		"$FROM_ZONE" "$TO_ZONE" "$FROM_ZONE" "$TO_ZONE" "$SET_NAME" | run_cli >/dev/null 2>&1
fi
sleep 5
# Fixture-active check: the narrowed match must be readable back, or every
# later reading is evidence about the wrong config. In broken mode the
# permit-all baseline itself is the checked state.
POST_LINES="$(policy_lines)"
if [[ -n "${WIRE_BROKEN_FIXTURE:-}" ]]; then
	if ! grep -q "policy allow-all match application any" <<<"$POST_LINES"; then
		echo "VOID: negative control needs baseline permit-all (not present)"
		emit VOID harness-void "probe_offered=0 probe_leaked=0 control_offered=0 control_observed=0 cksum_bad=0"
		exit 2
	fi
	echo "negative control active: permit-all in place (probe must emerge)"
elif ! grep -q "$SET_NAME" <<<"$POST_LINES"; then
	echo "VOID: fixture did not land (narrowed match not readable back)"
	PROV_VERDICT="VOID"
	PROV_METRICS="probe_offered=0 probe_leaked=0 control_offered=0 control_observed=0 cksum_bad=0"
	RESTORE_CLEAN=1
	emit VOID harness-void "$PROV_METRICS"
	exit 2
fi
if [[ -z "${WIRE_BROKEN_FIXTURE:-}" ]]; then
	echo "fixture active: allow-all narrowed to $SET_NAME (probe has no permit rule)"
fi

# Restore is registered BEFORE measuring so any later failure still cleans
# up. Trap kills remote generators (the §6 watchdog) and deletes the fixture
# with a plain confirming commit, then the explicit step below verifies.
do_restore() {
	$SG "incus exec $SINK_EXEC -- pkill -f 'tcpdump.*$PROBE_PORT' 2>/dev/null" >/dev/null 2>&1 || true
	printf 'configure\ndelete applications application-set %s\ndelete applications application %s\ndelete security policies from-zone %s to-zone %s policy allow-all match application\nset security policies from-zone %s to-zone %s policy allow-all match application any\ncommit\nexit\n' \
		"$SET_NAME" "$APP_NAME" "$FROM_ZONE" "$TO_ZONE" "$FROM_ZONE" "$TO_ZONE" | run_cli >/dev/null 2>&1 || true
}
trap 'do_restore; rm -f "$BASELINE_SNAP"' EXIT

# ── Phase 2: shared capture window + bursts ──────────────────────────
# Probe at the §2 drop floor (1000, zero must emerge); control with a
# loss margin (offered 1500, ≥1000 must emerge) so routine path loss
# cannot manufacture a capture-blind VOID. Two sender runs under ONE
# capture window.
echo "--- capture window + bursts (probe $BURST, control $CONTROL_BURST) ---"
CAPLOG="$(mktemp "${TMPDIR:-/var/tmp}/xpf-wire-cap.XXXXXX")"
$SG "incus exec $SINK_EXEC -- timeout $STEP_TIMEOUT tcpdump -i any -n -vv udp and dst host $SINK and '(' dst port $PROBE_PORT or dst port $CONTROL_PORT ')'" >"$CAPLOG" 2>&1 &
CAP_PID=$!
sleep 3 # let tcpdump settle before the first datagram
SENT_P="$($SG "incus exec $CLUSTER_LAN_HOST -- timeout $STEP_TIMEOUT python3 $REMOTE_PROBE --dst $SINK --probe-port $PROBE_PORT --control-port $PROBE_PORT --count $((BURST / 2)) --rate 200" 2>&1 | grep -E '^SENT' || true)"
SENT_C="$($SG "incus exec $CLUSTER_LAN_HOST -- timeout $STEP_TIMEOUT python3 $REMOTE_PROBE --dst $SINK --probe-port $CONTROL_PORT --control-port $CONTROL_PORT --count $((CONTROL_BURST / 2)) --rate 200" 2>&1 | grep -E '^SENT' || true)"
echo "sender probe: $SENT_P"
echo "sender control: $SENT_C"
# Both legs of each run target the SAME port, so offered = probe + control.
# Portable sed (no gawk match() arrays): extract-or-empty, then add.
_pp=$(sed -E 's/.*probe=([0-9]+).*/\1/;t;d' <<<"$SENT_P" 2>/dev/null || true)
_pc=$(sed -E 's/.*control=([0-9]+).*/\1/;t;d' <<<"$SENT_P" 2>/dev/null || true)
_cp=$(sed -E 's/.*probe=([0-9]+).*/\1/;t;d' <<<"$SENT_C" 2>/dev/null || true)
_cc=$(sed -E 's/.*control=([0-9]+).*/\1/;t;d' <<<"$SENT_C" 2>/dev/null || true)
POFFERED=0
COFFERED=0
[[ "$_pp" =~ ^[0-9]+$ && "$_pc" =~ ^[0-9]+$ ]] && POFFERED=$((_pp + _pc))
[[ "$_cp" =~ ^[0-9]+$ && "$_cc" =~ ^[0-9]+$ ]] && COFFERED=$((_cp + _cc))
sleep 5 # drain: datagrams in flight when the sender exits
kill "$CAP_PID" 2>/dev/null || true
wait "$CAP_PID" 2>/dev/null || true
PLEAKED=$(grep -cE "\.${PROBE_PORT}:" "$CAPLOG" 2>/dev/null || true)
COBSERVED=$(grep -cE "\.${CONTROL_PORT}:" "$CAPLOG" 2>/dev/null || true)
CKSUM=$(grep -ciE "bad (udp|ip) (cksum|checksum)" "$CAPLOG" 2>/dev/null || true)
# grep -c prints 0 with rc 1 on no match; normalise to bare numbers.
PLEAKED=$(printf '%s' "$PLEAKED" | tr -d ' \n' || true)
COBSERVED=$(printf '%s' "$COBSERVED" | tr -d ' \n' || true)
CKSUM=$(printf '%s' "$CKSUM" | tr -d ' \n' || true)
[[ "$PLEAKED" =~ ^[0-9]+$ ]] || PLEAKED=0
[[ "$COBSERVED" =~ ^[0-9]+$ ]] || COBSERVED=0
[[ "$CKSUM" =~ ^[0-9]+$ ]] || CKSUM=0
rm -f "$CAPLOG"
echo "offered: probe=$POFFERED control=$COFFERED | observed: leaked=$PLEAKED control=$COBSERVED cksum_bad=$CKSUM"

# ── Phase 3: COMPUTE (not print) ─────────────────────────────────────
PROV_LINE="$(wire_deny_verdict "$POFFERED" "$PLEAKED" "$COFFERED" "$COBSERVED" "$CKSUM")"
PROV_RC=$?
PROV_VERDICT=$(awk '{print $3}' <<<"$PROV_LINE")
PROV_METRICS=$(sed -E 's/^WIRE_GATE wire_policy_deny (PASS|FAIL|VOID) reason=[^ ]+ //' <<<"$PROV_LINE")
case "$PROV_VERDICT" in
PASS) echo "provisional: PASS" ;;
FAIL) echo "provisional: FAIL ($(grep -oE 'probe_leaked=[0-9]+' <<<"$PROV_METRICS"))" ;;
*) echo "provisional: $PROV_VERDICT ($(awk '{print $4}' <<<"$PROV_LINE"))" ;;
esac

# ── Phase 4: verified restore (config AND same-path dataplane) ───────
echo "--- verified restore ---"
do_restore
trap 'rm -f "$BASELINE_SNAP"' EXIT
sleep 3
RESTORE_CLEAN=1
NOW_LINES="$(policy_lines)"
if grep -q "$APP_NAME\|$SET_NAME" <<<"$NOW_LINES"; then
	echo "RESTORE-DIRTY: fixture marker still present post-restore"
	RESTORE_CLEAN=0
fi
if ! grep -q "policy allow-all match application any" <<<"$NOW_LINES"; then
	echo "RESTORE-DIRTY: baseline match line not back"
	RESTORE_CLEAN=0
fi
# Same-path dataplane proof: P must forward AGAIN post-restore (the narrow
# exclude is gone) and the control must still forward. A config diff alone
# cannot certify this (store-only divergence).
RE_CAPLOG="$(mktemp "${TMPDIR:-/var/tmp}/xpf-wire-recap.XXXXXX")"
$SG "incus exec $SINK_EXEC -- timeout 60 tcpdump -i any -n udp and dst host $SINK and '(' dst port $PROBE_PORT or dst port $CONTROL_PORT ')'" >"$RE_CAPLOG" 2>&1 &
RE_CAP_PID=$!
sleep 3
if ! $SG "incus exec $CLUSTER_LAN_HOST -- timeout $STEP_TIMEOUT python3 $REMOTE_PROBE --dst $SINK --probe-port $PROBE_PORT --control-port $CONTROL_PORT --count 30 --rate 100" >/dev/null 2>&1; then
	echo "RESTORE-DIRTY: post-restore re-probe failed to send"
	kill "$RE_CAP_PID" 2>/dev/null || true
	wait "$RE_CAP_PID" 2>/dev/null || true
	rm -f "$RE_CAPLOG"
	RESTORE_CLEAN=0
else
sleep 2
kill "$RE_CAP_PID" 2>/dev/null || true
wait "$RE_CAP_PID" 2>/dev/null || true
if ! grep -qE "\.${PROBE_PORT}:" "$RE_CAPLOG"; then
	echo "RESTORE-DIRTY: probe does not forward post-restore (stale exclude?)"
	RESTORE_CLEAN=0
fi
if ! grep -qE "\.${CONTROL_PORT}:" "$RE_CAPLOG"; then
	echo "RESTORE-DIRTY: control does not forward post-restore"
	RESTORE_CLEAN=0
fi
rm -f "$RE_CAPLOG"
fi
if [[ "$RESTORE_CLEAN" == "1" ]]; then
	echo "restore verified: config diff clean + same-path forwarding back"
else
	echo "STALE-FIXTURE NOTICE: restore failed — later runs will refuse until '$APP_NAME/$SET_NAME' is gone and P forwards"
fi

# ── Phase 5: PRINT once, per the §5b(6) precedence table ──────────────
if [[ "$PROV_VERDICT" == "PASS" && "$RESTORE_CLEAN" == "1" ]]; then
	emit PASS -- "$PROV_METRICS"
	echo "PASS: transit no-permit-rule drop holds on the wire"
	exit 0
elif [[ "$PROV_VERDICT" == "PASS" ]]; then
	emit VOID env-void "$PROV_METRICS"
	exit 2
elif [[ "$PROV_VERDICT" == "FAIL" ]]; then
	echo "FAIL: policy_leak (probe frames emerged peer-side)"
	emit FAIL -- "$PROV_METRICS"
	exit 1
else
	PROV_REASON=$(awk '{print $4}' <<<"$PROV_LINE" | sed 's/reason=//')
	emit VOID "$PROV_REASON" "$PROV_METRICS"
	exit 2
fi
