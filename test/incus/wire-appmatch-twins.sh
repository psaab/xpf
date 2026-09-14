#!/usr/bin/env bash
# wire_appmatch_twins gate — #9531 (ZPV-01).
#
# The regression shape for the protocol-only widening class: a policy
# permitting ONLY two applications (tcp/80, udp/53) must forward both permit
# twins and drop both deny twins (tcp/8080, udp/5353) — all four legs under
# ONE shared capture window with ONE filter, so the emerged permit frames
# prove the capture path the deny absences are read against. TCP legs run as
# connect bursts (established AND refused both prove the SYN emerged); the
# tcp/80 leg gets a sink-side listener so handshakes complete. UDP twin
# ports are PINNED (53/5353), never derived. Permit legs are
# liveness-grade (plan §16: lab UDP loss makes 0%-loss claims unpassable).
#
# Usage / exit codes: same contract as wire-policy-deny.sh
#   (live lock cell; --fixture <tsv>; --selftest; 0/1/2/3).
# Live topology: same as wire-policy-deny.sh (LAN prober, VLAN-80 mouse
# target capture point).

set -uo pipefail

MODE=live
FIXTURE=""
for arg in "$@"; do
	case "$arg" in
	-h | --help)
		sed -n '1,16p' "$0"
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

# Pinned twin ports (plan §5a: band keys must be stable, never derived).
T80=80
T8080=8080
U53=53
U5353=5353

if [[ "$MODE" == "selftest" ]]; then
	pass=0
	fail=0
	cell() { # cell <label> <want_verdict> <want_rc> -- <9 counts...>
		local label="$1" want_v="$2" want_rc="$3"
		shift 3
		[[ "${1:-}" == "--" ]] && shift
		local out rc v
		out=$(wire_twins_verdict "$@")
		rc=$?
		v=$(awk '{print $3}' <<<"$out")
		if [[ "$v" == "$want_v" && "$rc" == "$want_rc" && "$out" == WIRE_GATE\ wire_appmatch_twins\ * ]]; then
			echo "  PASS  $label"
			pass=$((pass + 1))
		else
			echo "  FAIL  $label (got '$out' rc=$rc)"
			fail=$((fail + 1))
		fi
	}
	cell "good transcript maps to PASS" PASS 0 -- 1500 1400 1000 0 1500 1350 1000 0 0
	cell "lossy-but-above-floor permit legs still PASS" PASS 0 -- 1500 1100 1000 0 1500 1050 1000 0 0
	cell "widened deny twin maps to FAIL" FAIL 1 -- 1500 1400 1000 9 1500 1350 1000 0 0
	cell "widened udp twin maps to FAIL" FAIL 1 -- 1500 1400 1000 0 1500 1350 1000 4 0
	cell "dropped permit twin (sibling emerged) maps to FAIL" FAIL 1 -- 1500 400 1000 0 1500 1350 1000 0 0
	cell "both permit twins missing maps to VOID capture-blind" VOID 2 -- 1500 400 1000 0 1500 300 1000 0 0
	cell "thin deny leg maps to VOID under-sampled" VOID 2 -- 1500 1400 500 0 1500 1350 1000 0 0
	cell "thin permit offer maps to VOID under-sampled" VOID 2 -- 1000 1000 1000 0 1500 1350 1000 0 0
	cell "broken checksum maps to FAIL" FAIL 1 -- 1500 1400 1000 0 1500 1350 1000 0 3
	cell "non-numeric input maps to VOID harness-void" VOID 2 -- 1500 x 1000 0 1500 1350 1000 0 0
	echo "  wire-appmatch-twins selftest: $pass passed, $fail failed"
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
		printf 'WIRE_GATE wire_appmatch_twins VOID reason=harness-void tcp80_offered=0 tcp80_observed=0 tcp8080_offered=0 tcp8080_observed=0 udp53_offered=0 udp53_observed=0 udp5353_offered=0 udp5353_observed=0 deny_leaked=0 permit_missing=0 cksum_bad=0\n'
		exit 2
	}
	# shellcheck disable=SC2034
	eval "$parsed" || {
		printf 'WIRE_GATE wire_appmatch_twins VOID reason=harness-void tcp80_offered=0 tcp80_observed=0 tcp8080_offered=0 tcp8080_observed=0 udp53_offered=0 udp53_observed=0 udp5353_offered=0 udp5353_observed=0 deny_leaked=0 permit_missing=0 cksum_bad=0\n'
		exit 2
	}
	for k in tcp80_offered tcp80_observed tcp8080_offered tcp8080_observed udp53_offered udp53_observed udp5353_offered udp5353_observed; do
		if [[ -z "${!k:-}" ]]; then
			printf 'WIRE_GATE wire_appmatch_twins VOID reason=harness-void tcp80_offered=0 tcp80_observed=0 tcp8080_offered=0 tcp8080_observed=0 udp53_offered=0 udp53_observed=0 udp5353_offered=0 udp5353_observed=0 deny_leaked=0 permit_missing=0 cksum_bad=0\n'
			exit 2
		fi
	done
	wire_twins_verdict "$tcp80_offered" "$tcp80_observed" "$tcp8080_offered" "$tcp8080_observed" "$udp53_offered" "$udp53_observed" "$udp5353_offered" "$udp5353_observed" "${cksum_bad:-0}"
	exit $?
fi

# ── live gate (destructive lock cell) ────────────────────────────────
_CELL_DIR="$SCRIPT_DIR"
# shellcheck source=test/incus/cluster-cell.sh
source "${_CELL_DIR}/cluster-cell.sh"
xpf_enter_destructive_cluster_cell "wire-appmatch-twins $*" "$0" "$@"

# shellcheck source=test/incus/cluster-env.sh
source "${SCRIPT_DIR}/cluster-env.sh"

FROM_ZONE="${FROM_ZONE:-lan}"
TO_ZONE="${TO_ZONE:-wan}"
# Twin floors (live-finding demotion, plan §16): deny legs at the §2 drop
# floor; permit legs LIVENESS-grade — offered 1500 (500-frame margin over the
# 1000-observed floor, absorbing routine path loss), no 0%-loss claim.
PERMIT_N="${PERMIT_N:-1500}"
DENY_N="${DENY_N:-1000}"
SINK="${SINK:-${MOUSE_TARGET_V4:-172.16.80.201}}"
APP_TCP="wire-9531-http"
APP_UDP="wire-9531-dns"
SET_NAME="wire-9531-twins"
SG="sg incus-admin -c"
PROBER_SRC="${SCRIPT_DIR}/wire_probe_burst.py"
REMOTE_PROBE="/tmp/xpf-wire_probe_burst.py"
LISTEN_SRC="${SCRIPT_DIR}/wire_tcp_accept.py"
REMOTE_LISTEN="/tmp/xpf-wire_tcp_accept.py"
STEP_TIMEOUT="${STEP_TIMEOUT:-180}"

PROV_VERDICT=""
PROV_METRICS=""
RESTORE_CLEAN=1

run_cli() { $SG "incus exec $NODE -- bash -lc 'cli'" 2>&1; }
NODE="${NODE:-$FW0}"

emit() {
	printf 'WIRE_GATE wire_appmatch_twins %s reason=%s %s\n' "$1" "$2" "$3"
}

early_void() {
	emit VOID "$1" ""
	exit 3
}

policy_lines() {
	printf 'show configuration security policies from-zone %s to-zone %s | display set\nexit\n' \
		"$FROM_ZONE" "$TO_ZONE" | run_cli
}

# legs_filter — the ONE shared capture filter covering all four twin ports,
# both transports (TCP legs are connects; UDP legs datagrams). The WHOLE
# filter is single-quoted: $SG runs its argument through a local shell
# first, and bare parens anywhere are a syntax error there (the incus
# invocation then never runs and the capture is empty).
legs_filter() {
	printf "'( tcp or udp ) and dst host %s and ( dst port %s or dst port %s or dst port %s or dst port %s )'" \
		"$SINK" "$T80" "$T8080" "$U53" "$U5353"
}
leg_count() {
	local n
	n=$(grep -cE "\.${2}:" "$1" 2>/dev/null || true)
	n=$(printf '%s' "$n" | tr -d ' \n' || true)
	[[ "$n" =~ ^[0-9]+$ ]] || n=0
	printf '%s' "$n"
}

# parse_leg <port> — offered count for one twin from the SENT legs= line.
# Anchored on `legs=` with an optional comma-terminated prefix so port 80
# never matches inside 8080. Reads the global SENT_LINE.
parse_leg() {
	local v
	v=$(sed -E "s/^.*legs=(.*,)?${1}=([0-9]+).*/\2/;t;d" <<<"$SENT_LINE" 2>/dev/null | head -1 || echo "")
	[[ "$v" =~ ^[0-9]+$ ]] || v=0
	printf '%s' "$v"
}

# start_listener <port> <seconds> — sink-side TCP acceptor for the tcp/80
# permit leg (handshakes must complete so connects prove transit, not just
# SYNs). Backgrounded; stop_listener kills it. The deny twin gets NO
# listener: any SYN there is a leak, RST or not.
LISTEN_PID=""
start_listener() {
	$SG "incus exec $SINK_EXEC -- timeout $2 python3 $REMOTE_LISTEN --port $1 --duration $2" >/dev/null 2>&1 &
	LISTEN_PID=$!
	sleep 3
}
stop_listener() {
	kill "$LISTEN_PID" 2>/dev/null || true
	wait "$LISTEN_PID" 2>/dev/null || true
	LISTEN_PID=""
}

# parse_tcpleg <port> — offered count from the SENT tcplegs= line (global
# SENT_TCP). Same anchoring discipline as parse_leg.
parse_tcpleg() {
	local v
	v=$(sed -E "s/^.*tcplegs=(.*,)?${1}=([0-9]+).*/\2/;t;d" <<<"$SENT_TCP" 2>/dev/null | head -1 || echo "")
	[[ "$v" =~ ^[0-9]+$ ]] || v=0
	printf '%s' "$v"
}

echo "=== wire_appmatch_twins: permit+deny twins on the wire ==="
echo "node=$NODE lan_host=$CLUSTER_LAN_HOST sink=$SINK"

# ── Phase 0: preconditions ───────────────────────────────────────────
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
if grep -q "$APP_TCP\|$APP_UDP\|$SET_NAME" <<<"$POLines"; then
	echo "REFUSE: stale wire-9531 fixture already present"
	early_void env-void
fi
echo "baseline allow-all: PRESENT, no stale fixture"

if ! $SG "incus exec $CLUSTER_LAN_HOST -- ping -c2 -W2 $SINK" >/dev/null 2>&1; then
	echo "REFUSE: lan host cannot reach sink $SINK"
	early_void no-prober
fi
MOUSE_REF="${MOUSE_TARGET_NAME:-loss:xpf-mouse-target}"
if ! $SG "incus exec $MOUSE_REF -- sh -c 'command -v tcpdump'" >/dev/null 2>&1; then
	echo "REFUSE: no managed capture point (tcpdump missing on $MOUSE_REF)"
	early_void no-prober
fi
SINK_EXEC="$MOUSE_REF"
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
if [[ ! -f "$LISTEN_SRC" ]]; then
	echo "REFUSE: listener missing: $LISTEN_SRC"
	early_void harness-void
fi
$SG "incus exec $SINK_EXEC -- rm -f $REMOTE_LISTEN" >/dev/null 2>&1 || true
if ! $SG "incus file push --mode 0755 $LISTEN_SRC ${SINK_EXEC}${REMOTE_LISTEN}" >/dev/null 2>&1; then
	echo "REFUSE: could not push listener to $SINK_EXEC"
	early_void harness-void
fi

BASELINE_SNAP="$(mktemp "${TMPDIR:-/var/tmp}/xpf-wire-baseline.XXXXXX")"
trap 'rm -f "$BASELINE_SNAP"' EXIT
printf '%s\n' "$POLines" >"$BASELINE_SNAP"

# Same-path baseline: all four twins forward pre-fixture (mini legs — a
# liveness check, not the verdict).
echo "--- same-path baseline burst (pre-fixture) ---"
BASE_CAPLOG="$(mktemp "${TMPDIR:-/var/tmp}/xpf-wire-basecap.XXXXXX")"
$SG "incus exec $SINK_EXEC -- timeout $STEP_TIMEOUT tcpdump -i any -n $(legs_filter)" >"$BASE_CAPLOG" 2>&1 &
BASE_CAP_PID=$!
sleep 3
start_listener $T80 120
if ! $SG "incus exec $CLUSTER_LAN_HOST -- timeout $STEP_TIMEOUT python3 $REMOTE_PROBE --dst $SINK --tcp-leg $T80:10 --tcp-leg $T8080:10 --leg $U53:30 --leg $U5353:30 --rate 100" >/dev/null 2>&1; then
	stop_listener
	kill "$BASE_CAP_PID" 2>/dev/null || true
	wait "$BASE_CAP_PID" 2>/dev/null || true
	rm -f "$BASE_CAPLOG"
	echo "REFUSE: baseline burst failed to send"
	early_void harness-void
fi
stop_listener
sleep 2
kill "$BASE_CAP_PID" 2>/dev/null || true
wait "$BASE_CAP_PID" 2>/dev/null || true
for p in $T80 $T8080 $U53 $U5353; do
	if ! grep -qE "\.${p}:" "$BASE_CAPLOG"; then
		rm -f "$BASE_CAPLOG"
		echo "REFUSE: baseline twin port $p did not emerge pre-fixture"
		early_void env-void
	fi
done
rm -f "$BASE_CAPLOG"
echo "same-path baseline: all four twins forward pre-fixture"

# ── Phase 1: two-term fixture (commit-confirmed) ─────────────────────
echo "--- fixture: allow-all narrowed to tcp/80 + udp/53 apps ---"
FIXTURE_CMDS="configure
set applications application $APP_TCP protocol tcp destination-port $T80
set applications application $APP_UDP protocol udp destination-port $U53
set applications application-set $SET_NAME application $APP_TCP
set applications application-set $SET_NAME application $APP_UDP
delete security policies from-zone $FROM_ZONE to-zone $TO_ZONE policy allow-all match application
set security policies from-zone $FROM_ZONE to-zone $TO_ZONE policy allow-all match application $SET_NAME
commit check"
# File-first commit gate (same pipe-race lesson as wire-policy-deny.sh).
printf '%s\nexit\n' "$FIXTURE_CMDS" | run_cli > /tmp/xpf-wire-twins-check.log 2>&1
if ! grep -q "check succeeds" /tmp/xpf-wire-twins-check.log; then
	tail -5 /tmp/xpf-wire-twins-check.log 2>/dev/null
	echo "VOID: fixture failed commit check (harness-side syntax problem)"
	emit VOID harness-void "tcp80_offered=0 tcp80_observed=0 tcp8080_offered=0 tcp8080_observed=0 udp53_offered=0 udp53_observed=0 udp5353_offered=0 udp5353_observed=0 deny_leaked=0 permit_missing=0 cksum_bad=0"
	exit 2
fi
# Negative control (fail-on-bad acceptance): WIRE_BROKEN_FIXTURE=1 leaves
# baseline permit-all in place (widened twin fixture) — the deny twins MUST
# emerge and the verdict MUST be FAIL with appmatch_widen.
if [[ -n "${WIRE_BROKEN_FIXTURE:-}" ]]; then
	echo "NEGATIVE CONTROL: skipping narrowing commit (permit-all stays)"
else
	printf 'configure\nset applications application %s protocol tcp destination-port %s\nset applications application %s protocol udp destination-port %s\nset applications application-set %s application %s\nset applications application-set %s application %s\ndelete security policies from-zone %s to-zone %s policy allow-all match application\nset security policies from-zone %s to-zone %s policy allow-all match application %s\ncommit confirmed 3\nexit\n' \
		"$APP_TCP" "$T80" "$APP_UDP" "$U53" "$SET_NAME" "$APP_TCP" "$SET_NAME" "$APP_UDP" \
		"$FROM_ZONE" "$TO_ZONE" "$FROM_ZONE" "$TO_ZONE" "$SET_NAME" | run_cli >/dev/null 2>&1
fi
sleep 5
POST_LINES="$(policy_lines)"
if [[ -n "${WIRE_BROKEN_FIXTURE:-}" ]]; then
	if ! grep -q "policy allow-all match application any" <<<"$POST_LINES"; then
		echo "VOID: negative control needs baseline permit-all (not present)"
		emit VOID harness-void "tcp80_offered=0 tcp80_observed=0 tcp8080_offered=0 tcp8080_observed=0 udp53_offered=0 udp53_observed=0 udp5353_offered=0 udp5353_observed=0 deny_leaked=0 permit_missing=0 cksum_bad=0"
		exit 2
	fi
	echo "negative control active: permit-all in place (deny twins must emerge)"
elif ! grep -q "$SET_NAME" <<<"$POST_LINES"; then
	echo "VOID: fixture did not land (narrowed match not readable back)"
	echo "(commit-confirmed auto-revert covers this path if the commit applied)"
	emit VOID harness-void "tcp80_offered=0 tcp80_observed=0 tcp8080_offered=0 tcp8080_observed=0 udp53_offered=0 udp53_observed=0 udp5353_offered=0 udp5353_observed=0 deny_leaked=0 permit_missing=0 cksum_bad=0"
	exit 2
elif [[ -z "${WIRE_BROKEN_FIXTURE:-}" ]]; then
	echo "fixture active: allow-all narrowed to $SET_NAME (tcp/80 + udp/53 only)"
fi

do_restore() {
	$SG "incus exec $SINK_EXEC -- pkill -f 'tcpdump.*dst port' 2>/dev/null" >/dev/null 2>&1 || true
	printf 'configure\ndelete applications application-set %s\ndelete applications application %s\ndelete applications application %s\ndelete security policies from-zone %s to-zone %s policy allow-all match application\nset security policies from-zone %s to-zone %s policy allow-all match application any\ncommit\nexit\n' \
		"$SET_NAME" "$APP_TCP" "$APP_UDP" "$FROM_ZONE" "$TO_ZONE" "$FROM_ZONE" "$TO_ZONE" | run_cli >/dev/null 2>&1 || true
}
trap 'do_restore; rm -f "$BASELINE_SNAP"' EXIT

# ── Phase 2: shared capture window + four legs ───────────────────────
# TCP legs run as connect bursts (the tcp/80 listener below completes
# handshakes; 8080 gets none — any SYN there is a leak). UDP legs as
# datagram bursts. One capture window covers both sender runs.
echo "--- capture window + twins (tcp permit $PERMIT_N/deny $DENY_N, udp permit $PERMIT_N/deny $DENY_N) ---"
CAPLOG="$(mktemp "${TMPDIR:-/var/tmp}/xpf-wire-cap.XXXXXX")"
$SG "incus exec $SINK_EXEC -- timeout $STEP_TIMEOUT tcpdump -i any -n -vv $(legs_filter)" >"$CAPLOG" 2>&1 &
CAP_PID=$!
sleep 3
start_listener $T80 600
SENT_TCP="$($SG "incus exec $CLUSTER_LAN_HOST -- timeout $STEP_TIMEOUT python3 $REMOTE_PROBE --dst $SINK --tcp-leg $T80:$PERMIT_N --tcp-leg $T8080:$DENY_N" 2>&1 || true)"
echo "sender tcp: $SENT_TCP"
SENT_LINE="$($SG "incus exec $CLUSTER_LAN_HOST -- timeout $STEP_TIMEOUT python3 $REMOTE_PROBE --dst $SINK --leg $U53:$PERMIT_N --leg $U5353:$DENY_N --rate 200" 2>&1 || true)"
echo "sender udp: $SENT_LINE"
stop_listener
T80O=$(parse_tcpleg $T80)
T88O=$(parse_tcpleg $T8080)
U53O=$(parse_leg $U53)
U35O=$(parse_leg $U5353)
sleep 5
kill "$CAP_PID" 2>/dev/null || true
wait "$CAP_PID" 2>/dev/null || true
T80B=$(leg_count "$CAPLOG" $T80)
T88B=$(leg_count "$CAPLOG" $T8080)
U53B=$(leg_count "$CAPLOG" $U53)
U35B=$(leg_count "$CAPLOG" $U5353)
CKS=$(grep -ciE "bad (udp|ip|tcp) (cksum|checksum)" "$CAPLOG" 2>/dev/null || true)
CKS=$(printf '%s' "$CKS" | tr -d ' \n' || true)
[[ "$CKS" =~ ^[0-9]+$ ]] || CKS=0
rm -f "$CAPLOG"
echo "offered: 80=$T80O 8080=$T88O 53=$U53O 5353=$U35O | observed: 80=$T80B 8080=$T88B 53=$U53B 5353=$U35B cksum_bad=$CKS"

# ── Phase 3: COMPUTE (not print) ─────────────────────────────────────
PROV_LINE="$(wire_twins_verdict "$T80O" "$T80B" "$T88O" "$T88B" "$U53O" "$U53B" "$U35O" "$U35B" "$CKS")"
PROV_VERDICT=$(awk '{print $3}' <<<"$PROV_LINE")
PROV_METRICS=$(sed -E 's/^WIRE_GATE wire_appmatch_twins (PASS|FAIL|VOID) reason=[^ ]+ //' <<<"$PROV_LINE")
echo "provisional: $PROV_VERDICT"

# ── Phase 4: verified restore ────────────────────────────────────────
echo "--- verified restore ---"
do_restore
trap 'rm -f "$BASELINE_SNAP"' EXIT
sleep 3
RESTORE_CLEAN=1
NOW_LINES="$(policy_lines)"
if grep -q "$APP_TCP\|$APP_UDP\|$SET_NAME" <<<"$NOW_LINES"; then
	echo "RESTORE-DIRTY: fixture marker still present post-restore"
	RESTORE_CLEAN=0
fi
if ! grep -q "policy allow-all match application any" <<<"$NOW_LINES"; then
	echo "RESTORE-DIRTY: baseline match line not back"
	RESTORE_CLEAN=0
fi
RE_CAPLOG="$(mktemp "${TMPDIR:-/var/tmp}/xpf-wire-recap.XXXXXX")"
$SG "incus exec $SINK_EXEC -- timeout 60 tcpdump -i any -n $(legs_filter)" >"$RE_CAPLOG" 2>&1 &
RE_CAP_PID=$!
sleep 3
start_listener $T80 90
if ! $SG "incus exec $CLUSTER_LAN_HOST -- timeout $STEP_TIMEOUT python3 $REMOTE_PROBE --dst $SINK --tcp-leg $T80:10 --tcp-leg $T8080:10 --leg $U53:30 --leg $U5353:30 --rate 100" >/dev/null 2>&1; then
	echo "RESTORE-DIRTY: post-restore re-probe failed to send"
	stop_listener
	kill "$RE_CAP_PID" 2>/dev/null || true
	wait "$RE_CAP_PID" 2>/dev/null || true
	rm -f "$RE_CAPLOG"
	RESTORE_CLEAN=0
else
	stop_listener
	sleep 2
	kill "$RE_CAP_PID" 2>/dev/null || true
	wait "$RE_CAP_PID" 2>/dev/null || true
	for p in $T80 $T8080 $U53 $U5353; do
		if ! grep -qE "\.${p}:" "$RE_CAPLOG"; then
			echo "RESTORE-DIRTY: twin port $p does not forward post-restore"
			RESTORE_CLEAN=0
		fi
	done
	rm -f "$RE_CAPLOG"
fi
if [[ "$RESTORE_CLEAN" == "1" ]]; then
	echo "restore verified: config diff clean + same-path forwarding back"
else
	echo "STALE-FIXTURE NOTICE: restore failed — later runs will refuse until '$SET_NAME' is gone and all twins forward"
fi

# ── Phase 5: PRINT once, per the §5b(6) precedence table ──────────────
if [[ "$PROV_VERDICT" == "PASS" && "$RESTORE_CLEAN" == "1" ]]; then
	emit PASS -- "$PROV_METRICS"
	echo "PASS: appmatch twins hold on the wire"
	exit 0
elif [[ "$PROV_VERDICT" == "PASS" ]]; then
	emit VOID env-void "$PROV_METRICS"
	exit 2
elif [[ "$PROV_VERDICT" == "FAIL" ]]; then
	echo "FAIL: appmatch twin violated (see metrics)"
	emit FAIL -- "$PROV_METRICS"
	exit 1
else
	PROV_REASON=$(awk '{print $4}' <<<"$PROV_LINE" | sed 's/reason=//')
	emit VOID "$PROV_REASON" "$PROV_METRICS"
	exit 2
fi
