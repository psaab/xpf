#!/usr/bin/env bash
# #10030 — wire_conntrack_lifecycle: create, witness, idle-expire, and re-probe.
# The subject socket remains established and silent while the session timeout
# elapses; a later payload is sent on that same five-tuple. A fresh raw tuple
# and a permitted SYN control use the SAME destination port and capture window;
# SYN-ness is the only policy-visible near-miss dimension.
set -uo pipefail

MODE=live
FIXTURE=""
while (($#)); do
    case "$1" in
    --selftest) MODE=selftest ;;
    --fixture) MODE=fixture; shift; FIXTURE="${1:-}" ;;
    -h|--help) sed -n '1,18p' "$0"; exit 0 ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *) echo "unexpected argument: $1" >&2; exit 2 ;;
    esac
    shift
done

if [[ -n "${WIRE_BROKEN_FIXTURE:-}" ]]; then
    export XPF_WIRE_BROKEN_FIXTURE="$WIRE_BROKEN_FIXTURE"
fi
BROKEN_FIXTURE="${XPF_WIRE_BROKEN_FIXTURE:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/wire-gate-lib.sh"

if [[ "$MODE" == selftest ]]; then
    pass=0; fail=0
    check() {
        local label="$1" want="$2" want_rc="$3"; shift 3
        local out rc v
        out=$(wire_conntrack_verdict "$@"); rc=$?; v=$(awk '{print $3}' <<<"$out")
        if [[ "$v" == "$want" && "$rc" == "$want_rc" && "$out" == WIRE_GATE\ wire_conntrack_lifecycle\ * ]]; then
            echo "  PASS  $label"; pass=$((pass + 1))
        else
            echo "  FAIL  $label (got '$out' rc=$rc)"; fail=$((fail + 1))
        fi
    }
    check "create witness expire and drops pass" PASS 0 1 1 0 1000 0 1000 0 1500 1500 1 0
    check "stale session fails" FAIL 1 1 1 1 1000 0 1000 0 1500 1500 1 0
    check "expired subject leak fails" FAIL 1 1 1 0 1000 1 1000 0 1500 1500 1 0
    check "missing subject witness is void" VOID 2 1 0 0 1000 0 1000 0 1500 1500 0 0
    check "missing create with control witness fails" FAIL 1 0 0 0 1000 0 1000 0 1500 1500 1 0
    check "missing create and control witness is void" VOID 2 0 0 0 1000 0 1000 0 1500 1500 0 0
    check "under-sampled post legs are void" VOID 2 1 1 0 999 0 1000 0 1500 1500 1 0
    check "checksum corruption fails" FAIL 1 1 1 0 1000 0 1000 0 1500 1500 1 1
    check "malformed field is harness void" VOID 2 1 1 0 1000 x 1000 0 1500 1500 1 0
    echo "  wire-conntrack-lifecycle selftest: $pass passed, $fail failed"
    [[ "$fail" -eq 0 && "$pass" -gt 0 ]] || exit 1
    exit 0
fi

if [[ "$MODE" == fixture ]]; then
    [[ -n "$FIXTURE" && -f "$FIXTURE" ]] || { echo "usage: $0 --fixture <transcript>" >&2; exit 2; }
    vals=(); malformed=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        case "$line" in
        created=*|witnessed=*|stale_present=*|exp_offered=*|exp_leaked=*|fresh_offered=*|fresh_leaked=*|syn_offered=*|syn_observed=*|ctrl_sess=*|cksum_bad=*) vals+=("${line#*=}") ;;
        *) malformed=1 ;;
        esac
    done <"$FIXTURE"
    if ((malformed)) || ((${#vals[@]} != 11)); then
        wire_conntrack_verdict x x x x x x x x x x x; exit $?
    fi
    wire_conntrack_verdict "${vals[@]}"; exit $?
fi

source "${SCRIPT_DIR}/cluster-cell.sh"
xpf_enter_destructive_cluster_cell "wire-conntrack-lifecycle $*" "$0" "$@"
source "${SCRIPT_DIR}/cluster-env.sh"

INCUS_REMOTE="${INCUS_REMOTE:-loss}"
NODE="${NODE:-${FW0:-xpf-userspace-fw0}}"
FW_A="${FW0:-${INCUS_REMOTE}:xpf-userspace-fw0}"
FW_B="${FW1:-${INCUS_REMOTE}:xpf-userspace-fw1}"
LAN_REF="${CLUSTER_LAN_HOST:-${INCUS_REMOTE}:cluster-userspace-host}"
SINK_HOST="${SINK_HOST:-xpf-mouse-target}"; SINK_HOST="${SINK_HOST#*:}"
SINK_REF="${INCUS_REMOTE}:${SINK_HOST}"
LAN_ADDR="${LAN_ADDR:-${LAN_HOST_IP:-10.0.61.102}}"; LAN_ADDR="${LAN_ADDR%%/*}"
SINK_ADDR="${SINK_ADDR:-172.16.80.201}"
LIFECYCLE_PORT="${LIFECYCLE_PORT:-54921}"
LIFECYCLE_SRC_PORT="${LIFECYCLE_SRC_PORT:-$((40000 + RANDOM % 20000))}"
CONTROL_SOURCE_PORT="${CONTROL_SOURCE_PORT:-$((40000 + RANDOM % 20000))}"
FRESH_SOURCE_PORT="${FRESH_SOURCE_PORT:-$((40000 + RANDOM % 20000))}"
while [[ "$CONTROL_SOURCE_PORT" == "$LIFECYCLE_SRC_PORT" || "$CONTROL_SOURCE_PORT" == "$FRESH_SOURCE_PORT" ]]; do CONTROL_SOURCE_PORT="$((40000 + RANDOM % 20000))"; done
while [[ "$FRESH_SOURCE_PORT" == "$LIFECYCLE_SRC_PORT" ]]; do FRESH_SOURCE_PORT="$((40000 + RANDOM % 20000))"; done
CONTROL_BURST="${CONTROL_BURST:-1500}"
EXPIRED_BURST="${EXPIRED_BURST:-1000}"
FRESH_BURST="${FRESH_BURST:-1000}"
IDLE_WAIT="${IDLE_WAIT:-15}"
APP_TIMEOUT="${APP_TIMEOUT:-10}"
STEP_TIMEOUT="${STEP_TIMEOUT:-90}"
APP_SET="wire-10030-lifecycle-set"
APP_LIFECYCLE="wire-10030-lifecycle"
HOLD_SRC="${SCRIPT_DIR}/wire_tcp_hold.py"
PROBER_SRC="${SCRIPT_DIR}/wire_probe_burst.py"
RAW_SRC="${SCRIPT_DIR}/wire_raw_tcp_burst.py"
REMOTE_HOLD="/tmp/xpf-wire_tcp_hold.py"
REMOTE_PROBE="/tmp/xpf-wire_probe_burst.py"
REMOTE_RAW="/tmp/xpf-wire_raw_tcp_burst.py"
SG="sg incus-admin -c"
CAP_PID=""; CAPLOG=""; RESTORE_NEEDED=0; RESTORE_OK=1

run_cli() { $SG "incus exec ${NODE} -- bash -lc 'cli'"; }
run_cli_t() { timeout 90 $SG "incus exec ${NODE} -- bash -lc 'cli'" 2>&1; }
cli_show() { printf '%s\nexit\n' "$1" | run_cli; }
fail_void() { printf 'WIRE_GATE wire_conntrack_lifecycle VOID reason=%s created=0 witnessed=0 evicted=0 stale_present=0 exp_offered=0 exp_leaked=0 fresh_offered=0 fresh_leaked=0 syn_offered=0 syn_observed=0 ctrl_sess=0 lifecycle_bad=0 cksum_bad=0\n' "$1"; exit 3; }

session_list() { printf 'show security flow session destination-prefix %s destination-port %s limit 10000\nexit\n' "$SINK_ADDR" "$1" | run_cli_t; }
session_count() {
    local port="$1" out n
    out="$(session_list "$port")" || return 2
    [[ "$out" == *"Total sessions:"* ]] || return 2
    n="$(grep -cE "${SINK_ADDR//./\\.}.*${port}|${port}.*${SINK_ADDR//./\\.}" <<<"$out" 2>/dev/null || true)"
    n="$(printf '%s' "$n" | tr -d ' \n')"; [[ "$n" =~ ^[0-9]+$ ]] || n=0
    printf '%s' "$n"
}

restore_config() {
    ((RESTORE_NEEDED)) || return 0
    local log=/tmp/xpf-wire-conntrack-restore.log
    local cmds
    cmds="configure\ndelete security policies from-zone lan to-zone wan policy allow-all match application\nset security policies from-zone lan to-zone wan policy allow-all match application any\ndelete applications application-set ${APP_SET}\ndelete applications application ${APP_LIFECYCLE}\ncommit\nexit\n"
    if ! printf '%b' "$cmds" | $SG "incus exec ${NODE} -- bash -lc 'cli'" >"$log" 2>&1; then RESTORE_OK=0; fi
    grep -qE 'commit (complete|succeeded)' "$log" 2>/dev/null || RESTORE_OK=0
    local p; p="$(cli_show 'show configuration security policies from-zone lan to-zone wan | display set' 2>&1)"
    [[ "$p" == *"policy allow-all match application any"* ]] || RESTORE_OK=0
    [[ "$p" != *"wire-10030"* ]] || RESTORE_OK=0
    local a; a="$(cli_show 'show configuration applications | display set' 2>&1)"
    [[ "$a" != *"wire-10030"* ]] || RESTORE_OK=0
    RESTORE_NEEDED=0
}
cleanup() {
    [[ -n "$CAP_PID" ]] && kill "$CAP_PID" >/dev/null 2>&1 || true
    for host in "$LAN_REF" "$SINK_REF"; do
        $SG "incus exec ${host} -- pkill -f '[w]ire_tcp_hold.py'" >/dev/null 2>&1 || true
        $SG "incus exec ${host} -- pkill -f '[w]ire_probe_burst'" >/dev/null 2>&1 || true
        $SG "incus exec ${host} -- pkill -f '[w]ire_raw_tcp_burst.py'" >/dev/null 2>&1 || true
    done
    restore_config
    [[ -n "$CAPLOG" ]] && rm -f "$CAPLOG"
}
trap cleanup EXIT
trap 'trap - INT TERM; cleanup; exit 130' INT
trap 'trap - INT TERM; cleanup; exit 143' TERM

BASE="$(cli_show 'show configuration security policies | display set' 2>&1)"
[[ "$BASE" == *"set security policies default-policy deny-all"* ]] || fail_void env-void
[[ "$BASE" == *"from-zone lan to-zone wan policy allow-all match application any"* ]] || fail_void env-void
[[ "$BASE" != *"wire-10030"* ]] || fail_void env-void
[[ -f "$HOLD_SRC" && -f "$PROBER_SRC" && -f "$RAW_SRC" ]] || fail_void harness-void
$SG "incus exec ${SINK_REF} -- sh -c 'command -v tcpdump && command -v python3'" >/dev/null 2>&1 || fail_void no-prober
$SG "incus exec ${LAN_REF} -- sh -c 'command -v python3 && python3 -c \"import socket; s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_RAW); s.close()\"'" >/dev/null 2>&1 || fail_void no-prober
$SG "incus exec ${LAN_REF} -- rm -f ${REMOTE_HOLD} ${REMOTE_PROBE} ${REMOTE_RAW}" >/dev/null 2>&1 || fail_void harness-void
$SG "incus file push --mode 0755 ${HOLD_SRC} ${LAN_REF}${REMOTE_HOLD}" >/dev/null 2>&1 || fail_void harness-void
$SG "incus file push --mode 0755 ${PROBER_SRC} ${LAN_REF}${REMOTE_PROBE}" >/dev/null 2>&1 || fail_void harness-void
$SG "incus file push --mode 0755 ${RAW_SRC} ${LAN_REF}${REMOTE_RAW}" >/dev/null 2>&1 || fail_void harness-void
$SG "incus exec ${SINK_REF} -- rm -f ${REMOTE_HOLD}" >/dev/null 2>&1 || fail_void harness-void
$SG "incus file push --mode 0755 ${HOLD_SRC} ${SINK_REF}${REMOTE_HOLD}" >/dev/null 2>&1 || fail_void harness-void

RESTORE_NEEDED=1
TIMEOUT_VALUE="$APP_TIMEOUT"
[[ -n "$BROKEN_FIXTURE" ]] && TIMEOUT_VALUE=300
CONFIG="configure\nset applications application ${APP_LIFECYCLE} protocol tcp destination-port ${LIFECYCLE_PORT}\nset applications application ${APP_LIFECYCLE} inactivity-timeout ${TIMEOUT_VALUE}\nset applications application-set ${APP_SET} application ${APP_LIFECYCLE}\ndelete security policies from-zone lan to-zone wan policy allow-all match application\nset security policies from-zone lan to-zone wan policy allow-all match application ${APP_SET}\ncommit\nexit\n"
printf '%b' "$CONFIG" | $SG "incus exec ${NODE} -- bash -lc 'cli'" >/tmp/xpf-wire-conntrack-commit.log 2>&1 || fail_void harness-void
grep -qE 'commit (complete|succeeded)' /tmp/xpf-wire-conntrack-commit.log || fail_void harness-void

for p in "$LIFECYCLE_PORT"; do
    $SG "incus exec ${SINK_REF} -- rm -f /tmp/xpf-wire-hold-${p}.log" >/dev/null 2>&1 || fail_void harness-void
    $SG "incus exec ${SINK_REF} -- sh -c 'nohup python3 -u ${REMOTE_HOLD} --serve ${p} --duration 120 >/tmp/xpf-wire-hold-${p}.log 2>&1 &'" >/dev/null 2>&1 || fail_void harness-void
done
for p in "$LIFECYCLE_PORT"; do
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        $SG "incus exec ${SINK_REF} -- grep -q 'LISTEN port=${p}' /tmp/xpf-wire-hold-${p}.log" >/dev/null 2>&1 && break
        sleep 1
    done
    $SG "incus exec ${SINK_REF} -- grep -q 'LISTEN port=${p}' /tmp/xpf-wire-hold-${p}.log" >/dev/null 2>&1 || fail_void harness-void
done

$SG "incus exec ${LAN_REF} -- rm -f /tmp/xpf-wire-create.log" >/dev/null 2>&1 || fail_void harness-void
$SG "incus exec ${LAN_REF} -- sh -c 'nohup python3 -u ${REMOTE_HOLD} --client ${SINK_ADDR} ${LIFECYCLE_PORT} --duration 45 --heartbeat 1 --silent-after 3 --source-port ${LIFECYCLE_SRC_PORT} >/tmp/xpf-wire-create.log 2>&1 &'" >/dev/null 2>&1 || fail_void harness-void
CREATED=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if $SG "incus exec ${LAN_REF} -- grep -q CONNECTED /tmp/xpf-wire-create.log" >/dev/null 2>&1; then CREATED=1; break; fi
    sleep 1
done
WITNESSED=0; QUERY_BAD=0
if ((CREATED)); then
    for _ in 1 2 3 4 5; do
        if n="$(session_count "$LIFECYCLE_PORT")"; then
            if ((n > 0)); then WITNESSED=1; break; fi
        else QUERY_BAD=1; fi
        sleep 1
    done
fi
sleep "$IDLE_WAIT"
STALE=0
if n="$(session_count "$LIFECYCLE_PORT")"; then ((n > 0)) && STALE=1; else QUERY_BAD=1; fi
# Keep the lifecycle application permitted for the post-expiry probes.  The
# expired tuple and the never-created tuple differ from the control only by
# conntrack state and SYN-ness; deleting the application here would make a
# policy deny, rather than lifecycle state, explain every drop.
CONTROL_LOG="/tmp/xpf-wire-control.log"
$SG "incus exec ${LAN_REF} -- rm -f ${CONTROL_LOG}" >/dev/null 2>&1 || fail_void harness-void
$SG "incus exec ${LAN_REF} -- sh -c 'nohup python3 -u ${REMOTE_HOLD} --client ${SINK_ADDR} ${LIFECYCLE_PORT} --duration 45 --heartbeat 1 --source-port ${CONTROL_SOURCE_PORT} >${CONTROL_LOG} 2>&1 &'" >/dev/null 2>&1 || fail_void harness-void
CONTROL_READY=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
    $SG "incus exec ${LAN_REF} -- grep -q CONNECTED ${CONTROL_LOG}" >/dev/null 2>&1 && { CONTROL_READY=1; break; }
    sleep 1
done
((CONTROL_READY)) || fail_void harness-void

CAPLOG="$(mktemp "${TMPDIR:-/var/tmp}/xpf-wire-conntrack-cap.XXXXXX")"
$SG "incus exec ${SINK_REF} -- timeout ${STEP_TIMEOUT} tcpdump -i eth0 -nn -tt -vv -s 0 'tcp and dst host ${SINK_ADDR} and dst port ${LIFECYCLE_PORT}'" >"$CAPLOG" 2>&1 &
CAP_PID=$!
sleep 2
EXP_RAW="$($SG "incus exec ${LAN_REF} -- timeout ${STEP_TIMEOUT} python3 ${REMOTE_RAW} --src ${LAN_ADDR} --dst ${SINK_ADDR} --sport ${LIFECYCLE_SRC_PORT} --dport ${LIFECYCLE_PORT} --count ${EXPIRED_BURST} --payload-size 64 --rate 2000" 2>&1 || true)"
FRESH_RAW="$($SG "incus exec ${LAN_REF} -- timeout ${STEP_TIMEOUT} python3 ${REMOTE_RAW} --src ${LAN_ADDR} --dst ${SINK_ADDR} --sport ${FRESH_SOURCE_PORT} --dport ${LIFECYCLE_PORT} --count ${FRESH_BURST} --payload-size 64 --rate 2000" 2>&1 || true)"
SENT="$($SG "incus exec ${LAN_REF} -- timeout ${STEP_TIMEOUT} python3 ${REMOTE_PROBE} --dst ${SINK_ADDR} --tcp-timeout 0.2 --tcp-leg ${LIFECYCLE_PORT}:${CONTROL_BURST}" 2>&1 || true)"
sleep 8
$SG "incus exec ${SINK_REF} -- pkill -f '[t]cpdump.*${LIFECYCLE_PORT}'" >/dev/null 2>&1 || true
kill "$CAP_PID" >/dev/null 2>&1 || true; wait "$CAP_PID" >/dev/null 2>&1 || true; CAP_PID=""
legpart="${SENT##*SENT tcplegs=}"; extract_leg() { local p="$1" item; IFS=',' read -ra legs <<<"$legpart"; for item in "${legs[@]}"; do [[ "${item%%=*}" == "$p" ]] && { printf '%s' "${item#*=}"; return; }; done; printf '0'; }
SYN_OFFER="$(extract_leg "$LIFECYCLE_PORT")"
EXP_OFFER="${EXP_RAW##*SENT raw=}"; FRESH_OFFER="${FRESH_RAW##*SENT raw=}"
for v in EXP_OFFER FRESH_OFFER SYN_OFFER; do [[ "${!v}" =~ ^[0-9]+$ ]] || printf -v "$v" '0'; done
EXP_LEAK="$(grep -cE "\\.${LIFECYCLE_SRC_PORT} > .*\\.${LIFECYCLE_PORT}:" "$CAPLOG" 2>/dev/null || true)"
FRESH_LEAK="$(grep -cE "\\.${FRESH_SOURCE_PORT} > .*\\.${LIFECYCLE_PORT}:" "$CAPLOG" 2>/dev/null || true)"
SYN_OBS="$(grep -cE "\\.${LIFECYCLE_PORT}: Flags \\[S\\]" "$CAPLOG" 2>/dev/null || true)"
for v in EXP_LEAK FRESH_LEAK SYN_OBS; do [[ "${!v}" =~ ^[0-9]+$ ]] || printf -v "$v" '0'; done
CTRL_SESS=0
if n="$(session_count "$LIFECYCLE_PORT")"; then CTRL_SESS="$n"; else QUERY_BAD=1; fi
CK="$(grep -ciE 'bad (tcp|ip) (cksum|checksum)' "$CAPLOG" 2>/dev/null || true)"; [[ "$CK" =~ ^[0-9]+$ ]] || CK=0
if ((QUERY_BAD)); then WITNESSED=0; CTRL_SESS=0; fi
FINAL_OUT="$(wire_conntrack_verdict "$CREATED" "$WITNESSED" "$STALE" "$EXP_OFFER" "$EXP_LEAK" "$FRESH_OFFER" "$FRESH_LEAK" "$SYN_OFFER" "$SYN_OBS" "$CTRL_SESS" "$CK")"; FINAL_RC=$?
trap - EXIT INT TERM; cleanup
if ((RESTORE_OK == 0)); then
    printf 'WIRE_GATE wire_conntrack_lifecycle VOID reason=harness-void created=0 witnessed=0 evicted=0 stale_present=0 exp_offered=0 exp_leaked=0 fresh_offered=0 fresh_leaked=0 syn_offered=0 syn_observed=0 ctrl_sess=0 lifecycle_bad=0 cksum_bad=0\n'; exit 2
fi
printf '%s\n' "$FINAL_OUT"; exit "$FINAL_RC"
