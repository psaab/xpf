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

# Emit the parent-container delete only when the pre-run applications subtree
# was empty. `show configuration applications | display set` can hide an
# empty container while whole-config display still preserves it; cleanup must
# remove that residue without deleting unrelated pre-existing applications.
restore_application_cmd() {
    [[ -z "${APP_SNAP:-}" ]] && printf 'delete applications\n'
}
# `stale_present` is independent wire evidence: it is derived only from
# completed expired-tuple capture, never from the session census. Eviction is
# proved separately by the exact witnessed SID transition below.
wire_conntrack_stale_present() {
    local expired_wire_leak="${1:-}"
    wire_num "$expired_wire_leak" || return 2
    ((10#$expired_wire_leak > 0)) && printf '1' || printf '0'
}


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
    if wire_gate_finalizer_selftest; then
        echo "  PASS  cleanup finalizer shields restore"; pass=$((pass + 1))
    else
        echo "  FAIL  cleanup finalizer shields restore"; fail=$((fail + 1))
    fi
    APP_SNAP=""
    if [[ "$(restore_application_cmd)" == "delete applications" ]]; then
        echo "  PASS  empty applications container is removed on restore"; pass=$((pass + 1))
    else
        echo "  FAIL  empty applications container is removed on restore"; fail=$((fail + 1))
    fi
    APP_SNAP="set applications application preexisting protocol tcp"
    if [[ -z "$(restore_application_cmd)" ]]; then
        echo "  PASS  pre-existing applications are preserved on restore"; pass=$((pass + 1))
    else
        echo "  FAIL  pre-existing applications are preserved on restore"; fail=$((fail + 1))
    fi
    unset APP_SNAP
    if [[ "$(wire_conntrack_stale_present 0)" == 0 ]]; then
        echo "  PASS  dropped expired tuple is not stale"; pass=$((pass + 1))
    else
        echo "  FAIL  dropped expired tuple is not stale"; fail=$((fail + 1))
    fi
    if [[ "$(wire_conntrack_stale_present 1000)" == 1 ]]; then
        echo "  PASS  leaked expired tuple is stale"; pass=$((pass + 1))
    else
        echo "  FAIL  leaked expired tuple is stale"; fail=$((fail + 1))
    fi
    RENDERER_LIST='Session ID: 4343, Policy name: allow-all/1, HA State: Active, Timeout: 300, Session State: Valid
  In: 10.0.61.102/24001 --> 172.16.80.201/54921;tcp, Conn Tag: 0x0, If: ge-0/0/0, Zone: lan, Pkts: 1, Bytes: 64,
Total sessions: 1'
    if [[ "$(wire_conntrack_pick_sid "$RENDERER_LIST" 172.16.80.201 54921)" == "4343 300" ]]; then
        echo "  PASS  renderer-format SID witness parses"; pass=$((pass + 1))
    else
        echo "  FAIL  renderer-format SID witness parses"; fail=$((fail + 1))
    fi
    check "create witness evict and drops pass" PASS 0 1 1 0 1 1000 0 1000 0 1500 1500 1 0
    check "stale wire evidence fails" FAIL 1 1 1 1 1 1000 0 1000 0 1500 1500 1 0
    check "expired subject leak fails" FAIL 1 1 1 1 1 1000 1 1000 0 1500 1500 1 0
    out="$(wire_conntrack_verdict 1 1 1 1 1000 0 1000 0 1500 1500 1 0)"; rc=$?
    if [[ "$rc" == 1 && "$out" == *"stale_present=1"* && "$out" == *"lifecycle_bad=1"* ]]; then
        echo "  PASS  independent stale evidence has a nonzero headline"; pass=$((pass + 1))
    else
        echo "  FAIL  independent stale evidence headline (got '$out' rc=$rc)"; fail=$((fail + 1))
    fi
    out="$(wire_conntrack_verdict 1 1 1 1 1000 1000 1000 0 1500 1500 1 0)"; rc=$?
    if [[ "$rc" == 1 && "$out" == *"stale_present=1"* && "$out" == *"lifecycle_bad=1000"* ]]; then
        echo "  PASS  stale evidence is not double-counted"; pass=$((pass + 1))
    else
        echo "  FAIL  stale evidence is not double-counted (got '$out' rc=$rc)"; fail=$((fail + 1))
    fi
    check "retained witnessed SID fails eviction" FAIL 1 1 1 0 0 1000 0 1000 0 1500 1500 1 0
    check "missing subject witness is void" VOID 2 1 0 0 0 1000 0 1000 0 1500 1500 0 0
    check "missing create with control witness fails" FAIL 1 0 0 0 0 1000 0 1000 0 1500 1500 1 0
    check "missing create and control witness is void" VOID 2 0 0 0 0 1000 0 1000 0 1500 1500 0 0
    check "under-sampled post legs are void" VOID 2 1 1 0 1 999 0 1000 0 1500 1500 1 0
    check "checksum corruption fails" FAIL 1 1 1 0 1 1000 0 1000 0 1500 1500 1 1
    check "malformed field is harness void" VOID 2 1 1 0 1 1000 x 1000 0 1500 1500 1 0
    out="$(wire_conntrack_verdict 1 0 0 0 1000 0 1000 0 1500 1500 1 0)"; rc=$?
    if [[ "$rc" == 1 && "$out" == *"lifecycle_bad=2"* ]]; then
        echo "  PASS  missing witness headline records lifecycle failures"; pass=$((pass + 1))
    else
        echo "  FAIL  missing witness headline records lifecycle failures (got '$out' rc=$rc)"; fail=$((fail + 1))
    fi

    # Realistic Arm B-style listings exercise the session_list completeness
    # contract and tie post-state to the exact witnessed/control SIDs. The
    # broken fixture retains the witnessed subject SID; the fixed fixture
    # evicts it while retaining the control SID.
    MID_LIST='Session ID: 4242, Timeout: 300
  In: 10.0.61.102:24001 > 172.16.80.201:54921
  Out: 172.16.80.201:54921 > 10.0.61.102:24001
Total sessions: 1'
    CONTROL_LIST='Session ID: 4242, Timeout: 290
  In: 10.0.61.102:24001 > 172.16.80.201:54921
  Out: 172.16.80.201:54921 > 10.0.61.102:24001
Session ID: 4343, Timeout: 300
  In: 10.0.61.102:24003 > 172.16.80.201:54921
  Out: 172.16.80.201:54921 > 10.0.61.102:24003
Total sessions: 2'
    BROKEN_POST="$CONTROL_LIST"
    FIXED_POST='Session ID: 4343, Timeout: 290
  In: 10.0.61.102:24003 > 172.16.80.201:54921
  Out: 172.16.80.201:54921 > 10.0.61.102:24003
Total sessions: 1'
    transition="$(wire_conntrack_transition_flags "$MID_LIST" "$CONTROL_LIST" "$BROKEN_POST" 172.16.80.201 54921)"
    if [[ "$transition" == "4242 4343 0 1" ]]; then
        echo "  PASS  broken fixture parses complete listings and retains subject SID"; pass=$((pass + 1))
    else
        echo "  FAIL  broken fixture SID transition (got '$transition')"; fail=$((fail + 1))
    fi
    read -r subject_sid control_sid subject_absent control_present <<<"$transition"
    check "broken lifecycle fixture fails eviction" FAIL 1 1 1 0 "$subject_absent" 1000 0 1000 0 1500 1500 "$control_present" 0
    transition="$(wire_conntrack_transition_flags "$MID_LIST" "$CONTROL_LIST" "$FIXED_POST" 172.16.80.201 54921)"
    if [[ "$transition" == "4242 4343 1 1" ]]; then
        echo "  PASS  fixed fixture witnesses subject absent and control present"; pass=$((pass + 1))
    else
        echo "  FAIL  fixed fixture SID transition (got '$transition')"; fail=$((fail + 1))
    fi
    read -r subject_sid control_sid subject_absent control_present <<<"$transition"
    check "fixed lifecycle fixture passes eviction" PASS 0 1 1 0 "$subject_absent" 1000 0 1000 0 1500 1500 "$control_present" 0
    if ! wire_conntrack_transition_flags "$MID_LIST" "$CONTROL_LIST" "Session ID: 4343, Timeout: 290" 172.16.80.201 54921 >/dev/null 2>&1; then
        echo "  PASS  incomplete post listing is harness void"; pass=$((pass + 1))
    else
        echo "  FAIL  incomplete post listing was accepted"; fail=$((fail + 1))
    fi
    ZERO_POST='Total sessions: 0'
    transition="$(wire_conntrack_transition_flags "$MID_LIST" "$CONTROL_LIST" "$ZERO_POST" 172.16.80.201 54921)"
    if [[ "$transition" == "4242 4343 1 0" ]]; then
        echo "  PASS  zero-session listing is complete but lacks control"; pass=$((pass + 1))
    else
        echo "  FAIL  zero-session listing completeness (got '$transition')"; fail=$((fail + 1))
    fi
    read -r subject_sid control_sid subject_absent control_present <<<"$transition"
    check "zero-session witness is void" VOID 2 1 1 0 "$subject_absent" 1000 0 1000 0 1500 1500 "$control_present" 0
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
        created=*|witnessed=*|stale_present=*|subj_absent=*|exp_offered=*|exp_leaked=*|fresh_offered=*|fresh_leaked=*|syn_offered=*|syn_observed=*|ctrl_sess=*|cksum_bad=*) vals+=("${line#*=}") ;;
        *) malformed=1 ;;
        esac
    done <"$FIXTURE"
    if ((malformed)) || ((${#vals[@]} != 12)); then
        wire_conntrack_verdict x x x x x x x x x x x x; exit $?
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
LIFECYCLE_PORT="${LIFECYCLE_PORT:-$((40000 + RANDOM % 20000))}"
PORT_BASE="${WIRE_PORT_BASE:-$((20000 + RANDOM % 10000))}"
LIFECYCLE_SRC_PORT="${LIFECYCLE_SRC_PORT:-$PORT_BASE}"
FRESH_SOURCE_PORT="${FRESH_SOURCE_PORT:-$((LIFECYCLE_SRC_PORT + 1))}"
while [[ "$FRESH_SOURCE_PORT" == "$LIFECYCLE_SRC_PORT" ]]; do FRESH_SOURCE_PORT="$((20000 + RANDOM % 10000))"; done
CONTROL_SOURCE_PORT="${CONTROL_SOURCE_PORT:-$((FRESH_SOURCE_PORT + 1))}"
while [[ "$CONTROL_SOURCE_PORT" == "$LIFECYCLE_SRC_PORT" || "$CONTROL_SOURCE_PORT" == "$FRESH_SOURCE_PORT" ]]; do CONTROL_SOURCE_PORT="$((20000 + RANDOM % 10000))"; done
CONTROL_BURST="${CONTROL_BURST:-1500}"
EXPIRED_BURST="${EXPIRED_BURST:-1000}"
FRESH_BURST="${FRESH_BURST:-1000}"
IDLE_WAIT="${IDLE_WAIT:-}"
APP_TIMEOUT="${APP_TIMEOUT:-10}"
STEP_TIMEOUT="${STEP_TIMEOUT:-90}"
RESERVE_DURATION=$((STEP_TIMEOUT * 3 + 30))
SUBJECT_DURATION="${SUBJECT_DURATION:-$((RESERVE_DURATION + 360))}"
SINK_DURATION="${SINK_DURATION:-$((SUBJECT_DURATION + STEP_TIMEOUT + 60))}"
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
CREATE_LOG="/tmp/xpf-wire-create.log"
CREATE_PID_FILE="/tmp/xpf-wire-create.pid"
RESERVE_LOG="/tmp/xpf-wire-reserve.log"
RESERVE_PID_FILE="/tmp/xpf-wire-reserve.pid"

run_cli() { $SG "incus exec ${NODE} -- bash -lc 'cli'"; }
run_cli_t() { timeout 90 $SG "incus exec ${NODE} -- bash -lc 'cli'" 2>&1; }
cli_show() { printf '%s\nexit\n' "$1" | run_cli; }
snapshot() { cli_show "$1" 2>&1 | sed -n '/^set /p'; }
fail_void() {
    WIRE_GATE_FINAL_OUT="WIRE_GATE wire_conntrack_lifecycle VOID reason=$1 created=0 witnessed=0 evicted=0 subj_absent=0 stale_present=0 exp_offered=0 exp_leaked=0 fresh_offered=0 fresh_leaked=0 syn_offered=0 syn_observed=0 ctrl_sess=0 lifecycle_bad=0 cksum_bad=0"
    WIRE_GATE_FINAL_RC=3
    exit 3
}

session_list() {
    printf 'show security flow session destination-prefix %s destination-port %s limit 10000\nexit\n' "$SINK_ADDR" "$1" | run_cli_t
}
session_poll() {
    local port="$1" out
    for _ in 1 2 3; do
        out="$(session_list "$port")"
        if wire_conntrack_listing_complete "$out"; then
            printf '%s' "$out"
            return 0
        fi
        sleep 5
    done
    return 2
}


restore_config() {
    ((RESTORE_NEEDED)) || return 0
    local log=/tmp/xpf-wire-conntrack-restore.log
    local cmds line app_cmd
    cmds="configure\ndelete security flow\ndelete security policies from-zone lan to-zone wan policy allow-all match application\ndelete applications application-set ${APP_SET}\ndelete applications application ${APP_LIFECYCLE}\n"
    app_cmd="$(restore_application_cmd)"
    [[ -z "$app_cmd" ]] || cmds+="${app_cmd}"$'\n'
    while IFS= read -r line; do
        case "$line" in
        set\ security\ flow\ *) cmds+="${line}"$'\n' ;;
        set\ security\ policies\ from-zone\ lan\ to-zone\ wan\ policy\ allow-all\ match\ application\ *)
            cmds+="${line}"$'\n' ;;
        esac
    done <<<"$FLOW_SNAP"$'\n'"$POLICY_SNAP"
    cmds+="commit\nexit\n"
    if ! printf '%b' "$cmds" | $SG "incus exec ${NODE} -- bash -lc 'cli'" >"$log" 2>&1; then RESTORE_OK=0; fi
    grep -qE 'commit (complete|succeeded)' "$log" 2>/dev/null || RESTORE_OK=0
    local f; f="$(snapshot 'show configuration security flow | display set')"
    [[ "$f" == "$FLOW_SNAP" ]] || RESTORE_OK=0
    local p; p="$(snapshot 'show configuration security policies | display set')"
    [[ "$p" == "$POLICY_SNAP" ]] || RESTORE_OK=0
    local a; a="$(snapshot 'show configuration applications | display set')"
    [[ "$a" == "$APP_SNAP" ]] || RESTORE_OK=0
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
WIRE_GATE_CLEANUP_FN=cleanup
WIRE_GATE_RESTORE_OK_REF=RESTORE_OK
WIRE_GATE_RESTORE_VOID='WIRE_GATE wire_conntrack_lifecycle VOID reason=harness-void created=0 witnessed=0 evicted=0 subj_absent=0 stale_present=0 exp_offered=0 exp_leaked=0 fresh_offered=0 fresh_leaked=0 syn_offered=0 syn_observed=0 ctrl_sess=0 lifecycle_bad=0 cksum_bad=0'
wire_gate_signal_abort() { trap '' INT TERM; fail_void harness-void; }
trap wire_gate_finalize EXIT
trap wire_gate_signal_abort INT TERM

for port in "$LIFECYCLE_SRC_PORT" "$FRESH_SOURCE_PORT" "$CONTROL_SOURCE_PORT"; do
    [[ "$port" =~ ^[1-9][0-9]{0,4}$ ]] && ((10#$port <= 65535)) || fail_void harness-void
done
POLICY_SNAP="$(snapshot 'show configuration security policies | display set')"
APP_SNAP="$(snapshot 'show configuration applications | display set')"
FLOW_SNAP="$(snapshot 'show configuration security flow | display set')"
[[ "$POLICY_SNAP" == *"set security policies default-policy deny-all"* ]] || fail_void env-void
[[ "$POLICY_SNAP" == *"from-zone lan to-zone wan policy allow-all match application any"* ]] || fail_void env-void
[[ "$POLICY_SNAP" != *"wire-10030"* ]] || fail_void env-void
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
CONFIG="configure\nset applications application ${APP_LIFECYCLE} protocol tcp destination-port ${LIFECYCLE_PORT}\nset applications application ${APP_LIFECYCLE} inactivity-timeout ${APP_TIMEOUT}\nset applications application-set ${APP_SET} application ${APP_LIFECYCLE}\n"
if [[ -n "$BROKEN_FIXTURE" ]]; then
    CONFIG+="set security flow tcp-session initial-timeout 300\n"
fi
CONFIG+="delete security policies from-zone lan to-zone wan policy allow-all match application\nset security policies from-zone lan to-zone wan policy allow-all match application ${APP_SET}\ncommit\nexit\n"
printf '%b' "$CONFIG" | $SG "incus exec ${NODE} -- bash -lc 'cli'" >/tmp/xpf-wire-conntrack-commit.log 2>&1 || fail_void harness-void
grep -qE 'commit (complete|succeeded)' /tmp/xpf-wire-conntrack-commit.log || fail_void harness-void

for p in "$LIFECYCLE_PORT"; do
    $SG "incus exec ${SINK_REF} -- sh -c 'nohup python3 -u ${REMOTE_HOLD} --serve ${p} --duration ${SINK_DURATION} >/tmp/xpf-wire-hold-${p}.log 2>&1 &'" >/dev/null 2>&1 || fail_void harness-void
done
for p in "$LIFECYCLE_PORT"; do
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        $SG "incus exec ${SINK_REF} -- grep -q 'LISTEN port=${p}' /tmp/xpf-wire-hold-${p}.log" >/dev/null 2>&1 && break
        sleep 1
    done
    $SG "incus exec ${SINK_REF} -- grep -q 'LISTEN port=${p}' /tmp/xpf-wire-hold-${p}.log" >/dev/null 2>&1 || fail_void harness-void
done

$SG "incus exec ${LAN_REF} -- rm -f ${CREATE_LOG} ${CREATE_PID_FILE}" >/dev/null 2>&1 || fail_void harness-void
$SG "incus exec ${LAN_REF} -- sh -c 'nohup python3 -u ${REMOTE_HOLD} --client ${SINK_ADDR} ${LIFECYCLE_PORT} --duration ${SUBJECT_DURATION} --heartbeat 1 --silent-after 3 --source-port ${LIFECYCLE_SRC_PORT} >${CREATE_LOG} 2>&1 & echo \$! >${CREATE_PID_FILE}'" >/dev/null 2>&1 || fail_void harness-void
CREATED=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if $SG "incus exec ${LAN_REF} -- grep -q CONNECTED /tmp/xpf-wire-create.log" >/dev/null 2>&1; then CREATED=1; break; fi
    sleep 1
done
WITNESSED=0; QUERY_BAD=0; SUBJECT_SID=""; SUBJECT_TMO=0; MID_SESS_OUT=""
if ((CREATED)); then
    for _ in 1 2 3 4 5; do
        if MID_SESS_OUT="$(session_poll "$LIFECYCLE_PORT")"; then
            if pair="$(wire_conntrack_pick_sid "$MID_SESS_OUT" "$SINK_ADDR" "$LIFECYCLE_PORT")"; then
                read -r SUBJECT_SID SUBJECT_TMO <<<"$pair"
                WITNESSED=1
                break
            fi
        else
            QUERY_BAD=1
        fi
        sleep 1
    done
fi

if [[ -n "$BROKEN_FIXTURE" && "$WITNESSED" == 1 ]] &&
   { ! wire_num "$SUBJECT_TMO" || ((10#$SUBJECT_TMO < 250)); }; then
    fail_void harness-void
fi
if [[ -z "$IDLE_WAIT" ]]; then
    if [[ -n "$BROKEN_FIXTURE" ]]; then
        IDLE_WAIT=35
    elif ((WITNESSED)) && wire_num "$SUBJECT_TMO"; then
        IDLE_WAIT=$((10#$SUBJECT_TMO + 15))
        ((IDLE_WAIT > 120)) && IDLE_WAIT=120
    else
        fail_void harness-void
    fi
fi
sleep "$IDLE_WAIT"
if ! $SG "incus exec ${LAN_REF} -- sh -c 'pid=\$(cat ${CREATE_PID_FILE} 2>/dev/null) && kill -0 \"\$pid\" 2>/dev/null && grep -q CONNECTED ${CREATE_LOG} && ! grep -q Traceback ${CREATE_LOG}'" >/dev/null 2>&1; then
    fail_void harness-void
fi
# Keep the lifecycle application permitted for the post-expiry probes.  The
# expired tuple and the never-created tuple differ from the control only by
# conntrack state and SYN-ness; deleting the application here would make a
# policy deny, rather than lifecycle state, explain every drop.
CONTROL_LOG="/tmp/xpf-wire-control.log"
$SG "incus exec ${LAN_REF} -- rm -f ${CONTROL_LOG}" >/dev/null 2>&1 || fail_void harness-void
$SG "incus exec ${LAN_REF} -- sh -c 'nohup python3 -u ${REMOTE_HOLD} --client ${SINK_ADDR} ${LIFECYCLE_PORT} --duration ${SUBJECT_DURATION} --heartbeat 1 --source-port ${CONTROL_SOURCE_PORT} >${CONTROL_LOG} 2>&1 &'" >/dev/null 2>&1 || fail_void harness-void
CONTROL_READY=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
    $SG "incus exec ${LAN_REF} -- grep -q CONNECTED ${CONTROL_LOG}" >/dev/null 2>&1 && { CONTROL_READY=1; break; }
    sleep 1
done
((CONTROL_READY)) || fail_void harness-void
CONTROL_SESS_OUT=""; CONTROL_SID=""; CONTROL_TMO=0
if CONTROL_SESS_OUT="$(session_poll "$LIFECYCLE_PORT")" &&
   pair="$(wire_conntrack_pick_sid "$CONTROL_SESS_OUT" "$SINK_ADDR" "$LIFECYCLE_PORT" "$SUBJECT_SID")"; then
    read -r CONTROL_SID CONTROL_TMO <<<"$pair"
else
    QUERY_BAD=1
fi

$SG "incus exec ${LAN_REF} -- rm -f ${RESERVE_LOG} ${RESERVE_PID_FILE}" >/dev/null 2>&1 || fail_void harness-void
$SG "incus exec ${LAN_REF} -- sh -c 'nohup python3 -u ${REMOTE_HOLD} --reserve ${LAN_ADDR} ${FRESH_SOURCE_PORT} --duration ${RESERVE_DURATION} >${RESERVE_LOG} 2>&1 & echo \$! >${RESERVE_PID_FILE}'" >/dev/null 2>&1 || fail_void harness-void
RESERVED=0
for _ in 1 2 3 4 5; do
    $SG "incus exec ${LAN_REF} -- grep -q RESERVED ${RESERVE_LOG}" >/dev/null 2>&1 && { RESERVED=1; break; }
    sleep 1
done
((RESERVED)) || fail_void harness-void

CAPLOG="$(mktemp "${TMPDIR:-/var/tmp}/xpf-wire-conntrack-cap.XXXXXX")"
$SG "incus exec ${SINK_REF} -- timeout ${STEP_TIMEOUT} tcpdump -i eth0 -nn -tt -vv -s 0 'tcp and dst host ${SINK_ADDR} and dst port ${LIFECYCLE_PORT}'" >"$CAPLOG" 2>&1 &
CAP_PID=$!
sleep 2
EXP_RAW="$($SG "incus exec ${LAN_REF} -- timeout ${STEP_TIMEOUT} python3 ${REMOTE_RAW} --src ${LAN_ADDR} --dst ${SINK_ADDR} --sport ${LIFECYCLE_SRC_PORT} --dport ${LIFECYCLE_PORT} --count ${EXPIRED_BURST} --payload-size 64 --rate 2000" 2>&1 || true)"
FRESH_RAW="$($SG "incus exec ${LAN_REF} -- timeout ${STEP_TIMEOUT} python3 ${REMOTE_RAW} --src ${LAN_ADDR} --dst ${SINK_ADDR} --sport ${FRESH_SOURCE_PORT} --dport ${LIFECYCLE_PORT} --count ${FRESH_BURST} --payload-size 64 --rate 2000" 2>&1 || true)"
$SG "incus exec ${LAN_REF} -- sh -c 'pid=\$(cat ${RESERVE_PID_FILE} 2>/dev/null) && kill -0 \"\$pid\" 2>/dev/null'" >/dev/null 2>&1 || fail_void harness-void
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
if ! STALE="$(wire_conntrack_stale_present "$EXP_LEAK")"; then
    QUERY_BAD=1
    STALE=0
fi
SUBJ_ABSENT=0
CTRL_SESS=0
POST_SESS_OUT=""
if [[ -n "$SUBJECT_SID" && -n "$CONTROL_SID" ]] &&
   POST_SESS_OUT="$(session_poll "$LIFECYCLE_PORT")"; then
    if transition="$(wire_conntrack_transition_flags "$MID_SESS_OUT" "$CONTROL_SESS_OUT" "$POST_SESS_OUT" "$SINK_ADDR" "$LIFECYCLE_PORT")"; then
        read -r _ _ SUBJ_ABSENT CTRL_SESS <<<"$transition"
    else
        QUERY_BAD=1
    fi
else
    QUERY_BAD=1
fi
CK="$(grep -ciE 'bad (tcp|ip) (cksum|checksum)' "$CAPLOG" 2>/dev/null || true)"; [[ "$CK" =~ ^[0-9]+$ ]] || CK=0
if ((QUERY_BAD)); then WITNESSED=0; SUBJ_ABSENT=0; CTRL_SESS=0; fi
WIRE_GATE_FINAL_OUT="$(wire_conntrack_verdict "$CREATED" "$WITNESSED" "$STALE" "$SUBJ_ABSENT" "$EXP_OFFER" "$EXP_LEAK" "$FRESH_OFFER" "$FRESH_LEAK" "$SYN_OFFER" "$SYN_OBS" "$CTRL_SESS" "$CK")"
WIRE_GATE_FINAL_RC=$?
exit "$WIRE_GATE_FINAL_RC"
