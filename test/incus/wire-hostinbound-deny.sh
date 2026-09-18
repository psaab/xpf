#!/usr/bin/env bash
# #10029 — wire_hostinbound_deny: deny host-bound management services.
#
# The loss-cluster outside fixture is xpf-mouse-target on VLAN 80. It sends
# counted TCP SYNs to the DUT's WAN address (172.16.80.8) for SSH and HTTPS;
# tcpdump on that same managed outside endpoint is the peer-side oracle for
# replies. A temporary TCP netconf listener on the same DUT port family is the
# near-miss control admitted by the WAN host-inbound stanza. A temporary
# listener on both DUT nodes makes a SYN-ACK/RST an attributable admission
# observation rather than an absent application.
#
# Usage:
#   ./test/incus/wire-hostinbound-deny.sh
#   ./test/incus/wire-hostinbound-deny.sh --fixture transcript.tsv
#   ./test/incus/wire-hostinbound-deny.sh --selftest
#
# Fixture format: `reply_frames=N ctrl_offered=N ctrl_observed=N cksum_bad=N`
# followed by `cell OFFERED COMPLETED REFUSED` lines.
set -uo pipefail

MODE=live
FIXTURE=""
while (($#)); do
    case "$1" in
    --selftest) MODE=selftest ;;
    --fixture) MODE=fixture; shift; FIXTURE="${1:-}" ;;
    -h|--help) sed -n '1,28p' "$0"; exit 0 ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *) echo "unexpected argument: $1" >&2; exit 2 ;;
    esac
    shift
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/wire-gate-lib.sh"

if [[ "$MODE" == selftest ]]; then
    pass=0
    fail=0
    check() {
        local label="$1" want_v="$2" want_rc="$3"; shift 3
        local out rc v
        out=$(wire_hostinbound_verdict "$@")
        rc=$?
        v=$(awk '{print $3}' <<<"$out")
        if [[ "$v" == "$want_v" && "$rc" == "$want_rc" && "$out" == WIRE_GATE\ wire_hostinbound_deny\ * ]]; then
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
    GOOD=(1000 0 0 1000 0 0)
    check "denied SSH/HTTPS with TCP netconf control passes" PASS 0 0 1500 1500 0 2 "${GOOD[@]}"
    BAD=(1000 1 0 1000 0 0)
    check "SYN-ACK exposure fails" FAIL 1 0 1500 1500 0 2 "${BAD[@]}"
    REFUSED=(1000 0 1 1000 0 0)
    check "RST refusal counts as exposure" FAIL 1 0 1500 1500 0 2 "${REFUSED[@]}"
    check "under-sampled cell is VOID" VOID 2 0 1500 1500 0 2 999 0 0 1000 0 0
    check "missing TCP netconf control is capture-blind" VOID 2 0 1500 0 0 2 "${GOOD[@]}"
    check "duplicate control reply fails" FAIL 1 0 1500 1501 0 2 "${GOOD[@]}"
    check "bad checksum fails" FAIL 1 0 1500 1500 1 2 "${GOOD[@]}"
    check "malformed input is harness VOID" VOID 2 0 1500 1500 0 2 1000 x 0 1000 0 0
    echo "  wire-hostinbound-deny selftest: $pass passed, $fail failed"
    [[ "$fail" -eq 0 && "$pass" -gt 0 ]] || exit 1
    exit 0
fi

if [[ "$MODE" == fixture ]]; then
    [[ -n "$FIXTURE" && -f "$FIXTURE" ]] || { echo "usage: $0 --fixture <transcript.tsv>" >&2; exit 2; }
    RF=""; CO=""; CB=""; CK=""; CELLS=(); malformed=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        case "$line" in
        reply_frames=*) RF="${line#reply_frames=}" ;;
        ctrl_offered=*) CO="${line#ctrl_offered=}" ;;
        ctrl_observed=*) CB="${line#ctrl_observed=}" ;;
        cksum_bad=*) CK="${line#cksum_bad=}" ;;
        cell\ *)
            read -r off comp ref extra <<<"${line#cell }"
            [[ -n "${extra:-}" ]] && malformed=1
            CELLS+=("${off:-}" "${comp:-}" "${ref:-}")
            ;;
        *) malformed=1 ;;
        esac
    done <"$FIXTURE"
    if ((malformed)) || [[ -z "$RF" || -z "$CO" || -z "$CB" || -z "$CK" ]]; then
        wire_hostinbound_verdict x x x x "${#CELLS[@]}" "${CELLS[@]}"
        exit $?
    fi
    wire_hostinbound_verdict "$RF" "$CO" "$CB" "$CK" "$(( ${#CELLS[@]} / 3 ))" "${CELLS[@]}"
    exit $?
fi

if [[ -n "${WIRE_BROKEN_FIXTURE:-}" ]]; then
    export XPF_WIRE_BROKEN_FIXTURE="$WIRE_BROKEN_FIXTURE"
fi
BROKEN_FIXTURE="${XPF_WIRE_BROKEN_FIXTURE:-}"
source "${SCRIPT_DIR}/cluster-cell.sh"
xpf_enter_destructive_cluster_cell "wire-hostinbound-deny $*" "$0" "$@"
source "${SCRIPT_DIR}/cluster-env.sh"

INCUS_REMOTE="${INCUS_REMOTE:-loss}"
NODE="${NODE:-${FW0:-xpf-userspace-fw0}}"
FW_A="${FW0:-${INCUS_REMOTE}:xpf-userspace-fw0}"
FW_B="${FW1:-${INCUS_REMOTE}:xpf-userspace-fw1}"
UNTRUST_HOST="${UNTRUST_HOST:-xpf-mouse-target}"
UNTRUST_HOST="${UNTRUST_HOST#*:}"
DUT_ADDR="${DUT_ADDR:-172.16.80.8}"
PROBE_PORT_A="${PROBE_PORT_A:-22}"
PROBE_PORT_B="${PROBE_PORT_B:-443}"
CONTROL_PORT="${CONTROL_PORT:-830}"
BURST="${BURST:-1000}"
CONTROL_BURST="${CONTROL_BURST:-1500}"
STEP_TIMEOUT="${STEP_TIMEOUT:-120}"
TCP_TIMEOUT="${TCP_TIMEOUT:-0.2}"
LISTENER_SRC="${SCRIPT_DIR}/wire_tcp_accept.py"
REMOTE_LISTENER="/tmp/xpf-wire_tcp_accept.py"
REMOTE_PROBE="/tmp/xpf-wire_probe_burst.py"
PROBER_SRC="${SCRIPT_DIR}/wire_probe_burst.py"
SG="sg incus-admin -c"
UNTRUST_REF="${INCUS_REMOTE}:${UNTRUST_HOST}"
CAP_PID=""; CAPLOG=""; RESTORE_NEEDED=0; RESTORE_OK=1

run_cli() { $SG "incus exec ${NODE} -- bash -lc 'cli'"; }
cli_show() { printf '%s\nexit\n' "$1" | run_cli; }
fail_void() {
    WIRE_GATE_FINAL_OUT="WIRE_GATE wire_hostinbound_deny VOID reason=$1 cells_measured=0 syn_offered=0 handshake_completed=0 refused_total=0 exposed_total=0 reply_frames=0 ctrl_offered=0 ctrl_observed=0 cksum_bad=0"
    WIRE_GATE_FINAL_RC=3
    exit 3
}

restore_config() {
    ((RESTORE_NEEDED)) || return 0
    local log=/tmp/xpf-wire-hostinbound-restore.log
    if ! printf 'configure\ndelete security zones security-zone wan host-inbound-traffic system-services netconf\ndelete security zones security-zone wan host-inbound-traffic system-services ssh\ndelete security zones security-zone wan host-inbound-traffic system-services https\ncommit\nexit\n' | $SG "incus exec ${NODE} -- bash -lc 'cli'" >"$log" 2>&1; then RESTORE_OK=0; fi
    grep -qE 'commit (complete|succeeded)' "$log" 2>/dev/null || RESTORE_OK=0
    local z; z="$(cli_show 'show configuration security zones | display set' 2>&1)"
    [[ "$z" != *"security-zone wan host-inbound-traffic system-services netconf"* ]] || RESTORE_OK=0
    [[ "$z" != *"security-zone wan host-inbound-traffic system-services ssh"* ]] || RESTORE_OK=0
    [[ "$z" != *"security-zone wan host-inbound-traffic system-services https"* ]] || RESTORE_OK=0
    RESTORE_NEEDED=0
}
cleanup() {
    [[ -n "$CAP_PID" ]] && kill "$CAP_PID" >/dev/null 2>&1 || true
    $SG "incus exec ${UNTRUST_REF} -- pkill -f '[w]ire_probe_burst'" >/dev/null 2>&1 || true
    for fw in "$FW_A" "$FW_B"; do
        $SG "incus exec ${fw} -- pkill -f '[w]ire_tcp_accept.py'" >/dev/null 2>&1 || true
    done
    restore_config
    [[ -n "$CAPLOG" ]] && rm -f "$CAPLOG"
}
WIRE_GATE_CLEANUP_FN=cleanup
WIRE_GATE_RESTORE_OK_REF=RESTORE_OK
WIRE_GATE_RESTORE_VOID='WIRE_GATE wire_hostinbound_deny VOID reason=harness-void cells_measured=0 syn_offered=0 handshake_completed=0 refused_total=0 exposed_total=0 reply_frames=0 ctrl_offered=0 ctrl_observed=0 cksum_bad=0'
wire_gate_signal_abort() { trap '' INT TERM; fail_void harness-void; }
trap wire_gate_finalize EXIT
trap wire_gate_signal_abort INT TERM

BASE_ZONES="$(cli_show 'show configuration security zones | display set' 2>&1)"
[[ "$BASE_ZONES" == *"security-zone wan host-inbound-traffic system-services ping"* ]] || fail_void env-void
[[ "$BASE_ZONES" != *"security-zone wan host-inbound-traffic system-services netconf"* ]] || fail_void env-void
[[ "$BASE_ZONES" != *"security-zone wan host-inbound-traffic system-services ssh"* ]] || fail_void env-void
[[ "$BASE_ZONES" != *"security-zone wan host-inbound-traffic system-services https"* ]] || fail_void env-void
[[ -f "$LISTENER_SRC" && -f "$PROBER_SRC" ]] || fail_void harness-void
$SG "incus exec ${UNTRUST_REF} -- sh -c 'command -v tcpdump && command -v python3'" >/dev/null 2>&1 || fail_void no-prober
RESTORE_NEEDED=1
printf 'configure\nset security zones security-zone wan host-inbound-traffic system-services netconf\ncommit\nexit\n' | $SG "incus exec ${NODE} -- bash -lc 'cli'" >/tmp/xpf-wire-hostinbound-control.log 2>&1 || fail_void harness-void
grep -qE 'commit (complete|succeeded)' /tmp/xpf-wire-hostinbound-control.log || fail_void harness-void
for fw in "$FW_A" "$FW_B"; do
    $SG "incus exec ${fw} -- rm -f ${REMOTE_LISTENER}" >/dev/null 2>&1 || fail_void harness-void
    $SG "incus file push --mode 0755 ${LISTENER_SRC} ${fw}${REMOTE_LISTENER}" >/dev/null 2>&1 || fail_void harness-void
done
$SG "incus exec ${UNTRUST_REF} -- rm -f ${REMOTE_PROBE}" >/dev/null 2>&1 || fail_void harness-void
$SG "incus file push --mode 0755 ${PROBER_SRC} ${UNTRUST_REF}${REMOTE_PROBE}" >/dev/null 2>&1 || fail_void harness-void
for fw in "$FW_A" "$FW_B"; do
    $SG "incus exec ${fw} -- sh -c 'for p in ${PROBE_PORT_A} ${PROBE_PORT_B} ${CONTROL_PORT}; do nohup python3 -u ${REMOTE_LISTENER} --port \$p --duration ${STEP_TIMEOUT} >/tmp/xpf-hi-\$p.log 2>&1 & done'" >/dev/null 2>&1 || fail_void harness-void
done
sleep 2
for fw in "$FW_A" "$FW_B"; do
    for p in "$PROBE_PORT_A" "$PROBE_PORT_B" "$CONTROL_PORT"; do
        $SG "incus exec ${fw} -- sh -c 'grep -q \"LISTENING ${p}\" /tmp/xpf-hi-${p}.log || (ss -ltnH | grep -Eq \"[:.]${p} \")'" >/dev/null 2>&1 || fail_void harness-void
    done
done
if [[ -n "$BROKEN_FIXTURE" ]]; then
    printf 'configure\nset security zones security-zone wan host-inbound-traffic system-services ssh\nset security zones security-zone wan host-inbound-traffic system-services https\ncommit\nexit\n' | $SG "incus exec ${NODE} -- bash -lc 'cli'" >/tmp/xpf-wire-hostinbound-commit.log 2>&1 || fail_void harness-void
    grep -qE 'commit (complete|succeeded)' /tmp/xpf-wire-hostinbound-commit.log || fail_void harness-void
fi

CAPLOG="$(mktemp "${TMPDIR:-/var/tmp}/xpf-wire-hostinbound-cap.XXXXXX")"
$SG "incus exec ${UNTRUST_REF} -- timeout ${STEP_TIMEOUT} tcpdump -i eth0 -nn -tt -vv -s 0 host ${DUT_ADDR} and '(' tcp port ${PROBE_PORT_A} or tcp port ${PROBE_PORT_B} or tcp port ${CONTROL_PORT} ')'" >"$CAPLOG" 2>&1 &
CAP_PID=$!
sleep 2
SENT="$($SG "incus exec ${UNTRUST_REF} -- timeout ${STEP_TIMEOUT} python3 ${REMOTE_PROBE} --dst ${DUT_ADDR} --tcp-timeout ${TCP_TIMEOUT} --tcp-leg ${PROBE_PORT_A}:${BURST} --tcp-leg ${PROBE_PORT_B}:${BURST} --tcp-leg ${CONTROL_PORT}:${CONTROL_BURST}" 2>&1 || true)"
sleep 2
$SG "incus exec ${UNTRUST_REF} -- pkill -f '[t]cpdump.*${PROBE_PORT_A}'" >/dev/null 2>&1 || true
kill "$CAP_PID" >/dev/null 2>&1 || true
wait "$CAP_PID" >/dev/null 2>&1 || true
CAP_PID=""
legpart="${SENT##*$'\n'}"; legpart="${legpart#SENT tcplegs=}"
extract_leg() {
    local p="$1" item; IFS=',' read -ra legs <<<"$legpart"
    for item in "${legs[@]}"; do [[ "${item%%=*}" == "$p" ]] && { printf '%s' "${item#*=}"; return; }; done
    printf '0'
}
OFFER_A="$(extract_leg "$PROBE_PORT_A")"; OFFER_B="$(extract_leg "$PROBE_PORT_B")"; CONTROL_OFFERED="$(extract_leg "$CONTROL_PORT")"
for v in OFFER_A OFFER_B CONTROL_OFFERED; do [[ "${!v}" =~ ^[0-9]+$ ]] || printf -v "$v" '0'; done
count_replies() { grep -cE "\\.${1} > .*Flags \\[$2" "$CAPLOG" 2>/dev/null || true; }
COMP_A="$(count_replies "$PROBE_PORT_A" 'S\.')"; REF_A="$(count_replies "$PROBE_PORT_A" 'R')"
COMP_B="$(count_replies "$PROBE_PORT_B" 'S\.')"; REF_B="$(count_replies "$PROBE_PORT_B" 'R')"
CTRL_COMP="$(count_replies "$CONTROL_PORT" 'S\.')"; CTRL_REF="$(count_replies "$CONTROL_PORT" 'R')"
for v in COMP_A REF_A COMP_B REF_B CTRL_COMP CTRL_REF; do [[ "${!v}" =~ ^[0-9]+$ ]] || printf -v "$v" '0'; done
REPLIES=$((COMP_A + REF_A + COMP_B + REF_B))
CONTROL_OBS=$((CTRL_COMP + CTRL_REF))
CK="$(grep -ciE 'bad (tcp|ip) (cksum|checksum)' "$CAPLOG" 2>/dev/null || true)"; [[ "$CK" =~ ^[0-9]+$ ]] || CK=0
WIRE_GATE_FINAL_OUT="$(wire_hostinbound_verdict "$REPLIES" "$CONTROL_OFFERED" "$CONTROL_OBS" "$CK" 2 "$OFFER_A" "$COMP_A" "$REF_A" "$OFFER_B" "$COMP_B" "$REF_B")"
WIRE_GATE_FINAL_RC=$?
exit "$WIRE_GATE_FINAL_RC"
