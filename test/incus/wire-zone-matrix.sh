#!/usr/bin/env bash
# #10028 — wire_zone_matrix: the complete three-zone default-policy matrix.
#
# The live leg is intentionally exacting. It maps trust=lan, untrust=wan and
# dmz=the managed VLAN-50 prober on the loss userspace cluster, then measures
# all six ordered pairs under default-deny and all six again under
# default-permit. Every cell has a same-pair UDP near miss (destination port
# 55000) and a probe (55001); probes alternate 64-byte and 1400-byte payloads.
# Peer-side tcpdump is the oracle. A one/two-zone shortcut is refused.
#
# Usage:
#   ./test/incus/wire-zone-matrix.sh
#   ./test/incus/wire-zone-matrix.sh --fixture transcript.tsv
#   ./test/incus/wire-zone-matrix.sh --selftest
#
# Fixture format is one `cell <key> <8 numeric fields>` line per cell, where
# the fields are p64-offered p64-observed p1400-offered p1400-observed
# c64-offered c64-observed c1400-offered c1400-observed, plus cksum_bad=N.
#
# Exit: 0 PASS, 1 FAIL, 2 VOID, 3 refused precondition.
set -uo pipefail

MODE=live
FIXTURE=""
while (($#)); do
    case "$1" in
    --selftest) MODE=selftest ;;
    --fixture) MODE=fixture; shift; FIXTURE="${1:-}" ;;
    -h|--help) sed -n '1,35p' "$0"; exit 0 ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *) echo "unexpected argument: $1" >&2; exit 2 ;;
    esac
    shift
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/incus/wire-gate-lib.sh
source "${SCRIPT_DIR}/wire-gate-lib.sh"

matrix_keys=(
    deny:trust-'>'untrust deny:untrust-'>'trust deny:trust-'>'dmz
    deny:dmz-'>'trust deny:untrust-'>'dmz deny:dmz-'>'untrust
    permit:trust-'>'untrust permit:untrust-'>'trust permit:trust-'>'dmz
    permit:dmz-'>'trust permit:untrust-'>'dmz permit:dmz-'>'untrust
)

if [[ "$MODE" == selftest ]]; then
    pass=0
    fail=0
    matrix_make_good() {
        MATRIX=()
        local key
        for key in "${matrix_keys[@]}"; do
            if [[ "$key" == deny:* ]]; then
                MATRIX+=("$key" 1000 0 1000 0 1000 1000 1000 1000)
            else
                MATRIX+=("$key" 10000 10000 10000 10000 10000 10000 10000 10000)
            fi
        done
    }
    check() { # check label verdict rc args...
        local label="$1" want_v="$2" want_rc="$3"; shift 3
        local out rc v
        out=$(wire_matrix_verdict "$@")
        rc=$?
        v=$(awk '{print $3}' <<<"$out")
        if [[ "$v" == "$want_v" && "$rc" == "$want_rc" && "$out" == WIRE_GATE\ wire_zone_matrix\ * ]]; then
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
    matrix_make_good
    check "complete 12-cell matrix passes" PASS 0 0 12 "${MATRIX[@]}"
    BAD=("${MATRIX[@]}"); BAD[2]=1
    check "deny leak fails" FAIL 1 0 12 "${BAD[@]}"
    BAD=("${MATRIX[@]}"); BAD[56]=9999
    check "permit loss fails after proven control" FAIL 1 0 12 "${BAD[@]}"
    BAD=("${MATRIX[@]}"); BAD[56]=10001
    check "duplicate capture frame fails" FAIL 1 0 12 "${BAD[@]}"
    BAD=("${MATRIX[@]}"); BAD[55]=9999
    check "permit 64-byte under-sample is VOID" VOID 2 0 12 "${BAD[@]}"
    BAD=("${MATRIX[@]}"); BAD[0]=deny:trust-'>'trust
    check "wrong pair identity is VOID" VOID 2 0 12 "${BAD[@]}"
    check "one-cell shortcut is VOID" VOID 2 0 1 deny:trust-'>'untrust 1000 0 1000 0 1000 1000 1000 1000
    check "checksum corruption fails" FAIL 1 3 12 "${MATRIX[@]}"
    echo "  wire-zone-matrix selftest: $pass passed, $fail failed"
    [[ "$fail" -eq 0 && "$pass" -gt 0 ]] || exit 1
    exit 0
fi

if [[ "$MODE" == fixture ]]; then
    [[ -n "$FIXTURE" && -f "$FIXTURE" ]] || { echo "usage: $0 --fixture <transcript.tsv>" >&2; exit 2; }
    MATRIX=()
    CK=""
    malformed=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        case "$line" in
        cksum_bad=*) CK="${line#cksum_bad=}" ;;
        cell\ *)
            read -r key p64o p64b p1400o p1400b c64o c64b c1400o c1400b extra <<<"${line#cell }"
            [[ -n "${extra:-}" ]] && malformed=1
            MATRIX+=("${key:-}" "${p64o:-}" "${p64b:-}" "${p1400o:-}" "${p1400b:-}" "${c64o:-}" "${c64b:-}" "${c1400o:-}" "${c1400b:-}")
            ;;
        *) malformed=1 ;;
        esac
    done <"$FIXTURE"
    if ((malformed)) || [[ -z "$CK" ]]; then
        wire_matrix_verdict x "${#MATRIX[@]}" "${MATRIX[@]}"
        exit $?
    fi
    # MATRIX has nine arguments per cell; the core enforces 12-cell identity.
    wire_matrix_verdict "$CK" "$(( ${#MATRIX[@]} / 9 ))" "${MATRIX[@]}"
    exit $?
fi

if [[ -n "${WIRE_BROKEN_FIXTURE:-}" ]]; then
    export XPF_WIRE_BROKEN_FIXTURE="$WIRE_BROKEN_FIXTURE"
fi
BROKEN_FIXTURE="${XPF_WIRE_BROKEN_FIXTURE:-}"
# ── live gate ───────────────────────────────────────────────────────
source "${SCRIPT_DIR}/cluster-cell.sh"
xpf_enter_destructive_cluster_cell "wire-zone-matrix $*" "$0" "$@"
source "${SCRIPT_DIR}/cluster-env.sh"

INCUS_REMOTE="${INCUS_REMOTE:-loss}"
NODE="${NODE:-${FW0:-xpf-userspace-fw0}}"
TRUST_HOST="${TRUST_HOST:-${CLUSTER_LAN_HOST_NAME:-cluster-userspace-host}}"
UNTRUST_HOST="${UNTRUST_HOST:-xpf-mouse-target}"
DMZ_HOST="${DMZ_HOST:-xpf-zone-matrix-dmz}"
TRUST_HOST="${TRUST_HOST#*:}"
UNTRUST_HOST="${UNTRUST_HOST#*:}"
DMZ_HOST="${DMZ_HOST#*:}"
TRUST_ADDR="${TRUST_ADDR:-${LAN_HOST_IP:-10.0.61.102}}"
UNTRUST_ADDR="${UNTRUST_ADDR:-${MOUSE_TARGET_V4:-172.16.80.201}}"
DMZ_ADDR="${DMZ_ADDR:-172.16.50.201}"
PROBE_PORT="${PROBE_PORT:-55001}"
CONTROL_PORT="${CONTROL_PORT:-55000}"
DENY_BURST="${DENY_BURST:-2200}"       # 1100 at each payload size
LOSS_BURST="${LOSS_BURST:-20000}"      # 10000 at each payload size
RATE="${RATE:-2000}"
STEP_TIMEOUT="${STEP_TIMEOUT:-300}"
APP_NAME="wire-10028-control"
CONTROL_SET="wire-10028-control-set"
POLICY_PREFIX="wire-10028-control"
BROKEN_POLICY="wire-10028-broken"
PROBER_SRC="${SCRIPT_DIR}/wire_probe_burst.py"
REMOTE_PROBE="/tmp/xpf-wire_probe_burst.py"
SG="sg incus-admin -c"

PAIR_NAMES=(trust-untrust untrust-trust trust-dmz dmz-trust untrust-dmz dmz-untrust)
PAIR_FROM=(lan wan lan dmz wan dmz)
PAIR_TO=(wan lan dmz lan dmz wan)
HOSTS=("$TRUST_HOST" "$UNTRUST_HOST" "$DMZ_HOST")
ADDRS=("$TRUST_ADDR" "$UNTRUST_ADDR" "$DMZ_ADDR")

# The live gate always restores its owned route/config changes before the one
# final WIRE_GATE line.  The DMZ endpoint is a persistent managed prober, not
# a hidden external host; setup is idempotent and leaves it available for the
# next gate.
CAP_PID=""
CAPLOG=""
RESTORE_NEEDED=0
RESTORE_OK=1
ROUTES_MUTATED=0
declare -A ROUTE_SNAPSHOT
save_route() {
    local host="$1" prefix="$2" key="$1|$2" out
    out="$($SG "incus exec ${INCUS_REMOTE}:${host} -- ip -4 route show exact ${prefix}" 2>/dev/null)" || {
        RESTORE_OK=0
        return 1
    }
    ROUTE_SNAPSHOT["$key"]="$out"
}
restore_routes() {
    ((ROUTES_MUTATED)) || return 0
    local host prefix key old now
    for host in "$UNTRUST_HOST" "$DMZ_HOST"; do
        for prefix in 10.0.61.0/24 172.16.50.0/24 172.16.80.0/24; do
            [[ "$host" == "$UNTRUST_HOST" && "$prefix" == "172.16.80.0/24" ]] && continue
            [[ "$host" == "$DMZ_HOST" && "$prefix" == "172.16.50.0/24" ]] && continue
            key="$host|$prefix"; old="${ROUTE_SNAPSHOT[$key]:-}"
            if ! $SG "incus exec ${INCUS_REMOTE}:${host} -- ip route del ${prefix}" >/dev/null 2>&1; then
                RESTORE_OK=0
            fi
            if [[ -n "$old" ]] && ! $SG "incus exec ${INCUS_REMOTE}:${host} -- ip route replace ${old}" >/dev/null 2>&1; then
                RESTORE_OK=0
            fi
            now="$($SG "incus exec ${INCUS_REMOTE}:${host} -- ip -4 route show exact ${prefix}" 2>/dev/null)" || {
                RESTORE_OK=0
                continue
            }
            [[ "$now" == "$old" ]] || RESTORE_OK=0
        done
    done
    ROUTES_MUTATED=0
}
restore_config() {
    ((RESTORE_NEEDED)) || return 0
    local restore_log=/tmp/xpf-wire-zone-matrix-restore.log
    local policy_log="${restore_log}.policy" context_log="${restore_log}.context" zone_log="${restore_log}.zone"
    : >"$restore_log"; : >"$policy_log"; : >"$context_log"; : >"$zone_log"
    local cmds='configure\n' context_cmds='configure\n' slug context_needed=0 i
    for ((i = 0; i < ${#PAIR_NAMES[@]}; i++)); do
        slug="${PAIR_NAMES[$i]}"
        cmds+="delete security policies from-zone ${PAIR_FROM[$i]} to-zone ${PAIR_TO[$i]} policy ${POLICY_PREFIX}-${slug}\n"
        # The initial snapshot proves this whole context was absent.  Only
        # then remove the empty parent left by the owned policy deletion.
        if [[ "$POLICY_SNAP" != *"from-zone ${PAIR_FROM[$i]} to-zone ${PAIR_TO[$i]}"* ]]; then
            context_cmds+="delete security policies from-zone ${PAIR_FROM[$i]} to-zone ${PAIR_TO[$i]}\n"
            context_needed=1
        fi
    done
    cmds+="delete security policies from-zone lan to-zone wan policy allow-all match application\n"
    if [[ -n "$BROKEN_FIXTURE" ]]; then
        cmds+="delete security policies from-zone wan to-zone lan policy ${BROKEN_POLICY}\n"
    fi
    while IFS= read -r line; do
        case "$line" in
        set\ security\ policies\ from-zone\ lan\ to-zone\ wan\ policy\ allow-all\ match\ application\ *)
            cmds+="${line}"$'\n' ;;
        esac
    done <<<"$POLICY_SNAP"
    cmds+="delete applications application-set ${CONTROL_SET}\n"
    cmds+="delete applications application ${APP_NAME}\n"
    cmds+="commit\nexit\n"
    if ! printf '%b' "$cmds" | $SG "incus exec ${NODE} -- bash -lc 'cli'" >"$policy_log" 2>&1; then
        RESTORE_OK=0
    fi
    cat "$policy_log" >>"$restore_log"
    grep -qE 'commit (complete|succeeded)' "$policy_log" 2>/dev/null || RESTORE_OK=0
    if ((context_needed)); then
        context_cmds+="commit\nexit\n"
        if ! printf '%b' "$context_cmds" | $SG "incus exec ${NODE} -- bash -lc 'cli'" >"$context_log" 2>&1; then
            RESTORE_OK=0
        fi
        cat "$context_log" >>"$restore_log"
        grep -qE 'commit (complete|succeeded)' "$context_log" 2>/dev/null || RESTORE_OK=0
    fi
    if ! printf '%b' 'configure\ndelete security zones security-zone dmz\ndelete security zones security-zone wan interfaces reth0.50\ndelete security zones security-zone wan interfaces reth0.80\nset security zones security-zone wan interfaces reth0.50\nset security zones security-zone wan interfaces reth0.80\nset security policies default-policy deny-all\ncommit\nexit\n' |
        $SG "incus exec ${NODE} -- bash -lc 'cli'" >"$zone_log" 2>&1; then
        RESTORE_OK=0
    fi
    cat "$zone_log" >>"$restore_log"
    grep -qE 'commit (complete|succeeded)' "$zone_log" 2>/dev/null || RESTORE_OK=0
    local restored_policy restored_zone restored_apps
    restored_policy="$(snapshot 'show configuration security policies | display set')"
    restored_zone="$(snapshot 'show configuration security zones | display set')"
    restored_apps="$(snapshot 'show configuration applications | display set')"
    [[ "$restored_policy" == "$POLICY_SNAP" ]] || RESTORE_OK=0
    [[ "$restored_zone" == "$ZONE_SNAP" ]] || RESTORE_OK=0
    [[ "$restored_apps" == "$APP_SNAP" ]] || RESTORE_OK=0
    RESTORE_NEEDED=0
}
cleanup() {
    [[ -n "$CAP_PID" ]] && kill "$CAP_PID" >/dev/null 2>&1 || true
    $SG "incus exec ${INCUS_REMOTE}:${TRUST_HOST} -- pkill -f '[w]ire_probe_burst'" >/dev/null 2>&1 || true
    $SG "incus exec ${INCUS_REMOTE}:${UNTRUST_HOST} -- pkill -f '[w]ire_probe_burst'" >/dev/null 2>&1 || true
    $SG "incus exec ${INCUS_REMOTE}:${DMZ_HOST} -- pkill -f '[w]ire_probe_burst'" >/dev/null 2>&1 || true
    restore_config
    restore_routes
    [[ -n "$CAPLOG" ]] && rm -f "$CAPLOG"
}
WIRE_GATE_CLEANUP_FN=cleanup
WIRE_GATE_RESTORE_OK_REF=RESTORE_OK
WIRE_GATE_RESTORE_VOID='WIRE_GATE wire_zone_matrix VOID reason=harness-void cells_measured=0 cells_failed=0 deny_cells=0 permit_cells=0 permit64_offered=0 permit64_observed=0 permit1400_offered=0 permit1400_observed=0 deny_leaked=0 permit_missing=0 control_missing=0 duplicate_frames=0 cksum_bad=0'
fail_void() {
    WIRE_GATE_FINAL_OUT="WIRE_GATE wire_zone_matrix VOID reason=$1 cells_measured=0 cells_failed=0 deny_cells=0 permit_cells=0 permit64_offered=0 permit64_observed=0 permit1400_offered=0 permit1400_observed=0 deny_leaked=0 permit_missing=0 control_missing=0 duplicate_frames=0 cksum_bad=0"
    WIRE_GATE_FINAL_RC=3
    exit 3
}
run_cli() { $SG "incus exec ${NODE} -- bash -lc 'cli'"; }
cli_show() { printf '%s\nexit\n' "$1" | run_cli; }
wire_gate_signal_abort() { trap '' INT TERM; fail_void harness-void; }
trap wire_gate_finalize EXIT
trap wire_gate_signal_abort INT TERM
snapshot() { cli_show "$1" 2>&1 | sed -n '/^set /p'; }

POLICY_SNAP="$(snapshot 'show configuration security policies | display set')"
ZONE_SNAP="$(snapshot 'show configuration security zones | display set')"
APP_SNAP="$(snapshot 'show configuration applications | display set')"
[[ "$POLICY_SNAP" == *"set security policies default-policy deny-all"* ]] || fail_void env-void
[[ "$POLICY_SNAP" == *"from-zone lan to-zone wan policy allow-all match application any"* ]] || fail_void env-void
[[ "$ZONE_SNAP" == *"security-zone wan interfaces reth0.50"* && "$ZONE_SNAP" == *"security-zone wan interfaces reth0.80"* ]] || fail_void env-void
[[ "$ZONE_SNAP" != *"security-zone dmz"* ]] || fail_void env-void
if grep -q "$POLICY_PREFIX\|$APP_NAME\|$BROKEN_POLICY" <<<"$POLICY_SNAP$APP_SNAP"; then fail_void env-void; fi
[[ -f "$PROBER_SRC" ]] || fail_void harness-void

# Provision and identify the actual third-zone endpoint, then put only the
# destination-network routes needed for reverse directions through the DUT.
MOUSE_TARGET_NAME="$DMZ_HOST" MOUSE_TARGET_V4="$DMZ_ADDR" \
MOUSE_TARGET_V6="2001:559:8585:50::201" MOUSE_TARGET_PF="mlx0" MOUSE_TARGET_VLAN="50" \
$SG "bash ${SCRIPT_DIR}/mouse-target-setup.sh up" >/dev/null 2>&1 || fail_void no-prober
for host in "${HOSTS[@]}"; do
    if ! $SG "incus exec ${INCUS_REMOTE}:${host} -- sh -c 'command -v tcpdump'" >/dev/null 2>&1; then
        if [[ "$host" == "$DMZ_HOST" || "$host" == "$UNTRUST_HOST" ]]; then
            $SG "incus exec ${INCUS_REMOTE}:${host} -- sh -c 'apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq tcpdump >/dev/null 2>&1'" >/dev/null 2>&1 || fail_void no-prober
        else
            fail_void no-prober
        fi
    fi
done
for host in "${HOSTS[@]}"; do
    $SG "incus exec ${INCUS_REMOTE}:${host} -- sh -c 'command -v tcpdump'" >/dev/null 2>&1 || fail_void no-prober
done
for host in "${HOSTS[@]}"; do
    $SG "incus exec ${INCUS_REMOTE}:${host} -- rm -f ${REMOTE_PROBE}" >/dev/null 2>&1 || fail_void harness-void
done
if ! $SG "incus file push --mode 0755 ${PROBER_SRC} ${INCUS_REMOTE}:${TRUST_HOST}${REMOTE_PROBE}" >/dev/null 2>&1; then fail_void harness-void; fi
if ! $SG "incus file push --mode 0755 ${PROBER_SRC} ${INCUS_REMOTE}:${UNTRUST_HOST}${REMOTE_PROBE}" >/dev/null 2>&1; then fail_void harness-void; fi
if ! $SG "incus file push --mode 0755 ${PROBER_SRC} ${INCUS_REMOTE}:${DMZ_HOST}${REMOTE_PROBE}" >/dev/null 2>&1; then fail_void harness-void; fi
route_is_clear() {
    local host="$1" prefix="$2" out
    out="$($SG "incus exec ${INCUS_REMOTE}:${host} -- ip -4 route show ${prefix}" 2>/dev/null)" || return 1
    [[ -z "$out" ]]
}
save_route "$UNTRUST_HOST" 10.0.61.0/24 || fail_void harness-void
save_route "$UNTRUST_HOST" 172.16.50.0/24 || fail_void harness-void
save_route "$DMZ_HOST" 10.0.61.0/24 || fail_void harness-void
save_route "$DMZ_HOST" 172.16.80.0/24 || fail_void harness-void
route_is_clear "$UNTRUST_HOST" 10.0.61.0/24 || fail_void env-void
route_is_clear "$UNTRUST_HOST" 172.16.50.0/24 || fail_void env-void
route_is_clear "$DMZ_HOST" 10.0.61.0/24 || fail_void env-void
route_is_clear "$DMZ_HOST" 172.16.80.0/24 || fail_void env-void
ROUTES_MUTATED=1
$SG "incus exec ${INCUS_REMOTE}:${UNTRUST_HOST} -- ip route replace 10.0.61.0/24 via 172.16.80.8" >/dev/null 2>&1 || fail_void no-prober
$SG "incus exec ${INCUS_REMOTE}:${UNTRUST_HOST} -- ip route replace 172.16.50.0/24 via 172.16.80.8" >/dev/null 2>&1 || fail_void no-prober
$SG "incus exec ${INCUS_REMOTE}:${DMZ_HOST} -- ip route replace 10.0.61.0/24 via 172.16.50.8" >/dev/null 2>&1 || fail_void no-prober
$SG "incus exec ${INCUS_REMOTE}:${DMZ_HOST} -- ip route replace 172.16.80.0/24 via 172.16.50.8" >/dev/null 2>&1 || fail_void no-prober

# Create the DMZ zone and owned control application/policies. The six
# directions are represented explicitly in the config, while the default
# policy arm is what decides the probe leg.
apply_mode() {
    local mode="$1"; local i from to slug
    local cmds="configure\n"
    if [[ "$mode" == deny ]]; then
        cmds+="set applications application ${APP_NAME} protocol udp destination-port ${CONTROL_PORT}\n"
        cmds+="set applications application-set ${CONTROL_SET} application ${APP_NAME}\n"
        cmds+="delete security zones security-zone wan interfaces reth0.50\n"
        cmds+="set security zones security-zone dmz interfaces reth0.50\n"
        cmds+="delete security policies from-zone lan to-zone wan policy allow-all match application\n"
        cmds+="set security policies from-zone lan to-zone wan policy allow-all match application ${CONTROL_SET}\n"
        for ((i = 0; i < 6; i++)); do
            from="${PAIR_FROM[$i]}"; to="${PAIR_TO[$i]}"; slug="${PAIR_NAMES[$i]}"
            cmds+="set security policies from-zone ${from} to-zone ${to} policy ${POLICY_PREFIX}-${slug} match source-address any\n"
            cmds+="set security policies from-zone ${from} to-zone ${to} policy ${POLICY_PREFIX}-${slug} match destination-address any\n"
            cmds+="set security policies from-zone ${from} to-zone ${to} policy ${POLICY_PREFIX}-${slug} match application ${CONTROL_SET}\n"
            cmds+="set security policies from-zone ${from} to-zone ${to} policy ${POLICY_PREFIX}-${slug} then permit\n"
        done
        if [[ -n "$BROKEN_FIXTURE" ]]; then
            cmds+="set security policies from-zone wan to-zone lan policy ${BROKEN_POLICY} match source-address any\n"
            cmds+="set security policies from-zone wan to-zone lan policy ${BROKEN_POLICY} match destination-address any\n"
            cmds+="set security policies from-zone wan to-zone lan policy ${BROKEN_POLICY} match application any\n"
            cmds+="set security policies from-zone wan to-zone lan policy ${BROKEN_POLICY} then permit\n"
        fi
        cmds+="set security policies default-policy deny-all\n"
    else
        # The fixture and zone move already landed in the deny arm.  This arm
        # changes only the default-policy, so both defaults measure the same
        # six ordered paths with no repeated/rejected delete operations.
        cmds+="set security policies default-policy permit-all\n"
    fi
    cmds+="commit\nexit\n"
    printf '%b' "$cmds" | run_cli >/tmp/xpf-wire-zone-matrix-commit.log 2>&1
    grep -qE 'commit (complete|succeeded)' /tmp/xpf-wire-zone-matrix-commit.log || return 1
    ! grep -qE '(^|[[:space:]])(error:|Error:)' /tmp/xpf-wire-zone-matrix-commit.log
}

# measure_cell <source-index> <destination-index> <mode> <count>
measure_cell() {
    local si="$1" di="$2" mode="$3" count="$4"
    local src="${HOSTS[$si]}" dst="${HOSTS[$di]}" dst_addr="${ADDRS[$di]}"
    local sent legpart totalp totalc
    CAPLOG="$(mktemp "${TMPDIR:-/var/tmp}/xpf-wire-zone-cap.XXXXXX")"
    $SG "incus exec ${INCUS_REMOTE}:${dst} -- timeout ${STEP_TIMEOUT} tcpdump -i eth0 -nn -tt -vv -s 0 udp and dst host ${dst_addr} and '(' dst port ${PROBE_PORT} or dst port ${CONTROL_PORT} ')'" >"$CAPLOG" 2>&1 &
    CAP_PID=$!
    sleep 2
    sent="$($SG "incus exec ${INCUS_REMOTE}:${src} -- timeout ${STEP_TIMEOUT} python3 ${REMOTE_PROBE} --dst ${dst_addr} --leg ${PROBE_PORT}:${count} --leg ${CONTROL_PORT}:${count} --sizes 64,1400 --rate ${RATE}" 2>&1 || true)"
    sleep 2
    $SG "incus exec ${INCUS_REMOTE}:${dst} -- pkill -f '[t]cpdump.*${PROBE_PORT}'" >/dev/null 2>&1 || true
    kill "$CAP_PID" >/dev/null 2>&1 || true
    wait "$CAP_PID" >/dev/null 2>&1 || true
    CAP_PID=""
    legpart="${sent##*$'\n'}"
    legpart="${legpart#SENT legs=}"
    totalp=0; totalc=0
    local item port value
    IFS=',' read -ra _legs <<<"$legpart"
    for item in "${_legs[@]}"; do
        port="${item%%=*}"; value="${item#*=}"
        [[ "$value" =~ ^[0-9]+$ ]] || value=0
        [[ "$port" == "$PROBE_PORT" ]] && totalp="$value"
        [[ "$port" == "$CONTROL_PORT" ]] && totalc="$value"
    done
    CELL_P64O=$(( (totalp + 1) / 2 )); CELL_P1400O=$(( totalp / 2 ))
    CELL_C64O=$(( (totalc + 1) / 2 )); CELL_C1400O=$(( totalc / 2 ))
    count_len() {
        local out
        out="$(grep -cE "\\.${1}:.*length ${2}([,[:space:]]|$)" "$CAPLOG" 2>/dev/null || true)"
        [[ "$out" =~ ^[0-9]+$ ]] || out=0
        printf '%s' "$out"
    }
    CELL_P64B="$(count_len "$PROBE_PORT" 64)"; CELL_P1400B="$(count_len "$PROBE_PORT" 1400)"
    CELL_C64B="$(count_len "$CONTROL_PORT" 64)"; CELL_C1400B="$(count_len "$CONTROL_PORT" 1400)"
    CELL_CK="$(grep -ciE 'bad (udp )?(cksum|checksum)' "$CAPLOG" 2>/dev/null || true)"
    [[ "$CELL_CK" =~ ^[0-9]+$ ]] || CELL_CK=0
    echo "cell ${mode} src=${src} dst=${dst} sent=${totalp}/${totalc} observed=${CELL_P64B}/${CELL_P1400B}/${CELL_C64B}/${CELL_C1400B}"
    rm -f "$CAPLOG"; CAPLOG=""
}

RESTORE_NEEDED=1
MATRIX=()
CKSUM_BAD=0
# Deny arm: all six probes must drop, with an explicit same-pair control
# permit. The broken fixture intentionally adds one broad permit to produce a
# positive FAIL pair rather than a silent/no-prober VOID.
apply_mode deny || fail_void harness-void
z="$(cli_show 'show configuration security policies | display set' 2>&1)"
grep -q 'set security policies default-policy deny-all' <<<"$z" || fail_void harness-void
for ((i = 0; i < 6; i++)); do
    si=0; di=1
    case "$i" in
    0) si=0; di=1 ;; 1) si=1; di=0 ;; 2) si=0; di=2 ;; 3) si=2; di=0 ;; 4) si=1; di=2 ;; 5) si=2; di=1 ;;
    esac
    measure_cell "$si" "$di" deny "$DENY_BURST"
    CKSUM_BAD=$((CKSUM_BAD + CELL_CK))
    key="deny:${PAIR_NAMES[$i]%%-*}->${PAIR_NAMES[$i]#*-}"
    MATRIX+=("$key" "$CELL_P64O" "$CELL_P64B" "$CELL_P1400O" "$CELL_P1400B" "$CELL_C64O" "$CELL_C64B" "$CELL_C1400O" "$CELL_C1400B")
done
# Permit arm: switch only the default policy; explicit control policies are
# retained as near misses, and the six probe cells must be loss-grade.
apply_mode permit || fail_void harness-void
z="$(cli_show 'show configuration security policies | display set' 2>&1)"
grep -q 'set security policies default-policy permit-all' <<<"$z" || fail_void harness-void
for ((i = 0; i < 6; i++)); do
    case "$i" in
    0) si=0; di=1 ;; 1) si=1; di=0 ;; 2) si=0; di=2 ;; 3) si=2; di=0 ;; 4) si=1; di=2 ;; 5) si=2; di=1 ;;
    esac
    measure_cell "$si" "$di" permit "$LOSS_BURST"
    CKSUM_BAD=$((CKSUM_BAD + CELL_CK))
    key="permit:${PAIR_NAMES[$i]%%-*}->${PAIR_NAMES[$i]#*-}"
    MATRIX+=("$key" "$CELL_P64O" "$CELL_P64B" "$CELL_P1400O" "$CELL_P1400B" "$CELL_C64O" "$CELL_C64B" "$CELL_C1400O" "$CELL_C1400B")
done

# The shared EXIT finalizer masks cancellation during cleanup and emits the
# verdict only after the exact restoration snapshot has been checked.
WIRE_GATE_FINAL_OUT="$(wire_matrix_verdict "$CKSUM_BAD" 12 "${MATRIX[@]}")"
WIRE_GATE_FINAL_RC=$?
exit "$WIRE_GATE_FINAL_RC"
