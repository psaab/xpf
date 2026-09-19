#!/usr/bin/env bash
# #10136 — wire_routing_separation: live VRF-miss deny gate.
#
# A temporary veth first remains unmastered, so the near-miss control follows
# the existing main-table VLAN-80 route. The same veth is then enslaved to a
# temporary, EMPTY kernel VRF table; the probe uses the same destination,
# sender namespace, UDP port and payload shape. The normal pref-2000
# l3mdev-unreachable rule must terminate that identical VRF miss. The negative
# control removes ONLY that terminator, so the miss falls through to main's
# already-proven VLAN-80 route and is visible at the managed peer. Both bursts
# run under one peer-side tcpdump window and successful sender sendto calls are
# the offered-frame count.
#
# Usage:
#   ./test/incus/wire-routing-separation.sh
#   ./test/incus/wire-routing-separation.sh --fixture transcript.tsv
#   ./test/incus/wire-routing-separation.sh --selftest
#
# Fixture format: one `probe_offered=N probe_leaked=N control_offered=N
# control_observed=N cksum_bad=N` line. Exit: 0 PASS, 1 FAIL, 2 VOID.
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
# shellcheck source=test/incus/wire-gate-lib.sh
source "${SCRIPT_DIR}/wire-gate-lib.sh"
cli_commit_succeeded() {
    local out="$1"
    grep -qE '^[[:space:]]*configuration check succeeds[[:space:]]*$' <<<"$out" &&
        grep -qE '^[[:space:]]*commit complete([: ].*)?$' <<<"$out"
}


if [[ "$MODE" == selftest ]]; then
    pass=0
    fail=0
    cell() {
        local label="$1" want_v="$2" want_rc="$3"
        shift 3
        local out rc v
        out=$(wire_routing_separation_verdict "$@")
        rc=$?
        v=$(awk '{print $3}' <<<"$out")
        if [[ "$v" == "$want_v" && "$rc" == "$want_rc" &&
            "$out" == WIRE_GATE\ wire_routing_separation\ * ]]; then
            echo "  PASS  $label"
            pass=$((pass + 1))
        else
            echo "  FAIL  $label (got '$out' rc=$rc)"
            fail=$((fail + 1))
        fi
    }
    marker_cell() {
        local label="$1" want="$2" text="$3" got
        if cli_commit_succeeded "$text"; then got=0; else got=1; fi
        if [[ "$got" == "$want" ]]; then
            echo "  PASS  $label"
            pass=$((pass + 1))
        else
            echo "  FAIL  $label (got rc=$got)"
            fail=$((fail + 1))
        fi
    }
    marker_cell "bare commit marker" 0 $'configuration check succeeds\ncommit complete'
    marker_cell "summary commit marker" 0 $'configuration check succeeds\ncommit complete: 1 statement(s) changed (1 added, 0 removed)'
    marker_cell "embedded commit marker rejected" 1 $'configuration check succeeds\nerror: commit failed before commit complete'

    if wire_gate_finalizer_selftest; then
        echo "  PASS  cleanup finalizer shields restore"
        pass=$((pass + 1))
    else
        echo "  FAIL  cleanup finalizer shields restore"
        fail=$((fail + 1))
    fi
    cell "clean VRF miss passes" PASS 0 1000 0 1500 1500 0
    cell "fault-injected miss leaks and fails" FAIL 1 1000 1 1500 1500 0
    cell "missing near-miss capture is VOID" VOID 2 1000 0 1500 999 0
    cell "short successful ingress burst is VOID" VOID 2 999 0 1500 1500 0
    cell "checksum corruption fails" FAIL 1 1000 0 1500 1500 1
    cell "malformed count is VOID" VOID 2 x 0 1500 1500 0

    # RED→GREEN proof through the fixture parser/emitter, not just a direct
    # reducer call: the fault transcript must fail and the baseline pass.
    good=$(mktemp "${TMPDIR:-/var/tmp}/xpf-10136-good.XXXXXX")
    bad=$(mktemp "${TMPDIR:-/var/tmp}/xpf-10136-bad.XXXXXX")
    printf '%s\n' 'probe_offered=1000 probe_leaked=0 control_offered=1500 control_observed=1500 cksum_bad=0' >"$good"
    printf '%s\n' 'probe_offered=1000 probe_leaked=1 control_offered=1500 control_observed=1500 cksum_bad=0' >"$bad"
    out=$("$0" --fixture "$bad"); rc=$?
    if [[ "$rc" == 1 && "$out" == *'WIRE_GATE wire_routing_separation FAIL reason=--'* ]]; then
        echo "  PASS  broken fixture fails"
        pass=$((pass + 1))
    else
        echo "  FAIL  broken fixture did not fail (rc=$rc out=$out)"
        fail=$((fail + 1))
    fi
    out=$("$0" --fixture "$good"); rc=$?
    if [[ "$rc" == 0 && "$out" == *'WIRE_GATE wire_routing_separation PASS reason=--'* ]]; then
        echo "  PASS  clean fixture passes"
        pass=$((pass + 1))
    else
        echo "  FAIL  clean fixture did not pass (rc=$rc out=$out)"
        fail=$((fail + 1))
    fi
    rm -f "$good" "$bad"
    echo "  wire-routing-separation selftest: $pass passed, $fail failed"
    [[ "$fail" -eq 0 && "$pass" -gt 0 ]] || exit 1
    exit 0
fi

if [[ "$MODE" == fixture ]]; then
    if [[ -z "$FIXTURE" || ! -f "$FIXTURE" ]]; then
        echo "usage: $0 --fixture <transcript.tsv>" >&2
        exit 2
    fi
    parsed=$(wire_parse_transcript "$FIXTURE") || {
        printf 'WIRE_GATE wire_routing_separation VOID reason=harness-void probe_offered=0 probe_leaked=0 control_offered=0 control_observed=0 cksum_bad=0\n'
        exit 2
    }
    # shellcheck disable=SC2034
    eval "$parsed" || {
        printf 'WIRE_GATE wire_routing_separation VOID reason=harness-void probe_offered=0 probe_leaked=0 control_offered=0 control_observed=0 cksum_bad=0\n'
        exit 2
    }
    po=${probe_offered:-} pl=${probe_leaked:-} co=${control_offered:-}
    cb=${control_observed:-} ck=${cksum_bad:-0}
    if [[ -z "$po" || -z "$pl" || -z "$co" || -z "$cb" ]]; then
        printf 'WIRE_GATE wire_routing_separation VOID reason=harness-void probe_offered=0 probe_leaked=0 control_offered=0 control_observed=0 cksum_bad=0\n'
        exit 2
    fi
    wire_routing_separation_verdict "$po" "$pl" "$co" "$cb" "$ck"
    exit $?
fi

# ── live gate (destructive lock cell) ────────────────────────────────
_CELL_DIR="$SCRIPT_DIR"
# shellcheck source=test/incus/cluster-cell.sh
source "${_CELL_DIR}/cluster-cell.sh"
xpf_enter_destructive_cluster_cell "wire-routing-separation $*" "$0" "$@"
# shellcheck source=test/incus/cluster-env.sh
source "${SCRIPT_DIR}/cluster-env.sh"

INCUS_REMOTE="${INCUS_REMOTE:-loss}"
NODE="${NODE:-${FW0:-${INCUS_REMOTE}:xpf-userspace-fw0}}"
NODE0="${FW0:-${INCUS_REMOTE}:xpf-userspace-fw0}"
NODE1="${FW1:-${INCUS_REMOTE}:xpf-userspace-fw1}"
TARGET="${TARGET:-${INCUS_REMOTE}:xpf-mouse-target}"
RI_NAME="${RI_NAME:-wire-10136}"
[[ "$RI_NAME" =~ ^[A-Za-z][A-Za-z0-9_-]{0,31}$ ]] || {
    printf 'WIRE_GATE wire_routing_separation VOID reason=harness-void probe_offered=0 probe_leaked=0 control_offered=0 control_observed=0 cksum_bad=0\n'
    exit 2
}
VRF_NAME="${VRF_NAME:-vrf-${RI_NAME}}"
VRF_TABLE=""
DEST_IP="${DEST_IP:-172.16.80.201}"
EGRESS_DEV="${EGRESS_DEV:-ge-0-0-2.80}"
NS="${NS:-xpf-wire-10136}"
VETH="${VETH:-xpf10136-vrf}"
VETH_PEER="${VETH_PEER:-xpf10136-peer}"
VETH_ADDR="${VETH_ADDR:-10.201.36.1}"
PEER_ADDR="${PEER_ADDR:-10.201.36.2}"
PORT="${PORT:-55901}"
PROBE_BURST="${PROBE_BURST:-1000}"
CONTROL_BURST="${CONTROL_BURST:-1500}"
RATE="${RATE:-500}"
STEP_TIMEOUT="${STEP_TIMEOUT:-120}"
REMOTE_PROBE="/tmp/xpf-wire-routing-probe-10136-${BASHPID}"
SG="sg incus-admin -c"

CAP_PID=""
CAPLOG=""
RI_OWNED=0
NS_OWNED=0
VETH_OWNED=0
ADDR_OWNED=0
REMOTE_PROBE_OWNED=0
RULE_MUTATED=0
BASELINE_CAPTURED=0
KERNEL_BASELINE_CAPTURED=0
RESTORE_OK=1
WIRE_GATE_FINAL_OUT=""
WIRE_GATE_FINAL_RC=2

remote() { $SG "incus exec ${NODE} -- bash -lc '$*'"; }
snapshot_node() {
    local n="$1" out="$2"
    printf 'show configuration | display set\nexit\n' |
        $SG "incus exec ${n} -- bash -lc 'cli'" >"$out" 2>&1
}
normalize_config() { sed -n '/^set /p' "$1"; }
cli_commit_ri() {
    local action="$1" out
    if [[ "$action" == add ]]; then
        out="$(printf 'configure\nrollback 0\nset routing-instances %s instance-type vrf\ncommit check\ncommit\nexit\nquit\n' "$RI_NAME" |
            $SG "incus exec ${NODE} -- cli" 2>&1)" || {
            printf '%s\n' "$out" >&2
            return 1
        }
    else
        out="$(printf 'configure\nrollback 0\ndelete routing-instances %s\ncommit check\ncommit\nexit\nquit\n' "$RI_NAME" |
            $SG "incus exec ${NODE} -- cli" 2>&1)" || {
            printf '%s\n' "$out" >&2
            return 1
        }
    fi
    if ! cli_commit_succeeded "$out"; then
        printf '%s\n' "$out" >&2
        return 1
    fi
}
managed_vrf_table() {
    remote "ip -d link show ${VRF_NAME}" 2>/dev/null |
        sed -n 's/.*vrf table \([0-9][0-9]*\).*/\1/p' | sed -n '1p'
}
wait_managed_vrf() {
    local i
    for ((i=0; i<60; i++)); do
        VRF_TABLE="$(managed_vrf_table)"
        RULE_2000="$(remote 'ip -4 rule show pref 2000' 2>/dev/null || true)"
        if [[ -n "$VRF_TABLE" && "$RULE_2000" == *unreachable* ]]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

ARCHIVE_DIR="${XPF_WIRE_CONFIG_ARCHIVE_DIR:-${TMPDIR:-/var/tmp}/xpf-wire-routing-separation-$(date +%s)}"
mkdir -p "$ARCHIVE_DIR" || true
BASE0_RAW="$ARCHIVE_DIR/fw0-pre.set"
BASE1_RAW="$ARCHIVE_DIR/fw1-pre.set"
POST0_RAW="$ARCHIVE_DIR/fw0-post.set"
POST1_RAW="$ARCHIVE_DIR/fw1-post.set"
BASE0_NORM="$ARCHIVE_DIR/fw0-pre.normalized.set"
BASE1_NORM="$ARCHIVE_DIR/fw1-pre.normalized.set"
POST0_NORM="$ARCHIVE_DIR/fw0-post.normalized.set"
POST1_NORM="$ARCHIVE_DIR/fw1-post.normalized.set"
RULE_SNAPSHOT=""
RULE_2000=""
TABLE_SNAPSHOT=""
WIRE_GATE_RESTORE_VOID='WIRE_GATE wire_routing_separation VOID reason=harness-void probe_offered=0 probe_leaked=0 control_offered=0 control_observed=0 cksum_bad=0'
void_now() {
    WIRE_GATE_FINAL_OUT="WIRE_GATE wire_routing_separation VOID reason=$1 probe_offered=0 probe_leaked=0 control_offered=0 control_observed=0 cksum_bad=0"
    WIRE_GATE_FINAL_RC=2
    exit 2
}

cleanup() {
    local saved_rc=$?
    trap '' EXIT INT TERM
    if [[ -n "$CAP_PID" ]]; then
        kill "$CAP_PID" >/dev/null 2>&1 || true
        wait "$CAP_PID" >/dev/null 2>&1 || true
        CAP_PID=""
    fi
    if ((KERNEL_BASELINE_CAPTURED && RULE_MUTATED)); then
        remote "ip -4 rule add pref 2000 l3mdev unreachable" >/dev/null 2>&1 || RESTORE_OK=0
        [[ "$(remote 'ip -4 rule show pref 2000' 2>/dev/null || true)" == "$RULE_2000" ]] || RESTORE_OK=0
        RULE_MUTATED=0
    fi
    if ((REMOTE_PROBE_OWNED)); then
        remote "rm -f ${REMOTE_PROBE}" >/dev/null 2>&1 || RESTORE_OK=0
        REMOTE_PROBE_OWNED=0
    fi
    if ((ADDR_OWNED)); then
        remote "ip addr del ${VETH_ADDR}/24 dev ${VETH}" >/dev/null 2>&1 || true
        ADDR_OWNED=0
    fi
    if ((NS_OWNED)); then
        remote "ip netns del ${NS}" >/dev/null 2>&1 || RESTORE_OK=0
        NS_OWNED=0
    fi
    if ((VETH_OWNED)); then
        remote "ip link del ${VETH}" >/dev/null 2>&1 || true
        VETH_OWNED=0
    fi
    if ((RI_OWNED)); then
        cli_commit_ri delete || RESTORE_OK=0
        RI_OWNED=0
    fi
    if ((KERNEL_BASELINE_CAPTURED)); then
        local restore_i
        for ((restore_i=0; restore_i<60; restore_i++)); do
            if [[ -z "$(remote "ip link show ${VRF_NAME}" 2>/dev/null || true)" &&
                "$(remote 'ip -4 rule show' 2>/dev/null || true)" == "$RULE_SNAPSHOT" ]]; then
                break
            fi
            sleep 1
        done
        [[ -z "$(remote "ip link show ${VRF_NAME}" 2>/dev/null || true)" ]] || RESTORE_OK=0
        [[ -z "$(remote "ip link show ${VETH}" 2>/dev/null || true)" ]] || RESTORE_OK=0
        [[ -z "$(remote "ip netns list | grep -E '^${NS}( |$)'" 2>/dev/null || true)" ]] || RESTORE_OK=0
        [[ -z "${VRF_TABLE:-}" || "$(remote "ip -4 route show table ${VRF_TABLE}" 2>/dev/null || true)" == "$TABLE_SNAPSHOT" ]] || RESTORE_OK=0
        [[ "$(remote 'ip -4 rule show' 2>/dev/null || true)" == "$RULE_SNAPSHOT" ]] || RESTORE_OK=0
    fi

    if ((BASELINE_CAPTURED)); then
        if ! snapshot_node "$NODE0" "$POST0_RAW"; then
            RESTORE_OK=0
        else
            normalize_config "$POST0_RAW" >"$POST0_NORM"
            cmp -s "$BASE0_NORM" "$POST0_NORM" || RESTORE_OK=0
        fi
        if ! snapshot_node "$NODE1" "$POST1_RAW"; then
            RESTORE_OK=0
        else
            normalize_config "$POST1_RAW" >"$POST1_NORM"
            cmp -s "$BASE1_NORM" "$POST1_NORM" || RESTORE_OK=0
        fi
        printf 'config_archive=%s pre_fw0_sha=%s post_fw0_sha=%s\n' \
            "$ARCHIVE_DIR" "$(sha256sum "$BASE0_NORM" 2>/dev/null | awk '{print $1}')" \
            "$(sha256sum "$POST0_NORM" 2>/dev/null | awk '{print $1}')"
    fi
    trap - INT TERM
    return "$saved_rc"
}
WIRE_GATE_CLEANUP_FN=cleanup
WIRE_GATE_RESTORE_OK_REF=RESTORE_OK
trap wire_gate_finalize EXIT
trap 'trap "" INT TERM; void_now harness-void' INT TERM

# ── Phase 0: complete snapshots and foreign-state refusal ────────────
snapshot_node "$NODE0" "$BASE0_RAW" || void_now env-void
snapshot_node "$NODE1" "$BASE1_RAW" || void_now env-void
normalize_config "$BASE0_RAW" >"$BASE0_NORM"
normalize_config "$BASE1_RAW" >"$BASE1_NORM"
[[ -s "$BASE0_NORM" && -s "$BASE1_NORM" ]] || void_now env-void
BASELINE_CAPTURED=1
if grep -qE 'wire-10136|xpf10136|10\.201\.36' "$BASE0_NORM" ||
    grep -qE 'wire-10136|xpf10136|10\.201\.36' "$BASE1_NORM"; then
    void_now env-void
fi
if grep -qE "^set routing-instances ${RI_NAME}[[:space:]]" "$BASE0_NORM" ||
    grep -qE "^set routing-instances ${RI_NAME}[[:space:]]" "$BASE1_NORM"; then
    void_now env-void
fi
[[ "$PORT" =~ ^[0-9]+$ && "$PROBE_BURST" =~ ^[0-9]+$ &&
    "$CONTROL_BURST" =~ ^[0-9]+$ ]] || void_now harness-void
if remote "ip link show ${VRF_NAME}" >/dev/null 2>&1; then void_now env-void; fi
if remote "ip link show ${VETH}" >/dev/null 2>&1; then void_now env-void; fi
if remote "ip netns list | grep -Eq '^${NS}( |$)'" >/dev/null 2>&1; then void_now env-void; fi
RULE_SNAPSHOT="$(remote 'ip -4 rule show' 2>/dev/null || true)"
RULE_2000="$(remote 'ip -4 rule show pref 2000' 2>/dev/null || true)"
KERNEL_BASELINE_CAPTURED=1
if [[ -z "$RULE_2000" ]] &&
    grep -qE '^set routing-instances [^ ]+ instance-type (vrf|virtual-router)' "$BASE0_NORM"; then
    void_now env-void
fi
remote "command -v ip >/dev/null && command -v python3 >/dev/null" >/dev/null 2>&1 || void_now no-prober
$SG "incus exec ${TARGET} -- sh -c 'command -v tcpdump >/dev/null && command -v python3 >/dev/null'" >/dev/null 2>&1 || void_now no-prober
if remote "test -e ${REMOTE_PROBE}" >/dev/null 2>&1; then void_now env-void; fi
RI_OWNED=1
cli_commit_ri add || void_now harness-void
wait_managed_vrf || void_now harness-void
[[ "$VRF_TABLE" =~ ^[0-9]+$ ]] || void_now harness-void
TABLE_SNAPSHOT="$(remote "ip -4 route show table ${VRF_TABLE}" 2>/dev/null || true)"
[[ -z "$TABLE_SNAPSHOT" ]] || void_now env-void
NS_OWNED=1
remote "ip netns add ${NS}" >/dev/null 2>&1 || void_now harness-void
VETH_OWNED=1
remote "ip link add ${VETH} type veth peer name ${VETH_PEER}" >/dev/null 2>&1 || void_now harness-void
remote "ip link set ${VETH_PEER} netns ${NS}" >/dev/null 2>&1 || void_now harness-void
 # Leave the ingress unmastered for the control: it follows the already
 # proven main-table VLAN-80 path. The identical veth is enslaved to the
 # empty VRF only after the control burst.
remote "ip link set ${VETH} up" >/dev/null 2>&1 || void_now harness-void
ADDR_OWNED=1
remote "ip addr add ${VETH_ADDR}/24 dev ${VETH}" >/dev/null 2>&1 || void_now harness-void
remote "ip netns exec ${NS} ip link set lo up" >/dev/null 2>&1 || void_now harness-void
remote "ip netns exec ${NS} ip link set ${VETH_PEER} up" >/dev/null 2>&1 || void_now harness-void
remote "ip netns exec ${NS} ip addr add ${PEER_ADDR}/24 dev ${VETH_PEER}" >/dev/null 2>&1 || void_now harness-void
remote "ip netns exec ${NS} ip route add default via ${VETH_ADDR} dev ${VETH_PEER}" >/dev/null 2>&1 || void_now harness-void

REMOTE_PROBE_OWNED=1
$SG "incus file push --mode 0755 ${SCRIPT_DIR}/wire_routing_probe.py ${NODE}${REMOTE_PROBE}" >/dev/null 2>&1 || void_now harness-void

# ── Phase 2: one peer-side window, main control then identical VRF miss ─
CAPLOG="$(mktemp "${TMPDIR:-/var/tmp}/xpf-wire-routing-cap.XXXXXX")" || void_now harness-void
$SG "incus exec ${TARGET} -- timeout ${STEP_TIMEOUT} tcpdump -i eth0 -nn -vv -A -s 0 udp and dst host ${DEST_IP} and dst port ${PORT}" >"$CAPLOG" 2>&1 &
CAP_PID=$!
sleep 2
kill -0 "$CAP_PID" >/dev/null 2>&1 || void_now no-prober
MAIN_LOOKUP="$(remote "ip -4 route get ${DEST_IP} 2>&1 || true")"
[[ "$MAIN_LOOKUP" == *"${EGRESS_DEV}"* ]] || void_now env-void
# Main-table near-miss control: same fixed source namespace, destination,
# port and payload shape, with the veth not yet claimed by the VRF.
SENT_CONTROL="$(remote "ip netns exec ${NS} python3 ${REMOTE_PROBE} --src ${PEER_ADDR} --source-port ${PORT} --dst ${DEST_IP} --port ${PORT} --count ${CONTROL_BURST} --tag C --rate ${RATE}" 2>&1 || true)"
sleep 1
# Claim the same ingress veth for the empty VRF. Its only route is the
# connected sender subnet; DEST_IP is a genuine VRF miss.
remote "ip link set ${VETH} master ${VRF_NAME}" >/dev/null 2>&1 || void_now harness-void
MISS_LOOKUP="$(remote "ip -4 route get ${DEST_IP} vrf ${VRF_NAME} 2>&1 || true")"
[[ "$MISS_LOOKUP" == *unreachable* ]] || void_now env-void
if [[ -n "${WIRE_BROKEN_FIXTURE:-}" ]]; then
    # Fault injection: remove ONLY the l3mdev terminator. The same empty
    # table miss now falls through to the already-proven main route.
    RULE_MUTATED=1
    remote 'ip -4 rule del pref 2000' >/dev/null 2>&1 || void_now harness-void
    FAULT_LOOKUP="$(remote "ip -4 route get ${DEST_IP} vrf ${VRF_NAME} 2>&1 || true")"
    [[ "$FAULT_LOOKUP" == *"${EGRESS_DEV}"* ]] || void_now env-void
fi
SENT_PROBE="$(remote "ip netns exec ${NS} python3 ${REMOTE_PROBE} --src ${PEER_ADDR} --source-port ${PORT} --dst ${DEST_IP} --port ${PORT} --count ${PROBE_BURST} --tag P --rate ${RATE}" 2>&1 || true)"
sleep 3
if ! kill -0 "$CAP_PID" >/dev/null 2>&1; then
    void_now no-prober
fi
kill "$CAP_PID" >/dev/null 2>&1 || true
wait "$CAP_PID" >/dev/null 2>&1 || true
CAP_PID=""
# Restore the fault before the verdict is emitted; the EXIT trap repeats this
# if a signal or later harness error interrupts the normal path.
if ((RULE_MUTATED)); then
    remote 'ip -4 rule add pref 2000 l3mdev unreachable' >/dev/null 2>&1 || void_now harness-void
    [[ "$(remote 'ip -4 rule show pref 2000' 2>/dev/null || true)" == "$RULE_2000" ]] || void_now harness-void
    RULE_MUTATED=0
fi

extract_sent() {
    local tag="$1" text="$2" value
    value=$(sed -n "s/.*SENT tag=${tag} count=\([0-9][0-9]*\).*/\1/p" <<<"$text" | tail -1)
    [[ "$value" =~ ^[0-9]+$ ]] && printf '%s\n' "$value" || printf '0\n'
}
POFFERED="$(extract_sent P "$SENT_PROBE")"
COFFERED="$(extract_sent C "$SENT_CONTROL")"
PLEAKED="$(grep -cE 'P10136:[0-9]+:' "$CAPLOG" 2>/dev/null || true)"
COBSERVED="$(grep -cE 'C10136:[0-9]+:' "$CAPLOG" 2>/dev/null || true)"
CKSUM="$(grep -ciE 'bad (udp|ip) (cksum|checksum)' "$CAPLOG" 2>/dev/null || true)"
rm -f "$CAPLOG"
[[ "$PLEAKED" =~ ^[0-9]+$ ]] || PLEAKED=0
[[ "$COBSERVED" =~ ^[0-9]+$ ]] || COBSERVED=0
[[ "$CKSUM" =~ ^[0-9]+$ ]] || CKSUM=0
printf 'offered: probe=%s control=%s observed: probe=%s control=%s cksum_bad=%s archive=%s\n' \
    "$POFFERED" "$COFFERED" "$PLEAKED" "$COBSERVED" "$CKSUM" "$ARCHIVE_DIR"
WIRE_GATE_FINAL_OUT="$(wire_routing_separation_verdict "$POFFERED" "$PLEAKED" "$COFFERED" "$COBSERVED" "$CKSUM")"
WIRE_GATE_FINAL_RC=$?
exit "$WIRE_GATE_FINAL_RC"
