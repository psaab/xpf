#!/usr/bin/env bash
# #10136 — wire_routing_separation: live VRF-miss deny gate.
#
# The product-owned LAN ingress (reth1 / ge-0-0-1, XDP-owned, transit-fence
# admitted) is the only offer path. The gate first sends the near-miss control
# from the LAN host through its existing main-table VLAN-80 path. It then
# creates an EMPTY RI and adds an exact-match input FBF term steering the probe
# tuple into it. The clean leg therefore reaches the userspace route miss and
# is denied. The broken leg inserts a temporary exact explicit `accept` term
# ahead of that FBF term, at the actual userspace enforcement point, so the
# same owned ingress follows main's already-proven VLAN-80 route and is visible
# at the managed peer.
# Both bursts run under one peer-side tcpdump window; successful sender
# sendto calls are the offered-frame count. Sender and capture mirror
# wire-conntrack-lifecycle: LAN host (cluster-userspace-host) offers, target
# captures on eth0. The target is deliberately the managed peer, not the
# host-side fence.
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
canonical_set_snapshot() {
    # Only these two sibling flow statements are known to be semantically
    # commutative on the managed peers. Preserve every other statement and its
    # position; a global sort would hide order-sensitive restore drift.
    awk '
        {
            if ($0 !~ /^set /) next
            lines[++n] = $0
            if ($0 == "set security flow allow-dns-reply") dns++
            if ($0 == "set security flow allow-embedded-icmp") embedded++
        }
        END {
            placed = 0
            for (i = 1; i <= n; i++) {
                if (lines[i] == "set security flow allow-dns-reply" ||
                    lines[i] == "set security flow allow-embedded-icmp") {
                    if (!placed) {
                        for (j = 0; j < dns; j++) print "set security flow allow-dns-reply"
                        for (j = 0; j < embedded; j++) print "set security flow allow-embedded-icmp"
                        placed = 1
                    }
                } else {
                    print lines[i]
                }
            }
        }
    ' "$1"
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
    set_a=$(mktemp "${TMPDIR:-/var/tmp}/xpf-10136-set-a.XXXXXX")
    set_b=$(mktemp "${TMPDIR:-/var/tmp}/xpf-10136-set-b.XXXXXX")
    set_c=$(mktemp "${TMPDIR:-/var/tmp}/xpf-10136-set-c.XXXXXX")
    set_d=$(mktemp "${TMPDIR:-/var/tmp}/xpf-10136-set-d.XXXXXX")
    printf '%s\n' \
        'set security flow allow-dns-reply' \
        'set security flow allow-embedded-icmp' >"$set_a"
    printf '%s\n' \
        'set security flow allow-embedded-icmp' \
        'set security flow allow-dns-reply' >"$set_b"
    printf '%s\n' 'set security flow allow-embedded-icmp' >"$set_c"
    printf '%s\n' \
        'cli — connected to xpfd (uptime: 1h)' \
        'Type '\''?'\'' for help' \
        'set security flow allow-dns-reply' \
        'set security flow allow-embedded-icmp' >"$set_d"
    if [[ "$(canonical_set_snapshot "$set_a")" == "$(canonical_set_snapshot "$set_b")" &&
        "$(canonical_set_snapshot "$set_a")" != "$(canonical_set_snapshot "$set_c")" &&
        "$(canonical_set_snapshot "$set_a")" == "$(canonical_set_snapshot "$set_d")" ]]; then
        echo "  PASS  semantic set reorder and CLI banner are restore-equivalent"
        pass=$((pass + 1))
    else
        echo "  FAIL  semantic set reorder and CLI banner are restore-equivalent"
        fail=$((fail + 1))
    fi
    rm -f "$set_a" "$set_b" "$set_c" "$set_d"

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
LAN_REF="${CLUSTER_LAN_HOST:-${INCUS_REMOTE}:cluster-userspace-host}"
LAN_ADDR="${LAN_ADDR:-${LAN_HOST_IP:-10.0.61.102}}"
LAN_ADDR="${LAN_ADDR%%/*}"
# The exact tuple is attached to the product-owned LAN ingress. The FBF term
# owns the fixed leg; the broken fixture inserts a temporary explicit accept
# term ahead of it, exercising the actual userspace enforcement point.
LAN_DEV="${LAN_DEV:-ge-0-0-1}"
PORT="${PORT:-$((40000 + RANDOM % 20000))}"
PROBE_BURST="${PROBE_BURST:-1000}"
CONTROL_BURST="${CONTROL_BURST:-1500}"
RATE="${RATE:-500}"
STEP_TIMEOUT="${STEP_TIMEOUT:-120}"
REMOTE_PROBE="/tmp/xpf-wire-routing-probe-10136-${BASHPID}"
SG="sg incus-admin -c"

CAP_PID=""
CAPLOG=""
RI_OWNED=0
FILTER_OWNED=0
ALLOW_OWNED=0
REMOTE_PROBE_OWNED=0
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
normalize_config() { canonical_set_snapshot "$1"; }
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
cli_commit_probe_filter() {
    local action="$1" out
    if [[ "$action" == add ]]; then
        out="$(printf 'configure\nrollback 0\nset firewall family inet filter sfmix-pbr term wire-10136 from source-address %s/32\nset firewall family inet filter sfmix-pbr term wire-10136 from destination-address %s/32\nset firewall family inet filter sfmix-pbr term wire-10136 from protocol udp\nset firewall family inet filter sfmix-pbr term wire-10136 from destination-port %s\nset firewall family inet filter sfmix-pbr term wire-10136 then routing-instance %s\ninsert firewall family inet filter sfmix-pbr term wire-10136 before term default\ncommit check\ncommit\nexit\nquit\n' "$LAN_ADDR" "$DEST_IP" "$PORT" "$RI_NAME" |
            $SG "incus exec ${NODE} -- cli" 2>&1)" || {
            printf '%s\n' "$out" >&2
            return 1
        }
    else
        out="$(printf 'configure\nrollback 0\ndelete firewall family inet filter sfmix-pbr term wire-10136\ncommit check\ncommit\nexit\nquit\n' |
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
cli_commit_probe_allow() {
    local action="$1" out
    if [[ "$action" == add ]]; then
        out="$(printf 'configure\nrollback 0\nset firewall family inet filter sfmix-pbr term wire-10136-allow from source-address %s/32\nset firewall family inet filter sfmix-pbr term wire-10136-allow from destination-address %s/32\nset firewall family inet filter sfmix-pbr term wire-10136-allow from protocol udp\nset firewall family inet filter sfmix-pbr term wire-10136-allow from destination-port %s\nset firewall family inet filter sfmix-pbr term wire-10136-allow then accept\ninsert firewall family inet filter sfmix-pbr term wire-10136-allow before term wire-10136\ncommit check\ncommit\nexit\nquit\n' "$LAN_ADDR" "$DEST_IP" "$PORT" |
            $SG "incus exec ${NODE} -- cli" 2>&1)" || {
            printf '%s\n' "$out" >&2
            return 1
        }
    else
        out="$(printf 'configure\nrollback 0\ndelete firewall family inet filter sfmix-pbr term wire-10136-allow\ncommit check\ncommit\nexit\nquit\n' |
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
LAN_MASTER_SNAPSHOT=""
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
    if ((ALLOW_OWNED)); then
        cli_commit_probe_allow delete || RESTORE_OK=0
        ALLOW_OWNED=0
    fi
    if ((FILTER_OWNED)); then
        cli_commit_probe_filter delete || RESTORE_OK=0
        FILTER_OWNED=0
    fi
    if ((REMOTE_PROBE_OWNED)); then
        $SG "incus exec ${LAN_REF} -- rm -f ${REMOTE_PROBE}" >/dev/null 2>&1 || RESTORE_OK=0
        REMOTE_PROBE_OWNED=0
    fi
    if ((RI_OWNED)); then
        cli_commit_ri delete || RESTORE_OK=0
        RI_OWNED=0
    fi
    if ((KERNEL_BASELINE_CAPTURED)); then
        local restore_i
        for ((restore_i=0; restore_i<60; restore_i++)); do
            if [[ -z "$(remote "ip link show ${VRF_NAME}" 2>/dev/null || true)" &&
                "$(remote "ip -o link show ${LAN_DEV}" 2>/dev/null | sed -n 's/.* master \([^ ]*\).*/\1/p')" == "$LAN_MASTER_SNAPSHOT" &&
                "$(remote 'ip -4 rule show' 2>/dev/null || true)" == "$RULE_SNAPSHOT" ]]; then
                break
            fi
            sleep 1
        done
        [[ -z "$(remote "ip link show ${VRF_NAME}" 2>/dev/null || true)" ]] || RESTORE_OK=0
        [[ "$(remote "ip -o link show ${LAN_DEV}" 2>/dev/null | sed -n 's/.* master \([^ ]*\).*/\1/p')" == "$LAN_MASTER_SNAPSHOT" ]] || RESTORE_OK=0
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
# The ingress filter must already be attached to the product-owned LAN unit.
# This is the ownership proof that replaces the old temporary unowned veth.
grep -q 'set interfaces reth1 unit 0 family inet filter input sfmix-pbr' "$BASE0_NORM" ||
    void_now env-void
grep -q '^set firewall family inet filter sfmix-pbr term default ' "$BASE0_NORM" ||
    void_now env-void
[[ "$PORT" =~ ^[0-9]+$ && "$PORT" -ge 1 && "$PORT" -le 65535 &&
    "$PROBE_BURST" =~ ^[0-9]+$ && "$CONTROL_BURST" =~ ^[0-9]+$ ]] ||
    void_now harness-void
if remote "ip link show ${VRF_NAME}" >/dev/null 2>&1; then void_now env-void; fi
RULE_SNAPSHOT="$(remote 'ip -4 rule show' 2>/dev/null || true)"
RULE_2000="$(remote 'ip -4 rule show pref 2000' 2>/dev/null || true)"
LAN_MASTER_SNAPSHOT="$(remote "ip -o link show ${LAN_DEV}" 2>/dev/null |
    sed -n 's/.* master \([^ ]*\).*/\1/p')"
KERNEL_BASELINE_CAPTURED=1
remote "ip -d link show ${LAN_DEV} | grep -q 'prog/xdp'" || void_now env-void
[[ -n "$RULE_2000" ]] || void_now env-void
remote "command -v ip >/dev/null" >/dev/null 2>&1 || void_now no-prober
$SG "incus exec ${LAN_REF} -- sh -c 'command -v python3 >/dev/null'" >/dev/null 2>&1 ||
    void_now no-prober
$SG "incus exec ${TARGET} -- sh -c 'command -v tcpdump >/dev/null && command -v python3 >/dev/null'" ||
    void_now no-prober
if $SG "incus exec ${LAN_REF} -- test -e ${REMOTE_PROBE}" >/dev/null 2>&1; then
    void_now env-void
fi

RI_OWNED=1
cli_commit_ri add || void_now harness-void
wait_managed_vrf || void_now harness-void
[[ "$VRF_TABLE" =~ ^[0-9]+$ ]] || void_now harness-void
TABLE_SNAPSHOT="$(remote "ip -4 route show table ${VRF_TABLE}" 2>/dev/null || true)"
[[ -z "$TABLE_SNAPSHOT" ]] || void_now env-void

REMOTE_PROBE_OWNED=1
$SG "incus file push --mode 0755 ${SCRIPT_DIR}/wire_routing_probe.py ${LAN_REF}${REMOTE_PROBE}" ||
    void_now harness-void

# ── Phase 1: same owned LAN ingress, control then empty-RI probe ─────
CAPLOG="$(mktemp "${TMPDIR:-/var/tmp}/xpf-wire-routing-cap.XXXXXX")" || void_now harness-void
$SG "incus exec ${TARGET} -- timeout ${STEP_TIMEOUT} tcpdump -i eth0 -nn -vv -A -s 0 udp and dst host ${DEST_IP} and dst port ${PORT}" >"$CAPLOG" 2>&1 &
CAP_PID=$!
sleep 2
kill -0 "$CAP_PID" >/dev/null 2>&1 || void_now no-prober
MAIN_ROUTE_ARGS="ip -4 route get ${DEST_IP} from ${LAN_ADDR} iif ${LAN_DEV} ipproto udp sport ${PORT} dport ${PORT}"
MAIN_LOOKUP="$(remote "${MAIN_ROUTE_ARGS} 2>&1 || true")"
[[ "$MAIN_LOOKUP" == *"${EGRESS_DEV}"* ]] || void_now env-void
SENT_CONTROL="$($SG "incus exec ${LAN_REF} -- ${REMOTE_PROBE} --src ${LAN_ADDR} --source-port ${PORT} --dst ${DEST_IP} --port ${PORT} --count ${CONTROL_BURST} --tag C --rate ${RATE}" 2>&1 || true)"
sleep 1

# Evict the control's cached forwarding decision on both cluster nodes. The
# dataplane intentionally reuses an established 5-tuple without re-running RI
# scope, so this remains destination/port-scoped and proves exact absence.
session_i=0
for clear_node in "$NODE0" "$NODE1"; do
    clear_out="$(printf 'clear security flow session destination-prefix %s destination-port %s\nexit\nquit\n' \
        "$DEST_IP" "$PORT" |
        $SG "incus exec ${clear_node} -- cli" 2>&1 || true)"
    grep -qiE 'error|failed|unknown command' <<<"$clear_out" && void_now harness-void
    session_out="$(printf 'show security flow session destination-prefix %s destination-port %s limit 10000\nexit\nquit\n' \
        "$DEST_IP" "$PORT" |
        $SG "incus exec ${clear_node} -- cli" 2>&1 || true)"
    printf '%s\n' "$session_out" >"$ARCHIVE_DIR/session-${session_i}.txt"
    grep -qE '^[[:space:]]*Total sessions:[[:space:]]*0[[:space:]]*$' <<<"$session_out" ||
        void_now harness-void
    grep -qE "In:.*${LAN_ADDR}/${PORT}.*${DEST_IP}/${PORT}" <<<"$session_out" &&
        void_now harness-void
    session_i=$((session_i + 1))
done

FILTER_OWNED=1
cli_commit_probe_filter add || void_now harness-void
PBR_RULES=""
PBR_MATCH=""
for ((pbr_i=0; pbr_i<60; pbr_i++)); do
    PBR_RULES="$(remote 'ip -4 rule show' 2>/dev/null | grep -E 'lookup [0-9]+$' || true)"
    PBR_MATCH="$(grep -E "iif ${LAN_DEV}.*lookup ${VRF_TABLE}([[:space:]]|$)" <<<"$PBR_RULES" || true)"
    [[ -n "$PBR_MATCH" ]] && break
    sleep 1
done
[[ -n "$PBR_MATCH" ]] || void_now harness-void
[[ -z "$(remote "ip -4 route show table ${VRF_TABLE}" 2>/dev/null || true)" ]] ||
    void_now env-void
printf '%s\n' "$PBR_MATCH" >"$ARCHIVE_DIR/pbr-rules.set"

if [[ -n "${WIRE_BROKEN_FIXTURE:-}" ]]; then
    # Fault injection is an exact, temporary explicit ALLOW at the real
    # userspace enforcement point. It precedes (but does not alter) the fixed
    # RI-steering term, so the broken packet follows the proven main route.
    ALLOW_OWNED=1
    cli_commit_probe_allow add || void_now harness-void
    ALLOW_CHECK_RAW="$ARCHIVE_DIR/allow-check.set"
    snapshot_node "$NODE0" "$ALLOW_CHECK_RAW" || void_now harness-void
    grep -q "set firewall family inet filter sfmix-pbr term wire-10136-allow then accept" \
        "$ALLOW_CHECK_RAW" || void_now harness-void
    MAIN_LOOKUP="$(remote "${MAIN_ROUTE_ARGS} 2>&1 || true")"
    [[ "$MAIN_LOOKUP" == *"${EGRESS_DEV}"* ]] || void_now env-void
fi
SENT_PROBE="$($SG "incus exec ${LAN_REF} -- ${REMOTE_PROBE} --src ${LAN_ADDR} --source-port ${PORT} --dst ${DEST_IP} --port ${PORT} --count ${PROBE_BURST} --tag P --rate ${RATE}" 2>&1 || true)"
sleep 3
if ! kill -0 "$CAP_PID" >/dev/null 2>&1; then
    void_now no-prober
fi
kill "$CAP_PID" >/dev/null 2>&1 || true
wait "$CAP_PID" >/dev/null 2>&1 || true
CAP_PID=""
if ((ALLOW_OWNED)); then
    cli_commit_probe_allow delete || void_now harness-void
    ALLOW_OWNED=0
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
