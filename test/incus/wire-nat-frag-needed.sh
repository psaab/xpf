#!/usr/bin/env bash
# #12809 — wire_nat_frag_needed: ICMP frag-needed capture for a NON-ZONE
# source-NAT scope (#12525 acceptance; the capture owed since #12085).
#
# PROPERTY. A flow matched by an interface-mode source-NAT rule-set whose
# to-scope is NOT a zone (`to interface reth0.80`) is translated to the
# egress address. A genuine, in-path kernel-generated ICMP frag-needed
# addressed to that NAT address must be handled by the userspace helper —
# which registered the address for exactly this scope (#12085) — and
# delivered to the ORIGINAL source with both the outer destination and the
# embedded quoted source reverse-translated. Pre-#12085 the address was
# never registered, the shim classified the error as local, and the kernel
# ate it: the client saw nothing.
#
# LIVE TOPOLOGY (loss userspace cluster):
#
#   cluster-userspace-host 10.0.61.102 (client, eth0)
#     |  default via reth1 VIP 10.0.61.1
#   [xpf-userspace-fw0]  reth1 (zone lan) -> reth0.80 (zone wan, 172.16.80.8)
#     |  lab rule-set: from zone lan, TO INTERFACE reth0.80, interface-mode
#     |  lab static route 198.18.128.0/24 next-hop 172.16.80.201
#   xpf-mouse-target 172.16.80.201 (WAN fixture, eth0; forwards during the
#     cell via dummy xpf-lab12809 MTU 1200 routing 198.18.128.0/24)
#
# The oversized DF echo (IP 1400) traverses the non-zone SNAT scope
# (observed on the fixture as src 172.16.80.8), cannot leave the fixture's
# 1200-MTU leg, and the fixture kernel generates a real frag-needed to
# 172.16.80.8 quoting the translated packet. The client-side capture must
# show that error arriving dst 10.0.61.102 with the embedded quote reading
# `10.0.61.102 > 198.18.128.1` — full reverse translation.
#
# DESTRUCTIVE: deletes the standing zone-scoped catch-all (`rule snat`
# under lan-to-wan) for the cell so the non-zone rule-set is the SOLE
# registrar of 172.16.80.8 — otherwise the zone row would register the
# address regardless and prove nothing. Internet-bound LAN traffic loses
# its catch-all for the cell's duration (~1 min, under the cluster lock).
# Restore is verified by sorted display-set compare (rule ORDER inside a
# rule-set is not part of the compared invariant; see restore_config).
#
# Strict Tri-State Exit Discipline (#8244):
#   Exit 0:  PASS  (frag-needed delivered, outer dst AND embedded quote
#                   reverse-translated, every attribution leg observed)
#   Exit 1:  FAIL  (positive defect evidence: untranslated leak, bad
#                   checksum, or delivery absent/translated-not with every
#                   other leg proven — the #12085 regression signature)
#   Exit 2/3: VOID (an attribution leg was missing; no claim)
#
# Usage:
#   ./test/incus/wire-nat-frag-needed.sh                # live (cluster lock)
#   ./test/incus/wire-nat-frag-needed.sh --selftest     # hermetic verdicts
#   ./test/incus/wire-nat-frag-needed.sh --fixture t.tsv
#
# Fixture format: one line of space-separated k=v pairs (probe_offered
# snat_observed error_generated control_offered control_observed
# error_delivered translated_quote untranslated_leaks mtu_confirmed
# cksum_bad).
set -uo pipefail

MODE=live
FIXTURE=""
while (($#)); do
    case "$1" in
    --selftest) MODE=selftest ;;
    --fixture)
        MODE=fixture
        FIXTURE="${2:-}"
        shift
        ;;
    -h|--help) sed -n '1,/^set -uo/p' "$0"; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
    esac
    shift
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/incus/wire-gate-lib.sh
source "${SCRIPT_DIR}/wire-gate-lib.sh"

if [[ "$MODE" == selftest ]]; then
    pass=0
    fail=0
    check() {
        local label="$1" want_v="$2" want_rc="$3"; shift 3
        local out rc v
        out=$(wire_nat_frag_needed_verdict "$@")
        rc=$?
        v=$(awk '{print $3}' <<<"$out")
        if [[ "$v" == "$want_v" && "$rc" == "$want_rc" && "$out" == WIRE_GATE\ wire_nat_frag_needed\ * ]]; then
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
    # probe snat gen ctl_off ctl_obs delivered quote leaks mtu cksum
    check "delivered+translated frag-needed passes" PASS 0 3 3 3 2 2 3 3 0 3 0
    check "untranslated quote leak fails" FAIL 1 3 3 3 2 2 3 3 1 3 0
    check "raw error addressed to the NAT address fails" FAIL 1 3 3 3 2 2 0 0 1 0 0
    check "delivery absent with all legs proven is the regression FAIL" FAIL 1 3 3 3 2 2 0 0 0 0 0
    check "delivered but quote untranslated is FAIL" FAIL 1 3 3 3 2 2 3 0 0 3 0
    check "bad checksum fails" FAIL 1 3 3 3 2 2 3 3 0 3 1
    check "no SNAT observation is env-void" VOID 2 3 0 3 2 2 3 3 0 3 0
    check "no generated error is env-void" VOID 2 3 3 0 2 2 3 3 0 3 0
    check "control not observed is capture-blind" VOID 2 3 3 3 2 0 3 3 0 3 0
    check "no probes offered is under-sampled" VOID 2 0 3 3 2 2 3 3 0 3 0
    check "malformed input is harness VOID" VOID 2 3 x 3 2 2 3 3 0 3 0
    echo "  wire-nat-frag-needed selftest: $pass passed, $fail failed"
    [[ "$fail" -eq 0 && "$pass" -gt 0 ]] || exit 1
    exit 0
fi

if [[ "$MODE" == fixture ]]; then
    [[ -n "$FIXTURE" && -f "$FIXTURE" ]] || { echo "usage: $0 --fixture <transcript.tsv>" >&2; exit 2; }
    eval "$(wire_parse_transcript "$FIXTURE")" || true
    wire_nat_frag_needed_verdict \
        "${probe_offered:-x}" "${snat_observed:-x}" "${error_generated:-x}" \
        "${control_offered:-x}" "${control_observed:-x}" "${error_delivered:-x}" \
        "${translated_quote:-x}" "${untranslated_leaks:-x}" "${mtu_confirmed:-x}" \
        "${cksum_bad:-x}"
    exit $?
fi

# ── live cell ─────────────────────────────────────────────────────────
# shellcheck source=test/incus/cluster-cell.sh
source "${SCRIPT_DIR}/cluster-cell.sh"
xpf_enter_destructive_cluster_cell "wire-nat-frag-needed #12809" "$0" "$@"
# shellcheck source=test/incus/cluster-env.sh
source "${SCRIPT_DIR}/cluster-env.sh"

INCUS_REMOTE="${INCUS_REMOTE:-loss}"
NODE="${NODE:-${FW0:-xpf-userspace-fw0}}"
CLIENT_REF="${CLUSTER_LAN_HOST:-${INCUS_REMOTE}:cluster-userspace-host}"
UNTRUST_HOST="${UNTRUST_HOST:-xpf-mouse-target}"
UNTRUST_REF="${INCUS_REMOTE}:${UNTRUST_HOST}"
CLIENT_IFACE="${CLIENT_IFACE:-eth0}"
TARGET_IFACE="${TARGET_IFACE:-eth0}"

# Lab fixture constants. E is reth0.80's address — preflight-asserted
# against the live config below, not trusted. The probe is sized between
# the fixture leg (1200) and the transit MTU (1500): 28 + 1372 = 1400.
EGRESS_ADDR="${EGRESS_ADDR:-172.16.80.8}"
TARGET_IP="${TARGET_IP:-172.16.80.201}"
LAB_DST_NET="${LAB_DST_NET:-198.18.128.0/24}"
LAB_DST="${LAB_DST:-198.18.128.1}"
DUMMY="${DUMMY:-xpf-lab12809}"
DUMMY_MTU="${DUMMY_MTU:-1200}"
PROBE_PAYLOAD="${PROBE_PAYLOAD:-1372}"
RULESET="${RULESET:-lab-12809}"
STEP_TIMEOUT="${STEP_TIMEOUT:-90}"

SG="sg incus-admin -c"

run_cli() { $SG "incus exec ${NODE} -- bash -lc 'cli'"; }
cli_show() { printf '%s\nexit\n' "$1" | run_cli; }
snapshot() { cli_show "show configuration $1 | display set" 2>&1 | sed -n '/^set /p'; }

fail_void() {
    WIRE_GATE_FINAL_OUT="WIRE_GATE wire_nat_frag_needed VOID reason=$1 probe_offered=0 snat_observed=0 error_generated=0 control_offered=0 control_observed=0 error_delivered=0 translated_quote=0 untranslated_leaks=0 mtu_confirmed=0 cksum_bad=0"
    WIRE_GATE_FINAL_RC=3
    exit 3
}

sort_lines() { LC_ALL=C sort; }

RESTORE_NEEDED=0
TARGET_SETUP=0
PREV_FWD=""
BASE_NAT=""
BASE_RT=""
CCAP_PID=""; TCAP_PID=""
CLIENT_CAP="/tmp/xpf-wire-nfn-client.cap"
TARGET_CAP="/tmp/xpf-wire-nfn-target.cap"
RESTORE_OK=1

# cli_config <name> <printf-format block> — commit and require success.
cli_config() {
    local name="$1" block="$2"
    local log="/tmp/xpf-wire-nfn-${name}.log"
    printf '%b' "$block" | $SG "incus exec ${NODE} -- bash -lc 'cli'" >"$log" 2>&1 || {
        echo "[$name] cli invocation failed:" >&2
        tail -5 "$log" >&2 || true
        return 1
    }
    grep -q 'commit complete' "$log"
}

restore_config() {
    ((RESTORE_NEEDED)) || return 0
    cli_config restore "configure\nrollback 0\ndelete security nat source rule-set ${RULESET}\ndelete routing-options static route ${LAB_DST_NET}\nset security nat source rule-set lan-to-wan rule snat match source-address 0.0.0.0/0\nset security nat source rule-set lan-to-wan rule snat then source-nat interface\ncommit check\ncommit\nexit\nquit\n" || RESTORE_OK=0
    # Sorted compare: restoring `rule snat` by delete+re-add lands it after
    # snat6 rather than between pool-snat and snat6. Rule order inside this
    # rule-set cannot change semantics here (pool-snat matches a source
    # range nothing else in the set matches and is v4-only; snat6 is
    # v6-only), so order is explicitly NOT part of the restored invariant;
    # membership is.
    [[ "$(snapshot 'security nat source' | sort_lines)" == "$(printf '%s\n' "$BASE_NAT" | sort_lines)" ]] || RESTORE_OK=0
    [[ "$(snapshot 'routing-options static' | sort_lines)" == "$(printf '%s\n' "$BASE_RT" | sort_lines)" ]] || RESTORE_OK=0
    RESTORE_NEEDED=0
}

teardown_target() {
    ((TARGET_SETUP)) || return 0
    $SG "incus exec ${UNTRUST_REF} -- ip route del ${LAB_DST_NET} dev ${DUMMY}" >/dev/null 2>&1 || true
    $SG "incus exec ${UNTRUST_REF} -- ip link del ${DUMMY}" >/dev/null 2>&1 || true
    if [[ -n "$PREV_FWD" ]]; then
        # shellcheck disable=SC2034 # read via the WIRE_GATE_RESTORE_OK_REF nameref
        $SG "incus exec ${UNTRUST_REF} -- sysctl -qw net.ipv4.ip_forward=${PREV_FWD}" >/dev/null 2>&1 || RESTORE_OK=0
    fi
    TARGET_SETUP=0
}

cleanup() {
    trap '' EXIT INT TERM
    for pid in "${CCAP_PID}" "${TCAP_PID}"; do
        [[ -n "$pid" ]] && kill "$pid" >/dev/null 2>&1 || true
    done
    $SG "incus exec ${UNTRUST_REF} -- pkill -f '[t]cpdump.*icmp and host ${EGRESS_ADDR}'" >/dev/null 2>&1 || true
    $SG "incus exec ${CLIENT_REF} -- pkill -f '[t]cpdump.*icmp and src host ${TARGET_IP}'" >/dev/null 2>&1 || true
    teardown_target
    restore_config
    [[ -n "$CCAP_PID" ]] && wait "$CCAP_PID" >/dev/null 2>&1 || true
    [[ -n "$TCAP_PID" ]] && wait "$TCAP_PID" >/dev/null 2>&1 || true
    CCAP_PID=""; TCAP_PID=""
}
WIRE_GATE_CLEANUP_FN=cleanup
WIRE_GATE_RESTORE_OK_REF=RESTORE_OK
WIRE_GATE_RESTORE_VOID='WIRE_GATE wire_nat_frag_needed VOID reason=harness-void probe_offered=0 snat_observed=0 error_generated=0 control_offered=0 control_observed=0 error_delivered=0 translated_quote=0 untranslated_leaks=0 mtu_confirmed=0 cksum_bad=0'
wire_gate_signal_abort() { trap '' INT TERM; fail_void harness-void; }
trap wire_gate_finalize EXIT
trap wire_gate_signal_abort INT TERM

# ── preflight ────────────────────────────────────────────────────────
for host in "$NODE" "$CLIENT_REF" "$UNTRUST_REF"; do
    $SG "incus list ${INCUS_REMOTE}: --format csv -c n -f name" 2>/dev/null | grep -qx "${host##*:}" || fail_void env-void
done

BASE_NAT="$(snapshot 'security nat source')"
BASE_RT="$(snapshot 'routing-options static')"
BASE_FLOW="$(snapshot 'security flow')"
BASE_IF="$(snapshot 'interfaces reth0')"

[[ "$BASE_NAT" == *"set security nat source rule-set lan-to-wan rule snat then source-nat interface"* ]] || fail_void env-void
[[ "$BASE_NAT" != *"${RULESET}"* ]] || fail_void env-void
[[ "$BASE_RT" != *"${LAB_DST_NET}"* ]] || fail_void env-void
[[ "$BASE_FLOW" == *"set security flow allow-embedded-icmp"* ]] || fail_void env-void
[[ "$BASE_IF" == *"set interfaces reth0 unit 80 family inet address ${EGRESS_ADDR}/24"* ]] || fail_void env-void

CLIENT_IP="$($SG "incus exec ${CLIENT_REF} -- bash -lc 'ip -o -4 addr show ${CLIENT_IFACE}'" 2>/dev/null | sed -n 's/.* inet \([0-9.]*\).*/\1/p' | head -1)"
[[ "$CLIENT_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail_void env-void

$SG "incus exec ${CLIENT_REF} -- bash -lc 'command -v ping && command -v tcpdump'" >/dev/null 2>&1 || fail_void no-prober
$SG "incus exec ${UNTRUST_REF} -- bash -lc 'command -v tcpdump && command -v ip'" >/dev/null 2>&1 || fail_void no-prober
PREV_FWD="$($SG "incus exec ${UNTRUST_REF} -- cat /proc/sys/net/ipv4/ip_forward" 2>/dev/null | tr -d '[:space:]')"
[[ "$PREV_FWD" =~ ^[01]$ ]] || fail_void env-void
[[ -z "$($SG "incus exec ${UNTRUST_REF} -- ip route show ${LAB_DST_NET}" 2>/dev/null)" ]] || fail_void env-void
$SG "incus exec ${UNTRUST_REF} -- ip link show ${DUMMY}" >/dev/null 2>&1 && fail_void env-void

# Baseline liveness: the client reaches the WAN fixture through the
# standing zone-scoped SNAT before the cell changes anything.
$SG "incus exec ${CLIENT_REF} -- ping -c 1 -W 2 ${TARGET_IP}" >/dev/null 2>&1 || fail_void env-void

esc() { printf '%s' "$1" | sed 's/\./\\./g'; }
E_RE="$(esc "$EGRESS_ADDR")"
TARGET_RE="$(esc "$TARGET_IP")"
CLIENT_RE="$(esc "$CLIENT_IP")"
DST_RE="$(esc "$LAB_DST")"

# ── fixture: non-zone rule-set becomes the sole registrar ────────────
RESTORE_NEEDED=1
cli_config mutate "configure\nrollback 0\ndelete security nat source rule-set lan-to-wan rule snat\nset security nat source rule-set ${RULESET} from zone lan\nset security nat source rule-set ${RULESET} to interface reth0.80\nset security nat source rule-set ${RULESET} rule probe match source-address ${CLIENT_IP}/32\nset security nat source rule-set ${RULESET} rule probe then source-nat interface\nset routing-options static route ${LAB_DST_NET} next-hop ${TARGET_IP}\ncommit check\ncommit\nexit\nquit\n" || fail_void harness-void

TARGET_SETUP=1
$SG "incus exec ${UNTRUST_REF} -- sysctl -qw net.ipv4.ip_forward=1" >/dev/null 2>&1 || fail_void harness-void
$SG "incus exec ${UNTRUST_REF} -- ip link add ${DUMMY} type dummy" >/dev/null 2>&1 || fail_void harness-void
$SG "incus exec ${UNTRUST_REF} -- ip link set dev ${DUMMY} mtu ${DUMMY_MTU} up" >/dev/null 2>&1 || fail_void harness-void
$SG "incus exec ${UNTRUST_REF} -- ip route replace ${LAB_DST_NET} dev ${DUMMY}" >/dev/null 2>&1 || fail_void harness-void
sleep 3

# ── captures + probes ────────────────────────────────────────────────
rm -f "$CLIENT_CAP" "$TARGET_CAP"
$SG "incus exec ${UNTRUST_REF} -- timeout ${STEP_TIMEOUT} tcpdump -i ${TARGET_IFACE} -nn -tt -vv -s 0 icmp and host ${EGRESS_ADDR}" >"$TARGET_CAP" 2>&1 &
TCAP_PID=$!
$SG "incus exec ${CLIENT_REF} -- timeout ${STEP_TIMEOUT} tcpdump -i ${CLIENT_IFACE} -nn -tt -vv -s 0 icmp and src host ${TARGET_IP}" >"$CLIENT_CAP" 2>&1 &
CCAP_PID=$!
sleep 2

# Control: normal-size echo through the SAME non-zone rule-set; its reply
# proves the capture window, the transit path, and reverse translation.
CTRL_OUT="$($SG "incus exec ${CLIENT_REF} -- ping -c 2 -W 2 ${TARGET_IP}" 2>&1 || true)"
# Probe: oversized DF echo toward the small-MTU leg behind the fixture.
PROBE_OUT="$($SG "incus exec ${CLIENT_REF} -- ping -c 3 -W 2 -M do -s ${PROBE_PAYLOAD} ${LAB_DST}" 2>&1 || true)"
sleep 2

$SG "incus exec ${UNTRUST_REF} -- pkill -f '[t]cpdump.*icmp and host ${EGRESS_ADDR}'" >/dev/null 2>&1 || true
$SG "incus exec ${CLIENT_REF} -- pkill -f '[t]cpdump.*icmp and src host ${TARGET_IP}'" >/dev/null 2>&1 || true
kill "$TCAP_PID" "$CCAP_PID" >/dev/null 2>&1 || true
wait "$TCAP_PID" >/dev/null 2>&1 || true
wait "$CCAP_PID" >/dev/null 2>&1 || true
TCAP_PID=""; CCAP_PID=""

# ── metrics ──────────────────────────────────────────────────────────
count() { grep -cE "$1" "$2" 2>/dev/null || true; }
tx_count() { grep -oE '[0-9]+ packets transmitted' <<<"$1" | head -1 | grep -oE '[0-9]+' || true; }

PROBE_OFFERED="$(tx_count "$PROBE_OUT")"
CONTROL_OFFERED="$(tx_count "$CTRL_OUT")"
SNAT_OBSERVED="$(count "^[[:space:]]*${E_RE} > ${DST_RE}: ICMP echo request" "$TARGET_CAP")"
ERROR_GENERATED="$(count "^[[:space:]]*${TARGET_RE} > ${E_RE}: .*unreachable - need to frag" "$TARGET_CAP")"
ERROR_DELIVERED="$(count "^[[:space:]]*${TARGET_RE} > ${CLIENT_RE}: .*unreachable - need to frag" "$CLIENT_CAP")"
TRANSLATED_QUOTE="$(count "^[[:space:]]*${CLIENT_RE} > ${DST_RE}: ICMP echo request" "$CLIENT_CAP")"
RAW_AT_CLIENT="$(count "^[[:space:]]*${TARGET_RE} > ${E_RE}: .*unreachable - need to frag" "$CLIENT_CAP")"
UNTRANSLATED_EMBED="$(count "^[[:space:]]*${E_RE} > ${DST_RE}: ICMP echo request" "$CLIENT_CAP")"
UNTRANSLATED_LEAKS=$((RAW_AT_CLIENT + UNTRANSLATED_EMBED))
MTU_CONFIRMED="$(count "^[[:space:]]*${TARGET_RE} > ${CLIENT_RE}: .*need to frag \(mtu ${DUMMY_MTU}\)" "$CLIENT_CAP")"
CONTROL_OBSERVED="$(count "^[[:space:]]*${TARGET_RE} > ${CLIENT_RE}: ICMP echo reply" "$CLIENT_CAP")"
# Loose corruption sweep, matching the other wire gates: any bad-checksum
# line in either capture counts. The helper computes checksums in software
# on this path, so a kernel-generated error quoting the helper's frame
# should not carry a bad checksum; if one fires, the capture (echoed into
# the run log and kept at the paths above) is the review artifact.
CKSUM_BAD="$(grep -hE 'bad cksum|bad checksum' "$CLIENT_CAP" "$TARGET_CAP" 2>/dev/null | grep -cE 'bad cksum|bad checksum' || true)"

# Evidence for the run log: the exact lines the verdict rests on.
echo "── #12809 evidence (client ${CLIENT_IP}, egress ${EGRESS_ADDR}, dst ${LAB_DST}) ──"
echo "[target-side capture: ${TARGET_CAP}]"
grep -E "^[[:space:]]*(${E_RE}|${TARGET_RE}) > " "$TARGET_CAP" 2>/dev/null | head -14 || true
echo "[client-side capture: ${CLIENT_CAP}]"
grep -E "unreachable|echo reply|> ${DST_RE}: ICMP echo request" "$CLIENT_CAP" 2>/dev/null | head -18 || true
echo "[probe] ${PROBE_OUT}"

WIRE_GATE_FINAL_OUT="$(wire_nat_frag_needed_verdict "$PROBE_OFFERED" "$SNAT_OBSERVED" "$ERROR_GENERATED" "$CONTROL_OFFERED" "$CONTROL_OBSERVED" "$ERROR_DELIVERED" "$TRANSLATED_QUOTE" "$UNTRANSLATED_LEAKS" "$MTU_CONFIRMED" "$CKSUM_BAD")"
WIRE_GATE_FINAL_RC=$?
exit "$WIRE_GATE_FINAL_RC"
