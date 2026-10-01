#!/usr/bin/env bash
#
# #1827 PR-2 — two-upstream FBF steering smoke (loss userspace cluster).
#
# Applies test/incus/fbf-two-upstream-config.set atomically on the RG0
# primary, validates the filter-based-forwarding composition end to end
# at the observable surfaces, then restores the pre-test config via
# `rollback 1 | commit`.
#
# What it verifies:
#   1. commit accepts the FBF composition (forwarding instance + FBF filter +
#      ip-monitoring preferred-route INTO the forwarding instance);
#   2. IPv4 and IPv6 kernel tables discovered from the PBR rule band each hold
#      the ISP-B default, and neither main table contains an ISP-B default;
#   3. DSCP-af31 pings from the LAN host increment matching steering-term
#      counters, while unmarked controls do not. Both receive replies at the
#      managed VLAN-80 peer, whose capture must show the marked next-hop's
#      Ethernet source differs from the unmarked main-table source;
#   4. `show services ip-monitoring status` lists the fbf-fallback policy.
#
# What it does NOT prove (single-provider lab, plan §9): true
# dual-provider failure modes, dual-public-IP SNAT, throughput under
# genuine dual-path load. Path-divergence under uplink failure is the
# smoke-runner's manual step: blackhole 172.16.80.1 upstream and watch
# the fbf-fallback policy repoint ISP-B.inet.0 at 172.16.50.1.
#
# Usage:
#   ./test/incus/test-fbf-steering.sh [loss:xpf-userspace-fw0]
#   FBF_EGRESS_HOST=loss:xpf-mouse-target  # managed VLAN-80 capture peer
#     provision it with ./test/incus/mouse-target-setup.sh up (installs tcpdump)
#   FBF_PING_DST=172.16.80.201 FBF_PING_DST6=2001:559:8585:80::201 ...
#   FBF_LAN_HOST=loss:cluster-userspace-host  # LAN traffic source
#
set -euo pipefail

TARGET="${1:-loss:xpf-userspace-fw0}"
[[ $# -le 1 ]] || { shift; echo "unexpected extra arguments: $*" >&2; exit 2; }
LAN_HOST="${FBF_LAN_HOST:-loss:cluster-userspace-host}"
ISP_B_GW4="${FBF_ISP_B_GW4:-172.16.80.1}"
ISP_B_GW6="${FBF_ISP_B_GW6:-2001:559:8585:80::1}"
EGRESS_HOST="${FBF_EGRESS_HOST:-${INCUS_REMOTE:-loss}:${MOUSE_TARGET_NAME:-xpf-mouse-target}}"
EGRESS_IFACE="${FBF_EGRESS_IFACE:-eth0}"
PING_DST4="${FBF_PING_DST:-${MOUSE_TARGET_V4:-172.16.80.201}}"
PING_DST6="${FBF_PING_DST6:-${MOUSE_TARGET_V6:-2001:559:8585:80::201}}"
PING_COUNT=5
MIN_ECHO_REPLIES=3
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/fbf-two-upstream-config.set"
REMOTE_SETS="/tmp/fbf-two-upstream.set"
REMOTE_CAPTURE_LOG="/tmp/fbf-steering-$$.log"
REMOTE_CAPTURE_PID="/tmp/fbf-steering-$$.pid"
PEER_CAPTURE_ACTIVE=0
PEER_CAPTURE_REQUIRED=0
CLI=/usr/local/sbin/cli

# #6936: the CLI-transcript marker gate (#6440) and the FBF verdict helpers.
# The `cos_` prefix is historical — those helpers are CLI-generic, and reusing
# them is deliberate: a second copy of the marker list could drift out of step
# with cmd/cli, and only one copy is pinned by
# cmd/cli/cos_apply_markers_6440_test.go.
# shellcheck source=./cos-apply-lib.sh
. "${SCRIPT_DIR}/cos-apply-lib.sh"
# shellcheck source=./fbf-steering-lib.sh
. "${SCRIPT_DIR}/fbf-steering-lib.sh"

info() { echo "==> $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

[[ -f "$CONFIG_FILE" ]] || fail "cannot find $CONFIG_FILE"

cleanup_peer_capture() {
    if (( PEER_CAPTURE_ACTIVE )); then
        incus exec "$EGRESS_HOST" -- sh -c \
            "pid=\$(cat '$REMOTE_CAPTURE_PID' 2>/dev/null || true); if [ -n \"\$pid\" ]; then kill -INT \"\$pid\" 2>/dev/null || true; fi; sleep 1" \
            >/dev/null 2>&1 || true
        PEER_CAPTURE_ACTIVE=0
    fi
    if (( PEER_CAPTURE_REQUIRED )); then
        incus exec "$EGRESS_HOST" -- rm -f "$REMOTE_CAPTURE_LOG" "$REMOTE_CAPTURE_PID" >/dev/null 2>&1 || true
        PEER_CAPTURE_REQUIRED=0
    fi
}

start_peer_capture() {
    local capture_filter
    capture_filter="(icmp and dst host ${PING_DST4}) or (icmp6 and dst host ${PING_DST6})"
    PEER_CAPTURE_REQUIRED=1
    incus exec "$EGRESS_HOST" -- rm -f "$REMOTE_CAPTURE_LOG" "$REMOTE_CAPTURE_PID" >/dev/null 2>&1 || true
    PEER_CAPTURE_ACTIVE=1
    if ! incus exec "$EGRESS_HOST" -- sh -c \
        "timeout 60 tcpdump -i '$EGRESS_IFACE' -e -nn -vv -l '$capture_filter' > '$REMOTE_CAPTURE_LOG' 2>&1 & echo \$! > '$REMOTE_CAPTURE_PID'; sleep 1; pid=\$(cat '$REMOTE_CAPTURE_PID' 2>/dev/null || true); [ -n \"\$pid\" ] && kill -0 \"\$pid\"" \
        >/dev/null 2>&1; then
        fail "could not start VLAN-80 peer capture on $EGRESS_HOST:$EGRESS_IFACE"
    fi
    sleep 2
}

stop_peer_capture() {
    if (( PEER_CAPTURE_ACTIVE )); then
        incus exec "$EGRESS_HOST" -- sh -c \
            "pid=\$(cat '$REMOTE_CAPTURE_PID' 2>/dev/null || true); if [ -n \"\$pid\" ]; then kill -INT \"\$pid\" 2>/dev/null || true; fi; sleep 1" \
            >/dev/null 2>&1 || true
        PEER_CAPTURE_ACTIVE=0
    fi
}

cleanup_files=()
trap 'cleanup_peer_capture; rm -f "${cleanup_files[@]}"' EXIT
CAPTURE_FILTER="(icmp and dst host ${PING_DST4}) or (icmp6 and dst host ${PING_DST6})"
if ! incus exec "$EGRESS_HOST" -- sh -c 'command -v tcpdump >/dev/null 2>&1'; then
    fail "VLAN-80 peer capture unavailable at $EGRESS_HOST; run test/incus/mouse-target-setup.sh up first"
fi
if ! incus exec "$EGRESS_HOST" -- tcpdump -i "$EGRESS_IFACE" -d "$CAPTURE_FILTER" >/dev/null 2>&1; then
    fail "cannot compile VLAN-80 peer capture filter on $EGRESS_HOST:$EGRESS_IFACE"
fi
peer_gateway_mac() {
    local family="$1" gateway="$2" neighbors
    incus exec "$EGRESS_HOST" -- ping "-${family}" -n -c 1 -W 1 "$gateway" >/dev/null 2>&1 || true
    neighbors="$(incus exec "$EGRESS_HOST" -- ip "-${family}" neigh show to "$gateway" dev "$EGRESS_IFACE" 2>/dev/null || true)"
    awk '{
        for (i = 1; i < NF; i++) if ($i == "lladdr") { print tolower($(i+1)); exit }
    }' <<<"$neighbors"
}

GATEWAY_MAC4="$(peer_gateway_mac 4 "$ISP_B_GW4")"
GATEWAY_MAC6="$(peer_gateway_mac 6 "$ISP_B_GW6")"
MAC_RE='^[[:xdigit:]][[:xdigit:]](:[[:xdigit:]][[:xdigit:]]){5}$'
[[ "$GATEWAY_MAC4" =~ $MAC_RE ]] || fail "cannot resolve IPv4 ISP-B gateway MAC on peer $EGRESS_HOST"
[[ "$GATEWAY_MAC6" =~ $MAC_RE ]] || fail "cannot resolve IPv6 ISP-B gateway MAC on peer $EGRESS_HOST"
info "VLAN-80 peer ISP-B gateway MACs: IPv4=$GATEWAY_MAC4 IPv6=$GATEWAY_MAC6"

SETS_TMP="$(mktemp)"
cleanup_files+=("$SETS_TMP")
grep -E '^set ' "$CONFIG_FILE" > "$SETS_TMP"
if [[ "$ISP_B_GW4" != "172.16.80.1" ]]; then
    info "Overriding ISP-B v4 gateway: 172.16.80.1 -> $ISP_B_GW4"
    sed -i "s/172\.16\.80\.1\b/${ISP_B_GW4}/g" "$SETS_TMP"
fi
if [[ "$ISP_B_GW6" != "2001:559:8585:80::1" ]]; then
    info "Overriding ISP-B v6 gateway: 2001:559:8585:80::1 -> $ISP_B_GW6"
    sed -i "s|2001:559:8585:80::1|${ISP_B_GW6}|g" "$SETS_TMP"
fi

restore() {
    info "Restoring pre-test config (rollback 1 + commit)..."
    # #6936: this gated on the session's exit status (`<<EOF || echo WARNING`).
    # The piped-stdin CLI is a REPL that prints `error: ...` and still exits 0
    # (#6440), so that warning could NEVER fire — a rollback that did not land
    # announced nothing and left this SHARED cluster on the FBF test config for
    # the next lane to measure against. cos_rollback_one verifies the CLI's own
    # "configuration rolled back" + "commit complete" markers.
    cos_rollback_one "$TARGET" \
        || echo "WARNING: rollback did NOT land — inspect $TARGET manually" >&2
}

metric_value() {
    local family="$1" filter="$2"
    # Family labels distinguish inet and inet6; filter names are separate in
    # the fixture (`fbf-steer` versus `fbf-steer6`).
    incus exec "$TARGET" -- sh -c \
        "curl -s 127.0.0.1:8080/metrics | grep 'xpf_filter_hits_total{' | grep 'family=\"${family}\"' | grep 'filter=\"${filter}\"' | grep 'term=\"to-isp-b\"' | awk '{print \$NF}'" \
        | head -1
}

# ---- Phase 1: atomic apply (commit check, then commit) ----
incus exec "$TARGET" -- rm -f "$REMOTE_SETS" >/dev/null 2>&1 || true
incus file push --mode 0644 "$SETS_TMP" "${TARGET}/${REMOTE_SETS}" >/dev/null

CHECK_OUT="$(mktemp)"; cleanup_files+=("$CHECK_OUT")
info "commit check on $TARGET..."
incus exec "$TARGET" -- "$CLI" > "$CHECK_OUT" 2>&1 <<EOF || true
configure
load merge ${REMOTE_SETS}
commit check
exit
quit
EOF
# #6936/#6440: gate on the CLI's own success MARKERS, not the session exit
# status, which is 0 even when a command inside the session failed. BOTH
# markers are required: a failed `load merge` leaves an EMPTY candidate, and an
# empty candidate checks clean — so `commit check` alone cannot tell "the
# fixture is valid" from "the fixture never loaded".
cos_require_markers "commit check on $TARGET" "$CHECK_OUT" \
    "$COS_MARKER_LOAD_MERGE" "$COS_MARKER_COMMIT_CHECK" \
    || fail "commit check failed (candidate invalid; live state unchanged)"

APPLY_OUT="$(mktemp)"; cleanup_files+=("$APPLY_OUT")
info "committing FBF two-upstream fixture..."
incus exec "$TARGET" -- "$CLI" > "$APPLY_OUT" 2>&1 <<EOF || true
configure
load merge ${REMOTE_SETS}
commit
exit
quit
EOF
# #6936/#6440: as above — the exit status proves nothing. Without this gate a
# commit that never landed let every cell below run against the PRE-TEST
# config, where the ISP-B default is legitimately absent: the smoke would
# report a clean main table having never applied the fixture that could dirty
# it, which is the exact silent under-steer #6936 wants regression cover for.
cos_require_markers "commit on $TARGET" "$APPLY_OUT" \
    "$COS_MARKER_LOAD_MERGE" "$COS_MARKER_COMMIT" \
    || fail "commit failed after commit-check passed"
# From here on, always restore on exit.
trap 'cleanup_peer_capture; restore; rm -f "${cleanup_files[@]}"' EXIT
sleep 3

# ---- Phase 2: kernel-side IPv4 and IPv6 routing ----
info "Discovering ISP-B kernel tables from the PBR ip-rule band..."
NEXTHOPS="$(incus exec "$TARGET" -- ip nexthop show 2>/dev/null || true)"

discover_isp_b_table() {
    local family="$1" gw="$2" label="$3"
    local candidates candidate routes
    PBR_TABLE=""
    PBR_ROUTES=""
    candidates="$(incus exec "$TARGET" -- sh -c \
        "ip -${family} rule show | awk -F'lookup ' '\$1 ~ /^29[0-9][0-9][0-9]:/ {print \$2}'" \
        | tr -d '\r')"
    [[ -n "${candidates//[[:space:]]/}" ]] \
        || fail "no IPv${family} PBR ip rule in the 29000-29999 band (FBF kernel rule missing)"
    info "IPv${family} PBR band candidates: $(echo "$candidates")"

    for candidate in $candidates; do
        routes="$(incus exec "$TARGET" -- ip "-${family}" route show table "$candidate" 2>/dev/null || true)"
        if fbf_table_holds_default "$gw" "$routes" "$NEXTHOPS"; then
            PBR_TABLE="$candidate"
            PBR_ROUTES="$routes"
            break
        fi
    done
    [[ -n "$PBR_TABLE" ]] \
        || fail "no IPv${family} table in the 29000-29999 band ($(echo "$candidates")) holds a default via ${gw} — the FBF rule or kernel route is missing"
    info "$label table $PBR_TABLE holds the ISP-B default: $(grep -m1 '^default' <<<"$PBR_ROUTES")"
}

check_main_table_leak() {
    local family="$1" gw="$2" label="$3" routes verdict
    routes="$(incus exec "$TARGET" -- ip "-${family}" route show default 2>/dev/null || true)"
    verdict="$(fbf_main_default_leak_verdict "$gw" "$routes" "$NEXTHOPS")"
    case "$verdict" in
        PASS\ *) info "$label main table: ${verdict#PASS }" ;;
        *)       fail "$label main table: ${verdict#FAIL }" ;;
    esac
}

discover_isp_b_table 4 "$ISP_B_GW4" IPv4
discover_isp_b_table 6 "$ISP_B_GW6" IPv6
check_main_table_leak 4 "$ISP_B_GW4" IPv4
check_main_table_leak 6 "$ISP_B_GW6" IPv6

# ---- Phase 3: steering-term match, peer capture and ping replies ----
BEFORE4="$(metric_value inet fbf-steer)"; BEFORE4="${BEFORE4:-0}"
BEFORE6="$(metric_value inet6 fbf-steer6)"; BEFORE6="${BEFORE6:-0}"
info "Steering-term hits before: IPv4=$BEFORE4 IPv6=$BEFORE6"
start_peer_capture

run_marked_ping() {
    local family="$1" destination="$2" label="$3" output verdict
    info "Sending $PING_COUNT DSCP-af31 $label pings (tos 0x68) from $LAN_HOST to $destination..."
    output="$(incus exec "$LAN_HOST" -- ping "-${family}" -n -c "$PING_COUNT" -W 2 -Q 0x68 "$destination" 2>&1 || true)"
    verdict="$(fbf_ping_reply_verdict "$MIN_ECHO_REPLIES" "$output")"
    case "$verdict" in
        PASS\ *) info "$label target replies: ${verdict#PASS }" ;;
        *)       fail "$label marked probe to $destination failed: ${verdict#FAIL }" ;;
    esac
}

run_unmarked_control() {
    local family="$1" destination="$2" label="$3"
    info "Sending $PING_COUNT unmarked $label control pings to $destination..."
    incus exec "$LAN_HOST" -- ping "-${family}" -n -c "$PING_COUNT" -W 2 -Q 0 "$destination" >/dev/null 2>&1 || true
}

check_peer_egress() {
    local family="$1" destination="$2" gateway_mac="$3" label="$4" verdict
    verdict="$(fbf_peer_egress_verdict "$family" "$destination" "$gateway_mac" "$MIN_ECHO_REPLIES" "$PEER_CAPTURE_OUTPUT")"
    case "$verdict" in
        PASS\ *) info "$label ISP-B next-hop evidence: ${verdict#PASS }" ;;
        *)       fail "$label egress check failed: ${verdict#FAIL }" ;;
    esac
}

run_marked_ping 4 "$PING_DST4" IPv4
run_marked_ping 6 "$PING_DST6" IPv6
run_unmarked_control 4 "$PING_DST4" IPv4
run_unmarked_control 6 "$PING_DST6" IPv6
sleep 2
stop_peer_capture
PEER_CAPTURE_OUTPUT="$(incus exec "$EGRESS_HOST" -- cat "$REMOTE_CAPTURE_LOG" 2>/dev/null || true)"
check_peer_egress 4 "$PING_DST4" "$GATEWAY_MAC4" IPv4
check_peer_egress 6 "$PING_DST6" "$GATEWAY_MAC6" IPv6
cleanup_peer_capture

AFTER4="$(metric_value inet fbf-steer)"; AFTER4="${AFTER4:-0}"
AFTER6="$(metric_value inet6 fbf-steer6)"; AFTER6="${AFTER6:-0}"

check_steering_delta() {
    local label="$1" before="$2" after="$3" delta max_delta
    delta="$(awk -v a="$after" -v b="$before" 'BEGIN{print a-b}')"
    max_delta=$((PING_COUNT * 2 - 1))
    awk -v d="$delta" -v minimum="$PING_COUNT" 'BEGIN{exit !(d >= minimum)}' \
        || fail "$label steering counter delta $delta < $PING_COUNT — af31 traffic not hitting the FBF term"
    awk -v d="$delta" -v maximum="$max_delta" 'BEGIN{exit !(d <= maximum)}' \
        || fail "$label steering counter delta $delta > $max_delta — unmarked control traffic also steered"
    info "$label steering counter delta $delta (marked traffic only) OK"
}

check_steering_delta IPv4 "$BEFORE4" "$AFTER4"
check_steering_delta IPv6 "$BEFORE6" "$AFTER6"
info "Steering-term hits after: IPv4=$AFTER4 IPv6=$AFTER6"

# ---- Phase 4: ip-monitoring composition ----
STATUS="$(incus exec "$TARGET" -- "$CLI" -c "show services ip-monitoring status" 2>/dev/null || true)"
echo "$STATUS" | grep -q "fbf-fallback" \
    || fail "fbf-fallback policy missing from 'show services ip-monitoring status':
$STATUS"
info "ip-monitoring fbf-fallback policy present:"
echo "$STATUS" | sed 's/^/    /'

info "PASS: FBF two-upstream steering smoke complete for IPv4 and IPv6 (config will be rolled back)"
