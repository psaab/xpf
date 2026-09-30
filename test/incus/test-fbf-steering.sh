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
#   1. commit accepts the FBF composition (forwarding instance + FBF
#      filter + ip-monitoring preferred-route INTO the forwarding
#      instance — the PR-1b rejection lifted in PR-2);
#   2. kernel side of the divergence fix: the ISP-B kernel table
#      (discovered from the PBR ip-rule band 29000-29999) contains the
#      instance default — before PR-2 that table was EMPTY and the
#      instance static leaked into the main table;
#   3. main table is NOT polluted by the ISP-B default;
#   4. steering: DSCP-af31 pings from the LAN host hit the steering
#      term (xpf_filter_hits_total{filter="fbf-steer",term="to-isp-b"}
#      delta > 0) while unmarked pings do not;
#   5. `show services ip-monitoring status` lists the fbf-fallback
#      policy (PASS while the ISP-B gateway answers).
#
# What it does NOT prove (single-provider lab, plan §9): true
# dual-provider failure modes, dual-public-IP SNAT, throughput under
# genuine dual-path load. Path-divergence under uplink failure is the
# smoke-runner's manual step: blackhole 172.16.80.1 upstream and watch
# the fbf-fallback policy repoint ISP-B.inet.0 at 172.16.50.1.
#
# Usage:
#   ./test/incus/test-fbf-steering.sh [loss:xpf-userspace-fw0]
#   FBF_ISP_B_GW4=172.16.80.200 ./test/incus/test-fbf-steering.sh
#     (override when 172.16.80.1 is not a live router — any live
#      VLAN-80 address works as the steering next-hop)
#   FBF_LAN_HOST=loss:cluster-userspace-host  # LAN traffic source
#
set -euo pipefail

TARGET="${1:-loss:xpf-userspace-fw0}"
[[ $# -le 1 ]] || { shift; echo "unexpected extra arguments: $*" >&2; exit 2; }
LAN_HOST="${FBF_LAN_HOST:-loss:cluster-userspace-host}"
ISP_B_GW4="${FBF_ISP_B_GW4:-172.16.80.1}"
# Any destination beyond the firewall works: the steering term matches
# on DSCP, not destination. Default to the ISP-A gateway so the control
# (unmarked) ping also has a live responder.
PING_DST="${FBF_PING_DST:-172.16.50.1}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/fbf-two-upstream-config.set"
REMOTE_SETS="/tmp/fbf-two-upstream.set"
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

cleanup_files=()
trap 'rm -f "${cleanup_files[@]}"' EXIT

SETS_TMP="$(mktemp)"
cleanup_files+=("$SETS_TMP")
grep -E '^set ' "$CONFIG_FILE" > "$SETS_TMP"
if [[ "$ISP_B_GW4" != "172.16.80.1" ]]; then
    info "Overriding ISP-B v4 gateway: 172.16.80.1 -> $ISP_B_GW4"
    sed -i "s/172\.16\.80\.1\b/${ISP_B_GW4}/g" "$SETS_TMP"
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
    # xpf_filter_hits_total{family="inet",filter="fbf-steer",term="to-isp-b"}
    incus exec "$TARGET" -- sh -c \
        "curl -s 127.0.0.1:8080/metrics | grep 'xpf_filter_hits_total{' | grep 'filter=\"fbf-steer\"' | grep 'term=\"to-isp-b\"' | awk '{print \$NF}'" \
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
trap 'restore; rm -f "${cleanup_files[@]}"' EXIT
sleep 3

# ---- Phase 2: kernel side of the divergence fix ----
info "Discovering ISP-B kernel table from the PBR ip-rule band..."
# #6936: enumerate ALL tables in the current PBR band and select by CONTENT,
# not by position: a configured filter can install several rules/tables, and
# only the ISP-B table has the expected default next hop.
PBR_CANDIDATES="$(incus exec "$TARGET" -- sh -c \
    "ip rule show | awk -F'lookup ' '\$1 ~ /^29[0-9][0-9][0-9]:/ {print \$2}'" | tr -d '\r')"
[[ -n "${PBR_CANDIDATES//[[:space:]]/}" ]] \
    || fail "no PBR ip rule in the 29000-29999 band (FBF kernel rule missing)"
info "PBR band candidates: $(echo $PBR_CANDIDATES)"

PBR_TABLE=""
ROUTES=""
for _cand in $PBR_CANDIDATES; do
    _routes="$(incus exec "$TARGET" -- ip route show table "$_cand" 2>/dev/null || true)"
    if fbf_table_holds_default "$ISP_B_GW4" "$_routes"; then
        PBR_TABLE="$_cand"
        ROUTES="$_routes"
        break
    fi
done
[[ -n "$PBR_TABLE" ]] || fail "no table in the 29000-29999 band ($(echo $PBR_CANDIDATES)) holds 'default via ${ISP_B_GW4}' — either FRR table rendering is broken (pre-PR-2 divergence) or the FBF rule never installed"
info "ISP-B table $PBR_TABLE holds the instance default (divergence fix OK): $(grep -m1 '^default' <<<"$ROUTES")"

# #6936: take the route TEXT, not a count. The counting form collapsed
# "no leak" and "the probe returned nothing" onto the same healthy verdict
# (`grep -c` prints 0 and exits 1, so `|| true` is load-bearing; an empty
# substitution then fell through `${MAIN_DEFAULTS:-0}` to 0 = PASS). The
# verdict below is TOTAL and treats a blind probe as a failure, because an
# absence cannot be certified by an instrument that returned no reading.
# Non-empty output doubles as the positive control: this venue always carries
# the ISP-A default, so seeing defaults at all proves the probe read the table.
MAIN_DEFAULTS="$(incus exec "$TARGET" -- ip route show default 2>/dev/null || true)"
LEAK_VERDICT="$(fbf_main_default_leak_verdict "$ISP_B_GW4" "$MAIN_DEFAULTS")"
case "$LEAK_VERDICT" in
    PASS\ *) info "${LEAK_VERDICT#PASS }" ;;
    *)       fail "${LEAK_VERDICT#FAIL }" ;;
esac

# ---- Phase 3: steering counter ----
BEFORE="$(metric_value)"; BEFORE="${BEFORE:-0}"
info "Steering-term hits before: $BEFORE"

info "Sending 5 DSCP-af31 pings (tos 0x68) from $LAN_HOST to $PING_DST..."
incus exec "$LAN_HOST" -- ping -c 5 -W 2 -Q 0x68 "$PING_DST" >/dev/null 2>&1 || true
info "Sending 5 unmarked control pings..."
incus exec "$LAN_HOST" -- ping -c 5 -W 2 "$PING_DST" >/dev/null 2>&1 || true
sleep 2

AFTER="$(metric_value)"; AFTER="${AFTER:-0}"
info "Steering-term hits after: $AFTER"
DELTA="$(awk -v a="$AFTER" -v b="$BEFORE" 'BEGIN{print a-b}')"
awk -v d="$DELTA" 'BEGIN{exit !(d >= 5)}' \
    || fail "steering counter delta $DELTA < 5 — af31 traffic not hitting the FBF term"
awk -v d="$DELTA" 'BEGIN{exit !(d <= 9)}' \
    || fail "steering counter delta $DELTA > 9 — unmarked control traffic also steered"
info "Steering counter delta $DELTA (marked traffic only) OK"

# ---- Phase 4: ip-monitoring composition ----
STATUS="$(incus exec "$TARGET" -- "$CLI" -c "show services ip-monitoring status" 2>/dev/null || true)"
echo "$STATUS" | grep -q "fbf-fallback" \
    || fail "fbf-fallback policy missing from 'show services ip-monitoring status':
$STATUS"
info "ip-monitoring fbf-fallback policy present:"
echo "$STATUS" | sed 's/^/    /'

info "PASS: FBF two-upstream steering smoke complete (config will be rolled back)"
