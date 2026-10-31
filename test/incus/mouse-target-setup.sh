#!/usr/bin/env bash
#
# #8259 — provision the SECOND VLAN-80 target, so a mouse-latency verdict can
# be attributed.
#
# THE PROBLEM THIS EXISTS FOR. Every mouse-latency and fairness harness sends
# mice and elephants to the SAME host, `172.16.80.200`. The loaded cell adds
# ~8.6 Gbit/s of receive load to the very host whose service time is inside
# every mouse sample, so the loaded/idle ratio cannot separate firewall
# queueing from target-host service. #8467 made the gate say so —
# `VOID-NOT-ATTRIBUTABLE` rather than a PASS or FAIL it cannot support — and
# recorded that the check "passes the moment the two targets differ".
#
# It could not be made to differ at the time: the standing target was
# then believed to be external lab hardware with no handle from here.
# #16213 corrected that record — 172.16.80.200 lives on THIS host (see
# the #16213 header below); only the v6 ::200 is external. What was
# missing was a second incus-managed host to move a flow to.
#
# There is now. This script creates one.
#
# WHAT IT BUILDS. An incus container on the loss remote with an SR-IOV VF on
# the WAN PF tagged into VLAN 80, running the same service grid
# `target-services.sh` documents as the contract: per-class
# iperf3 servers on 5200-5211 and per-class TCP echo daemons on 6200-6211,
# plus port 7. It is a drop-in second target, not a mouse-only appliance, so
# any harness can point either of its two knobs at it.
#
# THE PRIMARY TARGET'S ADDRESS IS DECLARED HERE (#16213). On the
# standing loss cluster, the elephant / iperf target that
# `IPERF_TARGET4` (loss-userspace-cluster.env) and
# `target-services.sh`'s $TARGET_V4 point at lives on THIS host
# (xpf-mouse-target) as a second address beside the pinned
# 172.16.80.201. It was 172.16.80.200, and nothing in the tree owned
# it: it was a hand `ip addr add`, so any recreate or reboot silently
# dropped it while harnesses kept measuring `.200` (the observed
# UP->gone flap). #18576: the external v6 box also answers ARP for v4
# .200, so loss now targets 172.16.80.202, which only this host holds.
# The alias is declarative: TARGET_ALIAS_V4 (default 172.16.80.202)
# names it, and when it differs from this host's pinned v4 on VLAN 80,
# mouse-addr.service pins BOTH in one oneshot. A host whose pinned v4
# already IS the primary emits no duplicate line, and hosts on other
# VLANs (the VLAN-50 DMZ prober reusing this script) never claim it.
# The v6 ::200 address is NOT aliased: it belongs to external
# hardware (it DAD-failed as a duplicate when tried on a container),
# so dual-stack smokes reach v4 here and v6 on that hardware; the
# split is recorded, not papered over with a dead v6 (see
# target-services.sh).
#
# WHY A VF AND NOT A BRIDGE. The firewall's own WAN interface is an SR-IOV VF
# on the same PF, UNTAGGED — the firewall does the VLAN 50/80 tagging itself
# (`reth0.80`). A VF tagged 80 by the hypervisor lands on the same L2 as
# `ge-0-0-2.80`, which is what puts the new host in the firewall's neighbour
# table alongside the existing target rather than behind another hop.
#
# IDEMPOTENT. Re-running reconciles: it will not recreate an existing
# instance, and every service is `enable --now`, so this is safe to run
# against a half-built host.
#
# CAPACITY, checked before this was written rather than assumed: the WAN PF
# exposes 32 VFs and the two firewalls use two. Taking a third does not
# contend with anything.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
[[ -f "${SCRIPT_DIR}/cluster-env.sh" ]] && source "${SCRIPT_DIR}/cluster-env.sh" 2>/dev/null || true
# shellcheck source=ha-assurance-lib.sh
source "${SCRIPT_DIR}/ha-assurance-lib.sh"   # ha_target_claim_probe (#18576)

INCUS_REMOTE="${INCUS_REMOTE:-loss}"
MOUSE_TARGET_NAME="${MOUSE_TARGET_NAME:-xpf-mouse-target}"
MOUSE_TARGET_V4="${MOUSE_TARGET_V4:-172.16.80.201}"
MOUSE_TARGET_V6="${MOUSE_TARGET_V6:-2001:559:8585:80::201}"
# The PF the firewalls' WAN VFs come from. Their VF is UNTAGGED; ours is
# tagged 80 because we terminate on that VLAN rather than routing between
# several.
MOUSE_TARGET_PF="${MOUSE_TARGET_PF:-mlx0}"
MOUSE_TARGET_VLAN="${MOUSE_TARGET_VLAN:-80}"
MOUSE_TARGET_IMAGE="${MOUSE_TARGET_IMAGE:-images:debian/trixie}"
# #16213: the primary elephant target's v4, declarative alias of this host
# when it differs from MOUSE_TARGET_V4 (the loss-cluster case: .202 beside
# .201, #18576; cluster-env.sh derives it from IPERF_TARGET4). Owned here so
# `up` (the unit), `status`, and `target-services.sh` agree on whether
# the alias is one this host must carry. An explicit override wins. EMPTY
# disables the alias everywhere, so the default uses `-`, not `:-`
# (cluster-env.sh does the same, #18576).
TARGET_ALIAS_V4="${TARGET_ALIAS_V4-172.16.80.202}"
# #18576: a DEPRECATED alias (loss: .200, which the external v6 box also
# answers ARP for). `up` keeps its pin only while this host ALREADY holds it,
# so a container restart does not strand consumers that still name it, and
# never claims it anew. Empty (the default) means none. The expiry is in the
# loss env.
TARGET_ALIAS_V4_DEPRECATED="${TARGET_ALIAS_V4_DEPRECATED-}"

IPERF_PORTS=(5200 5201 5202 5203 5204 5205 5206 5207 5208 5209 5210 5211)

inc() { incus "$@"; }
ref="${INCUS_REMOTE}:${MOUSE_TARGET_NAME}"

usage() {
    cat <<USAGE
${0##*/} — provision the #8259 second VLAN-80 target

  up       create (if absent) and reconcile the instance and its services
  status   report the instance, its VLAN-80 address, and the service grid
  destroy  delete the instance

Environment: MOUSE_TARGET_NAME MOUSE_TARGET_V4 MOUSE_TARGET_V6
             MOUSE_TARGET_PF MOUSE_TARGET_VLAN MOUSE_TARGET_IMAGE INCUS_REMOTE
             TARGET_ALIAS_V4 (default 172.16.80.202; empty disables)
             TARGET_ALIAS_V4_DEPRECATED (kept only while held; default none)
             MOUSE_TARGET_CLAIM_PROBE=skip (skip the #18576 claim probe;
             use only when no control address can answer, and say why)

\`up\` and \`destroy\` take the cluster lock (cluster-cell.sh); \`status\` does not.
USAGE
}

# claim_probe_new_v4 <held-addresses> <address>...
# #18576: before `up` pins a v4 address this host does not hold yet, probe
# it from this host's eth0 (RFC 5227, ha_target_claim_probe) and REFUSE if
# any other MAC answers. On 2026-10-24 a run with another cluster's values
# rewrote this unit to tcp's .210, and `up` now restarts the unit, so a
# conflicting address would be claimed at once. The cluster's own address
# on the VLAN (WAN_GW80_4 on 80, DMZ_GW4 on 50) is the positive control.
# If it does not answer, "nobody else answered" is not evidence, and `up`
# refuses too.
claim_probe_new_v4() {
    local held="$1" addr out mac others control
    shift
    case "$MOUSE_TARGET_VLAN" in
        80) control="${WAN_GW80_4:-}" ;;
        50) control="${DMZ_GW4:-}" ;;
        *) control="" ;;
    esac
    for addr in "$@"; do
        grep -qxF -- "$addr" <<<"$held" && continue
        if [[ "${MOUSE_TARGET_CLAIM_PROBE:-}" == skip ]]; then
            echo "WARNING: claim probe for new ${addr} skipped (MOUSE_TARGET_CLAIM_PROBE=skip)" >&2
            continue
        fi
        if [[ -z "$control" ]]; then
            echo "REFUSE: no control address for VLAN ${MOUSE_TARGET_VLAN}, so new ${addr} cannot be claim-probed (#18576)" >&2
            return 1
        fi
        inc exec "$ref" -- ip link set eth0 up >/dev/null 2>&1 || true
        if ! out="$(ha_target_claim_probe "$ref" "$addr" "$control" eth0 2>&1)"; then
            echo "REFUSE: the claim probe for new ${addr} could not run on ${ref}: ${out}" >&2
            return 1
        fi
        mac="$(awk '$1 == "iface" { print tolower($3); exit }' <<<"$out")"
        others="$(awk -v a="$addr" -v m="$mac" '$1 == "reply" && $2 == a && tolower($3) != m { print tolower($3) }' <<<"$out" | sort -u | tr '\n' ' ')"
        if [[ -z "$mac" ]]; then
            echo "REFUSE: the claim probe for new ${addr} printed no iface line: ${out}" >&2
            return 1
        fi
        if [[ -n "$others" ]]; then
            echo "REFUSE: ${addr} is already answered for by ${others}on VLAN ${MOUSE_TARGET_VLAN}; not pinning it on ${ref} (#18576)" >&2
            return 1
        fi
        if ! awk -v c="$control" '$1 == "reply" && $2 == c && $4 == "probe" { f = 1 } END { exit !f }' <<<"$out"; then
            echo "REFUSE: control ${control} did not answer the claim probe for new ${addr}, so no other holder is not evidence (#18576)" >&2
            return 1
        fi
        echo "claim probe: new ${addr} has no other holder (control ${control} answered)"
    done
}

instance_exists() { inc info "$ref" >/dev/null 2>&1; }

do_up() {
    if ! instance_exists; then
        echo "creating ${ref} from ${MOUSE_TARGET_IMAGE}"
        inc init "$MOUSE_TARGET_IMAGE" "$ref" || return 1
    else
        echo "${ref} already exists"
    fi

    if ! inc config device get "$ref" eth0 nictype >/dev/null 2>&1; then
        inc config device add "$ref" eth0 nic \
            nictype=sriov "parent=${MOUSE_TARGET_PF}" "vlan=${MOUSE_TARGET_VLAN}" || return 1
    fi

    inc start "$ref" >/dev/null 2>&1 || true
    # The instance may take a moment to present eth0.
    for _ in $(seq 1 20); do
        inc exec "$ref" -- ip link show eth0 >/dev/null 2>&1 && break
        sleep 1
    done

    echo "installing packages"
    # tcpdump/iperf3/python3 are the prober contract (#16328): a failed
    # install must fail `up`, not WARN-and-continue into a capture-blind
    # gate that only discovers the missing binary at preflight.
    inc exec "$ref" -- sh -c \
        'apt-get update -qq && apt-get install -y -qq iperf3 python3 tcpdump' || return 1
    inc exec "$ref" -- sh -c 'command -v tcpdump && command -v iperf3 && command -v python3' >/dev/null || return 1

    echo "installing the address unit"
    # #16213: TARGET_ALIAS_V4 (the primary elephant target, 172.16.80.202
    # on loss since #18576, .200 before) used to be a hand `ip addr add` on
    # this host with no owner — a recreate or reboot dropped it while
    # harnesses kept measuring `.200`. Declare it in the same oneshot: on VLAN 80, when
    # the alias differs from the pinned v4, pin BOTH. A host whose
    # pinned v4 already IS the primary (tcp/udp wire targets, whose env
    # sets MOUSE_TARGET_V4 to their cluster's iperf target) emits no
    # duplicate, and non-VLAN-80 hosts (the VLAN-50 DMZ prober reusing
    # this script) never claim a VLAN-80 address. The v6 ::200 is
    # external (DAD duplicate) and is never emitted (see header).
    local alias_line="" dep_line="" held pins=("$MOUSE_TARGET_V4")
    if [[ -n "$TARGET_ALIAS_V4" && "$TARGET_ALIAS_V4" != "$MOUSE_TARGET_V4" \
          && "$MOUSE_TARGET_VLAN" == "80" ]]; then
        alias_line="ExecStart=/sbin/ip addr replace ${TARGET_ALIAS_V4}/24 dev eth0"
        pins+=("$TARGET_ALIAS_V4")
    fi
    held="$(inc exec "$ref" -- ip -4 addr show dev eth0 2>/dev/null \
        | awk '$1 == "inet" { split($2, a, "/"); print a[1] }')"
    # #18576: the deprecated alias is kept (pinned) only while held, and is
    # never probed or claimed anew: it is dual-held by design until it expires.
    if [[ -n "$TARGET_ALIAS_V4_DEPRECATED" && "$TARGET_ALIAS_V4_DEPRECATED" != "$MOUSE_TARGET_V4" \
          && "$TARGET_ALIAS_V4_DEPRECATED" != "$TARGET_ALIAS_V4" && "$MOUSE_TARGET_VLAN" == "80" ]]; then
        if grep -qxF -- "$TARGET_ALIAS_V4_DEPRECATED" <<<"$held"; then
            dep_line="ExecStart=/sbin/ip addr replace ${TARGET_ALIAS_V4_DEPRECATED}/24 dev eth0"
            echo "deprecated alias ${TARGET_ALIAS_V4_DEPRECATED}: held, pin kept until its expiry (#18576)"
        else
            echo "deprecated alias ${TARGET_ALIAS_V4_DEPRECATED}: not held, not claimed (#18576)"
        fi
    fi
    claim_probe_new_v4 "$held" "${pins[@]}" || return 1
    inc exec "$ref" -- sh -c "cat > /etc/systemd/system/mouse-addr.service <<'UNIT'
[Unit]
Description=#8259 pin the mouse target's VLAN-80 address
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/ip addr replace ${MOUSE_TARGET_V4}/24 dev eth0
${alias_line:+${alias_line}
}${dep_line:+${dep_line}
}ExecStart=/sbin/ip -6 addr replace ${MOUSE_TARGET_V6}/64 dev eth0
ExecStart=/sbin/ip link set eth0 up

[Install]
WantedBy=multi-user.target
UNIT"

    echo "installing the echo daemon"
    inc file push "${SCRIPT_DIR}/mouse-target-echo.py" "${ref}/usr/local/bin/mouse-echo.py" || return 1
    inc exec "$ref" -- chmod +x /usr/local/bin/mouse-echo.py
    inc exec "$ref" -- sh -c "cat > /etc/systemd/system/mouse-echo.service <<'UNIT'
[Unit]
Description=#8259 mouse-latency TCP echo (port 7 and 6200-6211)
After=network.target

[Service]
ExecStart=/usr/bin/python3 /usr/local/bin/mouse-echo.py
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
UNIT"

    echo "installing the per-class iperf3 template"
    inc exec "$ref" -- sh -c "cat > '/etc/systemd/system/mouse-iperf3@.service' <<'UNIT'
[Unit]
Description=#8259 per-class iperf3 server on port %i
After=network.target

[Service]
ExecStart=/usr/bin/iperf3 --server --port %i
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
UNIT"

    inc exec "$ref" -- systemctl daemon-reload
    inc exec "$ref" -- systemctl enable --now mouse-addr.service mouse-echo.service >/dev/null 2>&1
    # #18576: re-run the address unit so a CHANGED address set applies now.
    # mouse-addr is a RemainAfterExit oneshot, so `enable --now` on a host
    # where it already ran is a no-op: a new alias would wait for the next
    # reboot (`status` below reported the new .202 alias MISSING right after
    # `up`). Every line is `ip addr replace` / `link set up`, which is
    # idempotent and never removes an address, so the restart is safe on a
    # live target.
    inc exec "$ref" -- systemctl restart mouse-addr.service >/dev/null 2>&1 || return 1
    for p in "${IPERF_PORTS[@]}"; do
        inc exec "$ref" -- systemctl enable --now "mouse-iperf3@${p}" >/dev/null 2>&1
    done

    do_status
}

do_status() {
    if ! instance_exists; then
        echo "${ref}: ABSENT — run '${0##*/} up'"
        return 1
    fi
    # `incus list <remote>:<name>` does NOT filter — the name has to be a
    # separate argument after the remote, or the listing comes back empty and
    # this line silently reports nothing about a running instance.
    echo "instance: $(inc list "${INCUS_REMOTE}:" "$MOUSE_TARGET_NAME" --format csv -c ns 2>/dev/null | head -1)"
    echo "address:  $(inc exec "$ref" -- ip -br -4 addr show eth0 2>/dev/null | tr -s ' ')"
    # #16213: the declarative alias must be PRESENT (after `up` / reboot),
    # not merely configured: report it, and name a missing one as drift
    # rather than letting the next harness rediscover it as flapping.
    if [[ -n "$TARGET_ALIAS_V4" && "$TARGET_ALIAS_V4" != "$MOUSE_TARGET_V4" \
          && "$MOUSE_TARGET_VLAN" == "80" ]]; then
        if inc exec "$ref" -- ip -4 addr show eth0 2>/dev/null | grep -q "inet ${TARGET_ALIAS_V4}/"; then
            echo "alias:    ${TARGET_ALIAS_V4} present (mouse-addr.service, #16213)"
        else
            echo "alias:    ${TARGET_ALIAS_V4} MISSING — run '${0##*/} up' to re-pin it (mouse-addr.service, #16213)"
        fi
    fi
    local active
    active="$(inc exec "$ref" -- systemctl list-units 'mouse-iperf3@*' --state=active --no-legend 2>/dev/null | wc -l)"
    echo "iperf3:   ${active} / ${#IPERF_PORTS[@]} per-class servers active"
    echo "echo:     $(inc exec "$ref" -- systemctl is-active mouse-echo 2>/dev/null)"
    echo
    echo "Point a harness at it with:  MOUSE_TARGET_V4=${MOUSE_TARGET_V4}"
    echo "The #8467 attributability check passes as soon as it differs from"
    echo "ELEPHANT_TARGET_V4 (default ${IPERF_TARGET4:-172.16.80.202})."
}

do_destroy() {
    instance_exists || { echo "${ref}: already absent"; return 0; }
    inc delete --force "$ref"
    echo "${ref}: deleted"
}

case "${1:-status}" in
    up|destroy)
        # #18576: `up` rewrites and restarts the address unit on a target
        # that every gate measures, and `destroy` deletes it. Both serialize
        # under the cluster lock, the way deploys do (re-entrant inside a
        # held cell, e.g. wire-zone-matrix's DMZ provisioning).
        # shellcheck source=cluster-cell.sh
        source "${SCRIPT_DIR}/cluster-cell.sh"
        xpf_enter_destructive_cluster_cell "mouse-target-setup $1 ${ref}" "$0" "$@"
        if [[ "$1" == up ]]; then do_up; else do_destroy; fi ;;
    status) do_status ;;
    -h|--help|help) usage ;;
    *) usage; exit 2 ;;
esac
