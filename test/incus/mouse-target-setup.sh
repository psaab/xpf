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
# It could not be made to differ. `target-services.sh` records why: the
# standing target is external lab hardware, answers ICMP, is not an incus
# instance in any project, accepts no ssh — "there is no handle to run a
# command on it from here" — and the firewall's WAN neighbour table held
# exactly two entries, the target and the upstream router. There was nowhere
# to move a flow to.
#
# There is now. This script creates one.
#
# WHAT IT BUILDS. An incus container on the loss remote with an SR-IOV VF on
# the WAN PF tagged into VLAN 80, pinned at 172.16.80.201, running the same
# service grid `target-services.sh` documents as the contract: per-class
# iperf3 servers on 5200-5211 and per-class TCP echo daemons on 6200-6211,
# plus port 7. It is a drop-in second target, not a mouse-only appliance, so
# any harness can point either of its two knobs at it.
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
USAGE
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
    inc exec "$ref" -- sh -c \
        'apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq iperf3 python3 tcpdump >/dev/null 2>&1' \
        || echo "WARN: package install returned non-zero; continuing to service setup"

    echo "installing the address unit"
    inc exec "$ref" -- sh -c "cat > /etc/systemd/system/mouse-addr.service <<'UNIT'
[Unit]
Description=#8259 pin the mouse target's VLAN-80 address
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/ip addr replace ${MOUSE_TARGET_V4}/24 dev eth0
ExecStart=/sbin/ip -6 addr replace ${MOUSE_TARGET_V6}/64 dev eth0
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
    local active
    active="$(inc exec "$ref" -- systemctl list-units 'mouse-iperf3@*' --state=active --no-legend 2>/dev/null | wc -l)"
    echo "iperf3:   ${active} / ${#IPERF_PORTS[@]} per-class servers active"
    echo "echo:     $(inc exec "$ref" -- systemctl is-active mouse-echo 2>/dev/null)"
    echo
    echo "Point a harness at it with:  MOUSE_TARGET_V4=${MOUSE_TARGET_V4}"
    echo "The #8467 attributability check passes as soon as it differs from"
    echo "ELEPHANT_TARGET_V4 (default ${IPERF_TARGET4:-172.16.80.200})."
}

do_destroy() {
    instance_exists || { echo "${ref}: already absent"; return 0; }
    inc delete --force "$ref"
    echo "${ref}: deleted"
}

case "${1:-status}" in
    up) do_up ;;
    status) do_status ;;
    destroy) do_destroy ;;
    -h|--help|help) usage ;;
    *) usage; exit 2 ;;
esac
