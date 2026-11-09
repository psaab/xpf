#!/usr/bin/env bash
#
# #8259 — provision the mouse-probe target service container. A second
# address on that container does not by itself make a mouse-latency verdict
# host-attributable.
#
# THE PROBLEM THIS EXISTS FOR. In the original loss setup, mice and elephants
# shared `172.16.80.200`. The loaded cell adds ~8.6 Gbit/s to the same host
# whose service time is inside every mouse sample, so loaded/idle could not
# separate firewall queueing from target-host service. #8467 returns
# VOID-NOT-ATTRIBUTABLE when target strings are equal. Differing strings clear
# that equality guard only; they do not establish distinct target hosts.
#
# It could not be made to differ at the time: the standing target was
# then believed to be external lab hardware with no handle from here.
# #16213 corrected that record — the container carried v4 .200, while v6
# ::200 was external. #18576 later found the external v6 box also answers
# ARP for v4 .200, making it dual-held. This script creates a managed target
# container; in the default loss fixture, .201 and .202 both terminate on
# xpf-mouse-target, so it is not separate from the current iperf target.
# WHAT IT BUILDS. An Incus service container on the selected remote, with an
# SR-IOV VF on the selected PF/VLAN and the grid documented by
# `target-services.sh`: per-class iperf3 servers on 5200-5211, TCP echo
# daemons on 6200-6211 and port 7, plus #18679's UDP sequence/translated
# identity echo on port 6201. Harnesses may use it as either target; different
# addresses on this container do not create distinct target hosts.
# #19022: the UDP echo answers from the address each datagram arrived on
# (IP_PKTINFO), so a probe to the .202 alias is not answered from .201.
# WHO SERVES 5200-5211 IS DECLARED, NOT INFERRED: MOUSE_TARGET_IPERF_PROVIDER
# (cluster env; default `units`). `units` (loss) installs and enables
# mouse-iperf3@52xx as before. `socket` (tcp, udp) is for a target that serves
# those ports itself through socket-activated iperf3@52xx.socket units, which
# are hand-provisioned lab state (no script here installs them; the refusal
# prints the restore command). There `up` installs no mouse-iperf3 unit. It
# first REFUSES, changing nothing, unless every port has a listener on the
# target's v4 address. It then stands down our own leftover units by exact
# name (a failed disable of an existing unit refuses) and checks again. If a
# port died, our unit was serving it, so it puts those units back as they were
# and refuses. Two review rounds of a runtime port-ownership classifier kept
# finding new edge cases (orphans, address coverage, enabled-runtime units),
# so the provider is a per-cluster fact. The runtime checks are listener
# presence and our own units' state.
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
# instance, and every unit it owns is `enable --now` (with the `socket`
# provider it owns no mouse-iperf3 units, #19022), so this is safe to run
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
# #19022: who serves iperf3 5200-5211 on this target, declared per cluster
# (cluster-env.sh; tcp/udp env files set `socket`). See the header.
MOUSE_TARGET_IPERF_PROVIDER="${MOUSE_TARGET_IPERF_PROVIDER:-units}"

IPERF_PORTS=(5200 5201 5202 5203 5204 5205 5206 5207 5208 5209 5210 5211)

inc() { incus "$@"; }
ref="${INCUS_REMOTE}:${MOUSE_TARGET_NAME}"

usage() {
    cat <<USAGE
${0##*/} — provision the #8259 mouse-probe target container

  up       create (if absent) and reconcile the instance and its services
  status   report the instance, its VLAN-80 address, and the service grid
  destroy  delete the instance

Environment: MOUSE_TARGET_NAME MOUSE_TARGET_V4 MOUSE_TARGET_V6
             MOUSE_TARGET_PF MOUSE_TARGET_VLAN MOUSE_TARGET_IMAGE INCUS_REMOTE
             TARGET_ALIAS_V4 (default 172.16.80.202; empty disables)
             MOUSE_TARGET_IPERF_PROVIDER=units|socket (default units; who
             serves 5200-5211: mouse-iperf3 units, or the target's own
             iperf3@<port>.socket units, which \`up\` only verifies)
             MOUSE_TARGET_CLAIM_PROBE=skip (skip the #18576 claim probe;
             use only when no control address can answer, and say why;
             recorded in mouse-addr.service and shown by \`status\`)

\`up\` and \`destroy\` take the cluster lock (cluster-cell.sh); \`status\` does not.
The lock is the one XPF_CLUSTER_LOCK/OWNER/EPOCH name, else the LOSS lock.
For the tcp or udp target, export that cluster's tuple (CLAUDE.md lock
table) along with BPFRX_CLUSTER_ENV, e.g. for tcp (udp: tcp -> udp):
  XPF_CLUSTER_LOCK=/var/worktrees/.cache/tmpdir/xpf-cluster-tcp.lock
  XPF_CLUSTER_OWNER=/var/worktrees/.cache/tmpdir/xpf-cluster-tcp.owner
  XPF_CLUSTER_EPOCH=/var/worktrees/.cache/tmpdir/xpf-cluster-state/epoch-tcp
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
            echo "WARNING: claim probe for new ${addr} skipped (MOUSE_TARGET_CLAIM_PROBE=skip); recorded in mouse-addr.service" >&2
            # The unit carries this marker for as long as it pins the
            # address, and `status` prints it, so a skip outlives the run's
            # log (wire-zone-matrix deletes its setup log on success).
            CLAIM_SKIP_MARKERS+="# claim-probe: SKIPPED for ${addr} by MOUSE_TARGET_CLAIM_PROBE=skip at $(date -u +%FT%TZ)"$'\n'
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

# target_v4_addrs: the v4 addresses this host pins (MOUSE_TARGET_V4, plus the
# TARGET_ALIAS_V4 alias on VLAN 80 when it differs). They are the same set
# mouse-addr.service pins and harnesses dial (#16213, #18576).
target_v4_addrs() {
    local addrs=("$MOUSE_TARGET_V4")
    if [[ -n "$TARGET_ALIAS_V4" && "$TARGET_ALIAS_V4" != "$MOUSE_TARGET_V4" \
          && "$MOUSE_TARGET_VLAN" == "80" ]]; then
        addrs+=("$TARGET_ALIAS_V4")
    fi
    printf '%s\n' "${addrs[*]}"
}

# IPERF_LISTENER_SCRIPT runs on the target (POSIX sh). For each port it
# prints "<port> <local address>" per listening TCP socket, then
# "<port> queried". A port without the "queried" line could not be listed
# (`ss` missing or failed). No ownership is inferred (#19022).
IPERF_LISTENER_SCRIPT="$(cat <<'LISTENERS'
# iperf-listeners (#19022)
command -v ss >/dev/null 2>&1 || exit 3
for p in "$@"; do
    rows="$(ss -Hltn "sport = :$p" 2>/dev/null)" || continue
    printf '%s\n' "$rows" | while read -r _state _recvq _sendq laddr _rest; do
        [ -n "$laddr" ] && echo "$p ${laddr%:*}"
    done
    echo "$p queried"
done
LISTENERS
)"

# iperf_listener_scan: sorts IPERF_PORTS into LISTEN_OK (a listener on every
# target v4 address: 0.0.0.0, the dual-stack `*`, or each address itself),
# LISTEN_MISSING (listed, no such listener) and LISTEN_UNKNOWN (not listed).
iperf_listener_scan() {
    local table p addrs a ok want
    LISTEN_OK=() LISTEN_MISSING=() LISTEN_UNKNOWN=()
    table="$(inc exec "$ref" -- sh -c "$IPERF_LISTENER_SCRIPT" sh "${IPERF_PORTS[@]}" 2>/dev/null)"
    read -r -a want <<<"$(target_v4_addrs)"
    for p in "${IPERF_PORTS[@]}"; do
        if ! grep -qx "${p} queried" <<<"$table"; then
            LISTEN_UNKNOWN+=("$p")
            continue
        fi
        addrs=" $(awk -v p="$p" '$1 == p && $2 != "queried" { printf "%s ", $2 }' <<<"$table")"
        ok=1
        if [[ "$addrs" != *" 0.0.0.0 "* && "$addrs" != *" * "* ]]; then
            for a in "${want[@]}"; do
                [[ "$addrs" == *" ${a} "* ]] || ok=0
            done
        fi
        if [[ "$ok" == 1 ]]; then LISTEN_OK+=("$p"); else LISTEN_MISSING+=("$p"); fi
    done
}

# MOUSE_UNIT_STATE_SCRIPT runs on the target (POSIX sh): one line per port,
# "<port> <LoadState> <UnitFileState or -> <ActiveState>", for OUR unit
# mouse-iperf3@<port>.service only. LoadState=not-found means absent.
MOUSE_UNIT_STATE_SCRIPT="$(cat <<'UNITSTATE'
# unit-state (#19022)
for p in "$@"; do
    st="$(systemctl show -p LoadState -p UnitFileState -p ActiveState "mouse-iperf3@$p.service" 2>/dev/null)" || continue
    l=""; f=""; a=""
    for kv in $st; do
        case "$kv" in
            LoadState=*) l="${kv#*=}" ;;
            UnitFileState=*) f="${kv#*=}" ;;
            ActiveState=*) a="${kv#*=}" ;;
        esac
    done
    [ -n "$l" ] && [ -n "$a" ] && echo "$p $l ${f:--} $a"
done
UNITSTATE
)"

# mouse_unit_scan: UNIT_LOAD / UNIT_FILE / UNIT_ACTIVE (by port) for our
# mouse-iperf3 units; UNIT_UNKNOWN lists ports whose state was not read.
mouse_unit_scan() {
    local table p line _p l f a
    UNIT_UNKNOWN=()
    declare -gA UNIT_LOAD=() UNIT_FILE=() UNIT_ACTIVE=()
    table="$(inc exec "$ref" -- sh -c "$MOUSE_UNIT_STATE_SCRIPT" sh "${IPERF_PORTS[@]}" 2>/dev/null)"
    for p in "${IPERF_PORTS[@]}"; do
        line="$(awk -v p="$p" '$1 == p { print; exit }' <<<"$table")"
        read -r _p l f a <<<"$line"
        if [[ -z "${l:-}" || -z "${a:-}" ]]; then
            UNIT_UNKNOWN+=("$p")
            continue
        fi
        UNIT_LOAD[$p]="$l" UNIT_FILE[$p]="$f" UNIT_ACTIVE[$p]="$a"
    done
}

# socket_restore_hint: how to bring back the iperf3@<port>.socket units a
# socket-provider target serves 5200-5211 with. Nothing in this repo
# provisions them (hand-provisioned lab state; the template ships in the
# iperf3 package), so the refusal says exactly what to run (#19022).
socket_restore_hint() {
    printf '%s' "A socket-provider target serves 5200-5211 through the iperf3 package's iperf3@<port>.socket units, which no script in this repo provisions (hand-provisioned lab state). Restore them with: incus exec ${ref} -- sh -c 'apt-get install -y iperf3 && for p in \$(seq 5200 5211); do systemctl enable --now iperf3@\$p.socket; done'. If this target is meant to run mouse-iperf3 units instead, declare MOUSE_TARGET_IPERF_PROVIDER=units in its cluster env file, not as a one-shot override (#19022)"
}

# claim_skip_markers: the "# claim-probe: SKIPPED ..." lines of the
# installed mouse-addr.service, if any (#18576).
claim_skip_markers() {
    inc exec "$ref" -- sh -c \
        "grep '^# claim-probe: SKIPPED' /etc/systemd/system/mouse-addr.service 2>/dev/null || true" 2>/dev/null
}

do_up() {
    local echo_source_hash echo_installed_hash echo_content_changed=false
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
    local alias_line="" held pins=("$MOUSE_TARGET_V4")
    if [[ -n "$TARGET_ALIAS_V4" && "$TARGET_ALIAS_V4" != "$MOUSE_TARGET_V4" \
          && "$MOUSE_TARGET_VLAN" == "80" ]]; then
        alias_line="ExecStart=/sbin/ip addr replace ${TARGET_ALIAS_V4}/24 dev eth0"
        pins+=("$TARGET_ALIAS_V4")
    fi
    held="$(inc exec "$ref" -- ip -4 addr show dev eth0 2>/dev/null \
        | awk '$1 == "inet" { split($2, a, "/"); print a[1] }')"
    # Carry forward skip markers for addresses the new unit still pins: a
    # held address is never re-probed, so its skip stays the only record.
    local prev_marker pinned
    CLAIM_SKIP_MARKERS=""
    while IFS= read -r prev_marker; do
        [[ "$prev_marker" == "# claim-probe: SKIPPED for "* ]] || continue
        for pinned in "${pins[@]}"; do
            if [[ "$prev_marker" == "# claim-probe: SKIPPED for ${pinned} "* ]]; then
                CLAIM_SKIP_MARKERS+="${prev_marker}"$'\n'
            fi
        done
    done < <(claim_skip_markers)
    claim_probe_new_v4 "$held" "${pins[@]}" || return 1
    inc exec "$ref" -- sh -c "cat > /etc/systemd/system/mouse-addr.service <<'UNIT'
[Unit]
${CLAIM_SKIP_MARKERS}Description=#8259 pin the mouse target's VLAN-80 address
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/ip addr replace ${MOUSE_TARGET_V4}/24 dev eth0
${alias_line:+${alias_line}
}ExecStart=/sbin/ip -6 addr replace ${MOUSE_TARGET_V6}/64 dev eth0
ExecStart=/sbin/ip link set eth0 up

[Install]
WantedBy=multi-user.target
UNIT"

    echo_source_hash="$(sha256sum "${SCRIPT_DIR}/mouse-target-echo.py")" || return 1
    echo_source_hash="${echo_source_hash%% *}"
    echo_installed_hash="$(inc exec "$ref" -- sha256sum /usr/local/bin/mouse-echo.py 2>/dev/null || true)"
    echo_installed_hash="${echo_installed_hash%% *}"
    [[ "$echo_source_hash" == "$echo_installed_hash" ]] || echo_content_changed=true

    echo "installing the echo daemon"
    inc file push "${SCRIPT_DIR}/mouse-target-echo.py" "${ref}/usr/local/bin/mouse-echo.py" || return 1
    inc exec "$ref" -- chmod +x /usr/local/bin/mouse-echo.py
    inc exec "$ref" -- sh -c "cat > /etc/systemd/system/mouse-echo.service <<'UNIT'
[Unit]
Description=#8259 TCP echo plus #18679 HA UDP sequence/NAT identity echo
After=network.target

[Service]
ExecStart=/usr/bin/python3 /usr/local/bin/mouse-echo.py
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
UNIT"

    if [[ "$MOUSE_TARGET_IPERF_PROVIDER" == units ]]; then
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
    fi

    inc exec "$ref" -- systemctl daemon-reload
    inc exec "$ref" -- systemctl enable --now mouse-addr.service >/dev/null 2>&1
    inc exec "$ref" -- systemctl enable mouse-echo.service >/dev/null 2>&1
    if [[ "$echo_content_changed" == true ]]; then
        # An active process keeps the old Python source after file push. Restart
        # only when its content changed so live TCP echo flows are undisturbed
        # by a no-op `up`.
        inc exec "$ref" -- systemctl restart mouse-echo.service >/dev/null 2>&1 || return 1
    else
        inc exec "$ref" -- systemctl start mouse-echo.service >/dev/null 2>&1 || return 1
    fi
    # #18576: re-run the address unit so a CHANGED address set applies now.
    # mouse-addr is a RemainAfterExit oneshot, so `enable --now` on a host
    # where it already ran is a no-op: a new alias would wait for the next
    # reboot (`status` below reported the new .202 alias MISSING right after
    # `up`). Every line is `ip addr replace` / `link set up`, which is
    # idempotent and never removes an address, so the restart is safe on a
    # live target.
    inc exec "$ref" -- systemctl restart mouse-addr.service >/dev/null 2>&1 || return 1
    case "$MOUSE_TARGET_IPERF_PROVIDER" in
        units)
            for p in "${IPERF_PORTS[@]}"; do
                inc exec "$ref" -- systemctl enable --now "mouse-iperf3@${p}" >/dev/null 2>&1
            done ;;
        socket)
            # #19022: this target serves 5200-5211 itself (tcp/udp:
            # iperf3@52xx.socket). A mouse-iperf3 unit there only
            # crash-loops on the busy port. Order matters: VERIFY first and
            # refuse with nothing changed; then stand down our leftovers;
            # then verify AGAIN, because a port our own unit was serving
            # (a units-served target declared `socket`) dies when it is
            # stood down. In that case put back exactly what was stood down
            # and refuse.
            iperf_listener_scan
            if [[ ${#LISTEN_MISSING[@]} -gt 0 || ${#LISTEN_UNKNOWN[@]} -gt 0 ]]; then
                echo "REFUSE: MOUSE_TARGET_IPERF_PROVIDER=socket, but ${ref} has no TCP listener on $(target_v4_addrs) for port(s) ${LISTEN_MISSING[*]:-none}${LISTEN_UNKNOWN[*]:+; listeners could not be listed for port(s) ${LISTEN_UNKNOWN[*]}}; nothing was changed. $(socket_restore_hint)" >&2
                return 1
            fi
            mouse_unit_scan
            if [[ ${#UNIT_UNKNOWN[@]} -gt 0 ]]; then
                echo "REFUSE: could not read the state of mouse-iperf3@<port>.service on ${ref} for port(s) ${UNIT_UNKNOWN[*]}; nothing was changed (#19022)" >&2
                return 1
            fi
            local p stood=() cleanup_failed=()
            for p in "${IPERF_PORTS[@]}"; do
                # Stand down only a unit that is enabled or not inactive. An
                # absent one (not-found: no file state, inactive) and one
                # already stood down (disabled, inactive) need nothing, and
                # `disable` on an absent unit fails, so it is never tried.
                [[ "${UNIT_FILE[$p]}" == enabled* || "${UNIT_ACTIVE[$p]}" != inactive ]] || continue
                if inc exec "$ref" -- systemctl disable --now "mouse-iperf3@${p}.service" >/dev/null 2>&1; then
                    stood+=("$p")
                    if [[ "${UNIT_ACTIVE[$p]}" == failed ]]; then
                        inc exec "$ref" -- systemctl reset-failed "mouse-iperf3@${p}.service" >/dev/null 2>&1 || true
                    fi
                else
                    cleanup_failed+=("mouse-iperf3@${p}.service")
                fi
            done
            iperf_listener_scan
            if [[ ${#LISTEN_MISSING[@]} -gt 0 || ${#LISTEN_UNKNOWN[@]} -gt 0 ]]; then
                for p in "${stood[@]}"; do
                    if [[ "${UNIT_FILE[$p]}" == enabled* ]]; then
                        inc exec "$ref" -- systemctl enable "mouse-iperf3@${p}.service" >/dev/null 2>&1 || true
                    fi
                    case "${UNIT_ACTIVE[$p]}" in
                        active|activating|reloading)
                            inc exec "$ref" -- systemctl start "mouse-iperf3@${p}.service" >/dev/null 2>&1 || true ;;
                    esac
                done
                echo "REFUSE: MOUSE_TARGET_IPERF_PROVIDER=socket, but port(s) ${LISTEN_MISSING[*]:-}${LISTEN_UNKNOWN[*]:+ ${LISTEN_UNKNOWN[*]}} lost their listener on ${ref} when mouse-iperf3 was stood down: mouse-iperf3 units serve this target, not iperf3@<port>.socket. Put back what was stood down (${stood[*]/#/mouse-iperf3@}). $(socket_restore_hint)" >&2
                return 1
            fi
            if [[ ${#cleanup_failed[@]} -gt 0 ]]; then
                echo "REFUSE: could not stand down existing unit(s) ${cleanup_failed[*]} on ${ref} (systemctl disable --now failed); left as is, it would compete with iperf3@<port>.socket (#19022)" >&2
                return 1
            fi
            echo "iperf3 provider socket: all ${#IPERF_PORTS[@]} ports have a listener on $(target_v4_addrs); no mouse-iperf3 installed${stood[*]:+, stood down: ${stood[*]/#/mouse-iperf3@}} (#19022)" ;;
    esac

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
    # #19022: report the DECLARED provider and, per port, whether a listener
    # exists on the target's v4 address. No ownership is inferred.
    iperf_listener_scan
    if [[ ${#LISTEN_UNKNOWN[@]} -gt 0 ]]; then
        echo "iperf3:   provider ${MOUSE_TARGET_IPERF_PROVIDER}; listeners unknown for port(s) ${LISTEN_UNKNOWN[*]} (could not list them on ${ref})"
    else
        echo "iperf3:   provider ${MOUSE_TARGET_IPERF_PROVIDER}; ${#LISTEN_OK[@]} / ${#IPERF_PORTS[@]} per-class ports have a listener on $(target_v4_addrs)"
    fi
    if [[ ${#LISTEN_MISSING[@]} -gt 0 ]]; then
        echo "iperf3:   NO listener on $(target_v4_addrs) for port(s) ${LISTEN_MISSING[*]}"
    fi
    # Our own units, as master reported them: a listener held by an orphan
    # behind a failed unit (the #16213 shape) shows here, not above.
    local active=0 off=()
    mouse_unit_scan
    for p in "${IPERF_PORTS[@]}"; do
        [[ -n "${UNIT_ACTIVE[$p]:-}" ]] || continue
        [[ "${UNIT_ACTIVE[$p]}" == active ]] && active=$((active + 1))
        if [[ "$MOUSE_TARGET_IPERF_PROVIDER" == units ]]; then
            [[ "${UNIT_ACTIVE[$p]}" == active && "${UNIT_FILE[$p]}" == enabled* ]] \
                || off+=("${p}(${UNIT_ACTIVE[$p]},${UNIT_FILE[$p]})")
        elif [[ "${UNIT_LOAD[$p]}" == loaded && ( "${UNIT_FILE[$p]}" == enabled* || "${UNIT_ACTIVE[$p]}" != inactive ) ]]; then
            off+=("${p}(${UNIT_ACTIVE[$p]},${UNIT_FILE[$p]})")
        fi
    done
    if [[ ${#UNIT_UNKNOWN[@]} -gt 0 ]]; then
        echo "iperf3:   mouse-iperf3 unit state unknown for port(s) ${UNIT_UNKNOWN[*]}"
    elif [[ "$MOUSE_TARGET_IPERF_PROVIDER" == units ]]; then
        echo "iperf3:   ${active} / ${#IPERF_PORTS[@]} mouse-iperf3 units active"
        if [[ ${#off[@]} -gt 0 ]]; then
            echo "iperf3:   mouse-iperf3 not active+enabled: ${off[*]}"
        fi
    elif [[ ${#off[@]} -gt 0 ]]; then
        echo "iperf3:   leftover mouse-iperf3 units (enabled or not inactive; \`up\` stands them down): ${off[*]}"
    fi
    echo "echo:     $(inc exec "$ref" -- systemctl is-active mouse-echo 2>/dev/null)"
    # #18576: a claim probe skipped for a pinned address stays visible.
    local skips
    skips="$(claim_skip_markers)"
    if [[ -n "$skips" ]]; then
        while IFS= read -r line; do echo "claim:    ${line#\# }"; done <<<"$skips"
    else
        # Say only what was checked: `up` probes NEW addresses only, so an
        # address held when `up` ran was never probed by it.
        echo "claim:    no claim-probe skip recorded (addresses already held when \`up\` ran are not probed; test-connectivity's claim cell checks IPERF_TARGET4 every run)"
    fi
    echo
    echo "Point a harness at it with:  MOUSE_TARGET_V4=${MOUSE_TARGET_V4}"
    echo "#8467 compares target strings only; different addresses clear its"
    echo "equality-based VOID-NOT-ATTRIBUTABLE guard, not host attribution."
    echo "Default loss fixture: .201/.202 share xpf-mouse-target; a non-VOID"
    echo "result is not host-attributable. A separate target host is required."
    echo "For other clusters or overrides, verify host placement before"
    echo "treating a non-VOID result as host-attributable."
}

do_destroy() {
    instance_exists || { echo "${ref}: already absent"; return 0; }
    inc delete --force "$ref"
    echo "${ref}: deleted"
}

case "$MOUSE_TARGET_IPERF_PROVIDER" in
    units|socket) ;;
    *) echo "REFUSE: MOUSE_TARGET_IPERF_PROVIDER must be units or socket, got '${MOUSE_TARGET_IPERF_PROVIDER}' (#19022)" >&2
       exit 2 ;;
esac

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
