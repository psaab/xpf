#!/usr/bin/env bash
#
# #16213 — hermetic self-test for the declarative address unit that
# test/incus/mouse-target-setup.sh installs.
#
# The defect it guards is INVISIBLE until a reboot: 172.16.80.200 (the
# elephant / iperf primary until #18576 moved loss to .202) was a hand
# `ip addr add` on xpf-mouse-target
# with no owner, so any recreate/reboot silently dropped it while every
# harness kept measuring `.200` (observed UP->gone). The fix makes
# mouse-addr.service pin BOTH the mouse address and the alias when the
# alias differs on VLAN 80 — and ONLY then: a host whose pinned v4 IS
# the primary (tcp/udp wire targets) must not duplicate it, and the
# VLAN-50 DMZ prober (same script, other VLAN) must never claim a
# VLAN-80 address. The v6 ::200 is external (DAD duplicate) and must
# never be emitted.
#
# Hermetic: `incus` is a recorder stub; nothing touches a cluster. The
# recorded `cat > .../mouse-addr.service` payload is the assertion
# surface — exactly what systemd will run at boot.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUBJECT="${SCRIPT_DIR}/mouse-target-setup.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fails=0
fail() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }
pass() { echo "ok: $*"; }

mkdir -p "${TMP}/bin"
cat > "${TMP}/bin/incus" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "${STUB_INCUS_LOG:?}"
# #18038: with-cluster.sh proves both firewall targets are VMs before the
# cell runs. Keep this hermetic stub on that contract as well: Incus `list
# --format json` returns an array keyed by the instance name.
case "$*" in
  *"--format json"*)
    if [[ "${2:-}" == *: ]]; then name="${3:-}"; else name="${2:-}"; fi
    printf '[{"name":"%s","type":"virtual-machine"}]\n' "$name"
    exit 0 ;;
  *"/proc/sys/kernel/random/boot_id"*) printf '00000000-0000-0000-0000-000000000001\n'; exit 0 ;;
esac
case "$1" in
  info) exit 0 ;;                       # instance exists
  list) echo "xpf-mouse-target,RUNNING"; exit 0 ;;
  config) exit 0 ;;                     # eth0 device already present
  file) exit 0 ;;
  exec)
    shift; shift; [[ "${1:-}" == "--" ]] && shift
    cmd="$*"
    echo "$cmd" >> "${STUB_EXEC_LOG:?}"
    case "$cmd" in
      *"ip link show eth0"*) exit 0 ;;
      *"ip -br -4 addr show"*) echo "eth0 UP 172.16.80.201/24 172.16.80.202/24"; exit 0 ;;
      *"ip -4 addr show"*)
        for a in ${STUB_HELD:-172.16.80.201 172.16.80.202}; do
          echo "    inet ${a}/24 scope global eth0"
        done
        exit 0 ;;
      *"grep '^# claim-probe: SKIPPED'"*)
        # The installed unit's skip markers (#18576), staged per case.
        [[ -n "${STUB_PREV_MARKER:-}" ]] && printf '%s\n' "$STUB_PREV_MARKER"
        exit 0 ;;
      "python3 - "*)
        # ha_target_claim_probe <target> <control> <ifname>: a clean probe
        # hears only the control. STUB_FOREIGN=<addr> adds another MAC for
        # that address; STUB_PROBE_DEAF=1 drops the control's reply.
        read -r _ _ target control _ <<< "$cmd"
        echo "iface eth0 10:66:6a:8b:91:a4"
        [[ "${STUB_PROBE_DEAF:-}" == 1 ]] || echo "reply ${control} 02:bf:72:16:01:00 probe"
        [[ "${STUB_FOREIGN:-}" == "$target" ]] && echo "reply ${target} f6:f0:06:10:77:d5 probe"
        exit 0 ;;
      *"sha256sum /usr/local/bin/mouse-echo.py"*)
        echo "${STUB_ECHO_HASH:-missing}  /usr/local/bin/mouse-echo.py"
        exit 0 ;;
      *"ip -6 route show"*)
        # #19016: the target's installed LAN v6 return route, staged per case.
        [[ -n "${STUB_ROUTE6:-}" ]] && echo "$STUB_ROUTE6"
        exit 0 ;;
      *systemctl*is-active*) echo active; exit 0 ;;
      *list-units*) echo "mouse-iperf3@5200.service loaded active running"; exit 0 ;;
      *) exit 0 ;;
    esac ;;
esac
exit 0
STUB
chmod +x "${TMP}/bin/incus"

# `up` self-locks (#18576, cluster-cell.sh): give it a PRIVATE lock tuple so
# this hermetic test never queues on, or takes, a real cluster lock.
mkdir -p "${TMP}/lock"
LOCK_ENV=(XPF_CLUSTER_LOCK="${TMP}/lock/lock" XPF_CLUSTER_OWNER="${TMP}/lock/owner"
          XPF_CLUSTER_EPOCH="${TMP}/lock/epoch" XPF_CLUSTER_EPOCH_STATE_DIR="${TMP}/lock"
          XPF_CLUSTER_BUILD_PROBE=0)
run_up() { # run_up [ENV=VAL ...] -> prints the recorded unit payload; rc in ${TMP}/rc
    local ilog="${TMP}/incus.log" elog="${TMP}/exec.log" rc
    : > "$ilog"; : > "$elog"
    env PATH="${TMP}/bin:${PATH}" STUB_INCUS_LOG="$ilog" STUB_EXEC_LOG="$elog" \
        "${LOCK_ENV[@]}" BPFRX_CLUSTER_ENV= "$@" bash "$SUBJECT" up > "${TMP}/up.out" 2>&1
    rc=$?
    echo "$rc" > "${TMP}/rc"
    # The unit payload crosses as ONE multi-line argv (heredoc in sh -c);
    # the stub log holds it whole — extract from its header to the UNIT end.
    awk '/cat > \/etc\/systemd\/system\/mouse-addr\.service/{f=1} f{print} f&&/^UNIT/{exit}' "$elog"
}

# --- 1. loss shape: pinned .201 + declarative .202 alias, no ::200 -------
unit="$(run_up TARGET_ALIAS_V4=172.16.80.202 MOUSE_TARGET_V4=172.16.80.201 MOUSE_TARGET_V6=2001:559:8585:80::201 MOUSE_TARGET_VLAN=80)"
[[ "$unit" == *"addr replace 172.16.80.201/24"* ]] \
    || fail "loss unit does not pin the mouse address .201:
$unit"
[[ "$unit" == *"addr replace 172.16.80.202/24"* ]] \
    || fail "#16213: loss unit does not declaratively pin the .202 alias (a reboot drops it again):
$unit"
[[ "$unit" != *"::200"* ]] \
    || fail "#16213: unit aliases the external v6 ::200 (DAD duplicate on the container):
$unit"
[[ "$unit" == *"addr replace 172.16.80.201/24"* && "$unit" == *"addr replace 172.16.80.202/24"* && "$unit" != *"::200"* ]] \
    && pass "loss unit pins .201 + .202 alias, never ::200"

# --- 1b. the REAL loss env, nothing overridden (#18576) -------------------
# The alias must come from loss-userspace-cluster.env through cluster-env.sh
# (IPERF_TARGET4 -> TARGET_ALIAS_V4), and it must not be .200, which the
# external v6 box also answers ARP for.
unit="$(run_up BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env)"
[[ "$unit" == *"addr replace 172.16.80.201/24"* && "$unit" == *"addr replace 172.16.80.202/24"* ]] \
    || fail "#18576: the loss env does not yield a unit pinning .201 + .202:
$unit"
[[ "$unit" != *"172.16.80.200"* ]] \
    || fail "#18576: the loss env still pins the dual-held .200:
$unit"
pass "loss env pins .201 + .202 and never pins the dual-held .200"


# --- 1c. `up` re-runs the address unit (#18576) ---------------------------
# mouse-addr is a RemainAfterExit oneshot: `enable --now` does not re-run it
# on a host where it already ran, so a changed alias waited for a reboot.
# `up` must restart it AFTER rewriting the unit, so the new set applies now.
run_up BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env > /dev/null
restart_line="$(grep -n 'systemctl restart mouse-addr.service' "${TMP}/exec.log" | head -1 | cut -d: -f1)"
write_line="$(grep -n 'mouse-addr.service <<' "${TMP}/exec.log" | head -1 | cut -d: -f1)"
if [[ -n "$restart_line" && -n "$write_line" && "$restart_line" -gt "$write_line" ]]; then
    pass "up restarts mouse-addr.service after rewriting it"
else
    fail "#18576: up does not restart mouse-addr.service after rewriting it (write line ${write_line:-none}, restart line ${restart_line:-none}); a changed alias waits for a reboot"
fi

# #18679: pushing unchanged source must not interrupt a live TCP echo flow,
# while a content change must restart the active process to load UDP/6201.
echo_source_hash="$(sha256sum "${SCRIPT_DIR}/mouse-target-echo.py")"
echo_source_hash="${echo_source_hash%% *}"
run_up "STUB_ECHO_HASH=${echo_source_hash}" > /dev/null
if grep -q 'systemctl restart mouse-echo.service' "${TMP}/exec.log"; then
    fail "#18679: unchanged mouse-echo source caused an unnecessary restart"
else
    pass "up leaves mouse-echo running when source content is unchanged"
fi
run_up STUB_ECHO_HASH=old-content-hash > /dev/null
grep -q 'systemctl restart mouse-echo.service' "${TMP}/exec.log" \
    && pass "up restarts mouse-echo after source content changes" \
    || fail "#18679: changed mouse-echo source was not activated by a restart"

# --- 1e. `up` runs inside a cluster lock cell (#18576) ---------------------
# It rewrites and restarts the unit on a target every gate measures, so it
# serializes like a deploy (here on the private tuple above).
run_up BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env > /dev/null
grep -q 'lock acquired .*purpose: mouse-target-setup up' "${TMP}/up.out" \
    && pass "up takes the cluster lock (cluster-cell.sh)" \
    || fail "#18576: up ran without the cluster lock:
$(<"${TMP}/up.out")"

# --- 2. primary-is-pinned shape (tcp/udp): no duplicate alias ------------
unit="$(run_up TARGET_ALIAS_V4=172.16.80.210 MOUSE_TARGET_V4=172.16.80.210 MOUSE_TARGET_V6=2001:559:8585:80::210 MOUSE_TARGET_VLAN=80)"
count="$(grep -o 'addr replace 172.16.80.210/24' <<< "$unit" | wc -l)"
[[ "$count" == "1" ]] \
    || fail "tcp shape emits the pinned primary ${count}x (want exactly 1, no alias duplicate):
$unit"
[[ "$count" == "1" ]] && pass "primary==pinned emits no duplicate alias"

# --- 3. DMZ shape (VLAN 50): never claims the VLAN-80 alias --------------
unit="$(run_up TARGET_ALIAS_V4=172.16.80.202 MOUSE_TARGET_V4=172.16.50.201 MOUSE_TARGET_V6=2001:559:8585:50::201 MOUSE_TARGET_VLAN=50 MOUSE_TARGET_NAME=xpf-zone-matrix-dmz)"
[[ "$unit" == *"addr replace 172.16.50.201/24"* && "$unit" != *"172.16.80."* ]] \
    || fail "DMZ (VLAN 50) unit claims a VLAN-80 address (or lost its own pin):
$unit"
[[ "$unit" == *"addr replace 172.16.50.201/24"* && "$unit" != *"172.16.80."* ]] && pass "DMZ unit never claims the VLAN-80 alias"

# --- 4. disabled alias: empty TARGET_ALIAS_V4 emits nothing --------------
# #18576: count EVERY v4 pin, not the absence of one literal. With `:-` the
# empty value was re-derived (to 172.16.100.200 in this legacy env), and a
# check for ".200" absent passed anyway.
unit="$(run_up TARGET_ALIAS_V4= MOUSE_TARGET_V4=172.16.80.201 MOUSE_TARGET_V6=2001:559:8585:80::201 MOUSE_TARGET_VLAN=80)"
v4pins="$(grep -cE 'ip addr replace [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/' <<< "$unit")"
[[ "$v4pins" == 1 && "$unit" == *"addr replace 172.16.80.201/24"* ]] \
    && pass "empty TARGET_ALIAS_V4 disables the alias (exactly one v4 pin)" \
    || fail "empty TARGET_ALIAS_V4 emits ${v4pins} v4 pins (want exactly the .201 one):
$unit"

# --- 5. claim probe before pinning a NEW address (#18576) -----------------
probe_case() { # <label> <want-rc> [ENV=VAL ...]
    local label="$1" want="$2"; shift 2
    unit="$(run_up "$@")"
    rc="$(<"${TMP}/rc")"
    if [[ "$want" == refuse ]]; then
        if [[ "$rc" != 0 && -z "$unit" ]] && ! grep -q 'restart mouse-addr' "${TMP}/exec.log" \
            && grep -q REFUSE "${TMP}/up.out"; then
            pass "$label"
        else
            fail "#18576: ${label}: want a refusal before the unit is written (rc=${rc}); unit:
${unit}
output: $(<"${TMP}/up.out")"
        fi
    else
        if [[ "$rc" == 0 && "$unit" == *"addr replace 172.16.80.203/24"* ]] \
            && grep -q 'python3 - 172.16.80.203 172.16.80.8 eth0' "${TMP}/exec.log"; then
            pass "$label"
        else
            fail "#18576: ${label}: want the new .203 probed from eth0 and pinned (rc=${rc}); unit:
${unit}
output: $(<"${TMP}/up.out")"
        fi
    fi
}
NEW=(TARGET_ALIAS_V4=172.16.80.203 MOUSE_TARGET_V4=172.16.80.201 MOUSE_TARGET_V6=2001:559:8585:80::201 MOUSE_TARGET_VLAN=80)
probe_case "a new address with no other holder is probed from eth0, then pinned" pin "${NEW[@]}"
probe_case "a new address another MAC answers for is refused before the unit is written" refuse "${NEW[@]}" STUB_FOREIGN=172.16.80.203
probe_case "a deaf probe (control silent) is refused: no other holder is not evidence" refuse "${NEW[@]}" STUB_PROBE_DEAF=1
# --- 6. MOUSE_TARGET_CLAIM_PROBE=skip is recorded, not just warned (#18576) -
# The skip must outlive the run's log: wire-zone-matrix deletes its setup log
# on success. So the unit carries a marker, `status` prints it, and a later
# `up` keeps the marker while it still pins that address.
unit="$(run_up "${NEW[@]}" STUB_FOREIGN=172.16.80.203 MOUSE_TARGET_CLAIM_PROBE=skip)"
if [[ "$(<"${TMP}/rc")" == 0 && "$unit" == *"addr replace 172.16.80.203/24"* \
      && "$unit" == *"# claim-probe: SKIPPED for 172.16.80.203 by MOUSE_TARGET_CLAIM_PROBE=skip at "* ]] \
   && grep -q 'WARNING: claim probe for new 172.16.80.203 skipped' "${TMP}/up.out"; then
    pass "a skipped claim probe warns AND writes its marker into mouse-addr.service"
else
    fail "#18576: MOUSE_TARGET_CLAIM_PROBE=skip must warn and write the unit marker (rc=$(<"${TMP}/rc")); unit:
${unit}
output: $(<"${TMP}/up.out")"
fi
OLD_MARK="# claim-probe: SKIPPED for 172.16.80.202 by MOUSE_TARGET_CLAIM_PROBE=skip at 2026-10-31T00:00:00Z"
GONE_MARK="# claim-probe: SKIPPED for 172.16.80.209 by MOUSE_TARGET_CLAIM_PROBE=skip at 2026-10-31T00:00:00Z"
unit="$(run_up BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env STUB_PREV_MARKER="${OLD_MARK}"$'\n'"${GONE_MARK}")"
[[ "$unit" == *"$OLD_MARK"* && "$unit" != *"172.16.80.209"* ]] \
    && pass "a later up keeps the skip marker of a still-pinned address and drops one no longer pinned" \
    || fail "#18576: skip markers not carried forward (or a stale one kept); unit:
${unit}"
run_status() { # run_status [ENV=VAL ...] -> status output
    env PATH="${TMP}/bin:${PATH}" STUB_INCUS_LOG="${TMP}/incus.log" STUB_EXEC_LOG="${TMP}/exec.log" \
        BPFRX_CLUSTER_ENV= "$@" bash "$SUBJECT" status 2>&1
}
st="$(run_status STUB_PREV_MARKER="$OLD_MARK")"
[[ "$st" == *"claim:    claim-probe: SKIPPED for 172.16.80.202 by MOUSE_TARGET_CLAIM_PROBE=skip"* ]] \
    && pass "status prints a recorded claim-probe skip" \
    || fail "#18576: status does not show the recorded skip:
${st}"
st="$(run_status)"
# It must claim only what was checked: held addresses are never probed by `up`.
[[ "$st" == *"claim:    no claim-probe skip recorded (addresses already held when \`up\` ran are not probed; test-connectivity's claim cell checks IPERF_TARGET4 every run)"* \
   && "$st" != *"was claim-probed"* ]] \
    && pass "status says no skip is recorded, without claiming every address was probed" \
    || fail "#18576: status has no claim line without a skip, or overclaims:
${st}"
# A held address is not re-probed: the loss shape (.201 + .202 held) with a
# foreign reply staged for .202 still pins, since .202 is not new.
unit="$(run_up BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env STUB_FOREIGN=172.16.80.202)"
[[ "$(<"${TMP}/rc")" == 0 && "$unit" == *"addr replace 172.16.80.202/24"* ]] && ! grep -q 'python3 - ' "${TMP}/exec.log" \
    && pass "held addresses are not re-probed" \
    || fail "#18576: a held address was probed (or the loss shape refused):
$(<"${TMP}/up.out")"

# --- 7. the LAN v6 return route follows the cluster's v6 NAT mode (#19016) -
# tcp and udp ROUTE the LAN v6 block (no v6 source-nat rule), so the VLAN-80
# target sees the LAN host's real source and must send replies back via the
# firewall's reth0.80 v6 address. loss SNATs v6 (rule snat6) and needs none.
# On udp that route was a hand `ip -6 route add`; the 2026-11-05 host reboot
# dropped it, the replies went to the lab router, and every v6 cell on udp
# failed for three days while the firewall was fine.
# The EXPECTATION is read from each env's CLUSTER_CONF (the firewall config
# is the source of truth for "routed or SNATed" and for the next hop), never
# from the env values the script itself uses: an env that disagrees with its
# firewall config fails here as well.
conf_v6_facts() { # <conf> -> "snat6=<0|1> snat4=<0|1> gw80=<addr> lan64=<addr>"
    python3 -I - "$1" <<'PY'
import re, sys
s = open(sys.argv[1]).read()
rule = r"match\s*\{\s*source-address\s+(%s)\s*;\s*\}\s*then\s*\{\s*source-nat\b"
snat6 = re.findall(rule % r"[0-9A-Fa-f]*:[0-9A-Fa-f:]*/\d+", s)
snat4 = re.findall(rule % r"\d+\.\d+\.\d+\.\d+/\d+", s)
gw = re.search(r"\breth0\s*\{.*?\bunit 80\s*\{.*?family inet6\s*\{\s*address\s+([0-9A-Fa-f:]+)/64;", s, re.S)
lan = re.search(r"\breth1\s*\{.*?\bunit 0\s*\{.*?family inet6\s*\{\s*address\s+([0-9A-Fa-f:]+)/64;", s, re.S)
print("snat6=%d snat4=%d gw80=%s lan64=%s" % (bool(snat6), bool(snat4),
      gw.group(1) if gw else "", lan.group(1) if lan else ""))
PY
}
# route_matches_conf <unit-payload> <gw80> <lan64>: the unit's one route line
# goes via the conf's reth0.80 v6 address and covers the conf's LAN /64.
route_matches_conf() {
    python3 -I - "$1" "$2" "$3" <<'PY'
import ipaddress, re, sys
unit, gw, lan = sys.argv[1:4]
routes = re.findall(r"^ExecStart=/sbin/ip -6 route replace (\S+) via (\S+) dev eth0$", unit, re.M)
if len(routes) != 1:
    sys.exit("want exactly one ExecStart route line, got %d" % len(routes))
pfx, via = routes[0]
net = ipaddress.ip_network(pfx)
if ipaddress.ip_address(via) != ipaddress.ip_address(gw):
    sys.exit("next hop %s is not the conf's reth0.80 v6 address %s" % (via, gw))
if ipaddress.ip_address(lan) not in net or net.prefixlen > 64:
    sys.exit("prefix %s does not cover the conf's LAN %s/64" % (pfx, lan))
PY
}
route_unit_of() { # the recorded return-route unit payload, if any
    awk '/cat > \/etc\/systemd\/system\/xpf-target-return-route\.service/{f=1} f{print} f&&/^UNIT/{exit}' "${TMP}/exec.log"
}
for envf in loss tcp udp; do
    env_path="test/incus/${envf}-userspace-cluster.env"
    conf="$(env BPFRX_CLUSTER_ENV="$env_path" bash -c 'source "$1/cluster-env.sh" >/dev/null 2>&1; printf %s "$CLUSTER_CONF"' _ "$SCRIPT_DIR")"
    facts="$(conf_v6_facts "$conf")"
    # Positive control: the parser must see each conf's v4 SNAT rule, its
    # reth0.80 v6 address and its LAN v6 /64, or "no v6 SNAT" proves nothing.
    if [[ "$facts" != *"snat4=1"* || "$facts" == *"gw80= "* || "$facts" == *"lan64=" ]]; then
        fail "#19016: ${envf}: conf parser blind on ${conf} (${facts})"
        continue
    fi
    gw80="$(sed -n 's/.*gw80=\([^ ]*\).*/\1/p' <<<"$facts")"
    lan64="$(sed -n 's/.*lan64=\([^ ]*\).*/\1/p' <<<"$facts")"
    run_up BPFRX_CLUSTER_ENV="$env_path" > /dev/null
    rc="$(<"${TMP}/rc")"
    unit="$(route_unit_of)"
    if [[ "$facts" == *"snat6=1"* ]]; then
        # v6 SNATed: no return route anywhere, and a stale unit is removed.
        if [[ "$rc" == 0 && -z "$unit" ]] && ! grep -q 'ip -6 route replace' "${TMP}/exec.log" \
           && grep -q 'disable --now xpf-target-return-route.service' "${TMP}/exec.log"; then
            pass "${envf} SNATs v6: no LAN v6 return route, and a stale unit is removed"
        else
            fail "#19016: ${envf} SNATs v6 (${conf##*/}) but up emitted a return route or kept a stale unit (rc=${rc}):
${unit}
$(grep -E 'route|xpf-target-return-route' "${TMP}/exec.log")"
        fi
    else
        why="$(route_matches_conf "$unit" "$gw80" "$lan64" 2>&1)"
        write_line="$(grep -n 'xpf-target-return-route.service <<' "${TMP}/exec.log" | head -1 | cut -d: -f1)"
        enable_line="$(grep -n 'systemctl enable xpf-target-return-route.service' "${TMP}/exec.log" | head -1 | cut -d: -f1)"
        restart_line="$(grep -n 'systemctl restart xpf-target-return-route.service' "${TMP}/exec.log" | head -1 | cut -d: -f1)"
        addr_line="$(grep -n 'systemctl restart mouse-addr.service' "${TMP}/exec.log" | head -1 | cut -d: -f1)"
        if [[ "$rc" == 0 && -n "$unit" && -z "$why" && "$unit" == *"After=mouse-addr.service"* \
              && -n "$write_line" && -n "$enable_line" && -n "$restart_line" && -n "$addr_line" \
              && "$enable_line" -gt "$write_line" && "$restart_line" -gt "$addr_line" ]]; then
            pass "${envf} routes v6: up installs, enables and starts the LAN v6 return route via ${gw80}"
        else
            fail "#19016: ${envf} routes v6 (no v6 source-nat in ${conf##*/}) but up does not persist the LAN v6 return route via ${gw80} covering ${lan64}/64 (rc=${rc}; ${why:-route line ok}; write ${write_line:-none} enable ${enable_line:-none} restart ${restart_line:-none} after mouse-addr ${addr_line:-none}):
${unit:-<no xpf-target-return-route.service written>}"
        fi
    fi
done
# A routed env with no next hop is refused before anything is written. No
# env file here: each real env assigns WAN_GW80_6 unconditionally, which
# would override the caller's empty value and never reach the refusal.
run_up LAN_ROUTED_PREFIX6=2001:db8:aa00::/56 WAN_GW80_6= MOUSE_TARGET_VLAN=80 \
    MOUSE_TARGET_V4=172.16.80.201 MOUSE_TARGET_V6=2001:559:8585:80::201 > /dev/null
if [[ "$(<"${TMP}/rc")" != 0 ]] && grep -q 'REFUSE: LAN_ROUTED_PREFIX6' "${TMP}/up.out" \
   && ! grep -q 'cat > /etc/systemd/system/' "${TMP}/exec.log"; then
    pass "a routed env without WAN_GW80_6 is refused before any unit is written"
else
    fail "#19016: LAN_ROUTED_PREFIX6 without WAN_GW80_6 was not refused up front (rc=$(<"${TMP}/rc")):
$(<"${TMP}/up.out")"
fi
# The VLAN-50 DMZ prober (same script) never takes the VLAN-80 return route.
run_up BPFRX_CLUSTER_ENV=test/incus/udp-userspace-cluster.env MOUSE_TARGET_VLAN=50 \
    MOUSE_TARGET_NAME=xpf-zone-matrix-dmz MOUSE_TARGET_V4=172.16.50.212 \
    MOUSE_TARGET_V6=2001:559:8585:50::212 > /dev/null
[[ "$(<"${TMP}/rc")" == 0 && -z "$(route_unit_of)" ]] \
    && pass "the VLAN-50 DMZ prober gets no VLAN-80 return route" \
    || fail "#19016: the VLAN-50 prober was given the VLAN-80 return route (rc=$(<"${TMP}/rc")):
$(route_unit_of)"
# status reports the route as present or MISSING, so drift is named.
st="$(run_status BPFRX_CLUSTER_ENV=test/incus/udp-userspace-cluster.env \
    STUB_ROUTE6="2001:559:8585:ba00::/56 via 2001:559:8585:80::b dev eth0 metric 1024 pref medium")"
st_missing="$(run_status BPFRX_CLUSTER_ENV=test/incus/udp-userspace-cluster.env)"
[[ "$st" == *"return6:  2001:559:8585:ba00::/56 via 2001:559:8585:80::b present"* \
   && "$st_missing" == *"return6:  2001:559:8585:ba00::/56 via 2001:559:8585:80::b MISSING"* ]] \
    && pass "status reports the LAN v6 return route present / MISSING" \
    || fail "#19016: status does not report the LAN v6 return route state:
${st}
---
${st_missing}"
st="$(run_status BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env)"
[[ "$st" != *"return6:"* ]] \
    && pass "status prints no return-route line where v6 is SNATed" \
    || fail "#19016: status reports a return route on loss:
${st}"

if [[ $fails -eq 0 ]]; then
    echo "mouse-target-setup selftest: all checks passed"
    exit 0
fi
echo "mouse-target-setup selftest: ${fails} check(s) FAILED" >&2
exit 1
