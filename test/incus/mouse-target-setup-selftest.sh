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
      *"iperf-port-owner (#19022)"*)
        # mouse-target-setup.sh's per-port owner table, staged per case
        # (empty = the exec printed nothing).
        [[ -n "${STUB_IPERF_OWNERS:-}" ]] && printf '%s\n' "$STUB_IPERF_OWNERS"
        exit 0 ;;
      *systemctl*is-active*) echo active; exit 0 ;;
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

# --- 7. iperf3 ports another UNIT serves are left to it (#19022) ----------
# tcp and udp serve 5200-5211 through socket-activated iperf3@52xx.socket
# units. `up` installed mouse-iperf3@52xx there anyway, and each one
# crash-looped on the busy port ("start request repeated too quickly"), until
# the units were disabled and reset by hand. Only a port ANOTHER systemd unit
# serves may stand our unit down. An orphan (the pre-#16213 detached-spawn
# shape) or an unreachable listener must not, since a disabled unit leaves the
# port dead after that holder exits or the target reboots. The classifier runs
# on the target (7b runs it for real); these cells pin what `up` and `status`
# do with each answer.
owner_table() { # <class> [port...]: one "<port> <class>" line per port
    local class="$1" p; shift
    for p in "$@"; do printf '%s %s\n' "$p" "$class"; done
}
ALL_IPERF=(5200 5201 5202 5203 5204 5205 5206 5207 5208 5209 5210 5211)
SOCKET_TABLE="$(for p in "${ALL_IPERF[@]}"; do echo "$p other iperf3@$p.socket"; done)"
ORPHAN_5200='5200 orphan pid=77(run-u7.service)'
iperf_counts() { # -> "<enable> <disable> <reset>" mouse-iperf3 commands in the exec log
    printf '%s %s %s' "$(grep -c 'systemctl enable --now mouse-iperf3@' "${TMP}/exec.log")" \
        "$(grep -c 'systemctl disable --now mouse-iperf3@' "${TMP}/exec.log")" \
        "$(grep -c 'systemctl reset-failed mouse-iperf3@' "${TMP}/exec.log")"
}
LOSS_ENV=BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env
run_up "$LOSS_ENV" STUB_IPERF_OWNERS="$SOCKET_TABLE" > /dev/null
if [[ "$(iperf_counts)" == "0 12 12" ]] && grep -q 'iperf3 5200: .*iperf3@5200.socket; not installing mouse-iperf3@5200' "${TMP}/up.out"; then
    pass "socket-unit ports (tcp/udp shape): no mouse-iperf3 enabled; 12 leftovers disabled and reset"
else
    fail "#19022: socket-unit ports: enable/disable/reset = $(iperf_counts) (want 0 12 12); output:
$(<"${TMP}/up.out")"
fi
run_up "$LOSS_ENV" STUB_IPERF_OWNERS="$(owner_table mine "${ALL_IPERF[@]}")" > /dev/null
[[ "$(iperf_counts)" == "12 0 0" ]] \
    && pass "our own mouse-iperf3 ports (loss shape) are enabled, never disabled" \
    || fail "#19022: loss shape enable/disable/reset = $(iperf_counts) (want 12 0 0)"
run_up "$LOSS_ENV" STUB_IPERF_OWNERS="${ORPHAN_5200}"$'\n'"$(owner_table free "${ALL_IPERF[@]:1}")" > /dev/null
if [[ "$(iperf_counts)" == "12 0 0" ]] && grep -q 'enable --now mouse-iperf3@5200' "${TMP}/exec.log" \
        && grep -q 'WARNING: iperf3 5200: held by pid=77(run-u7.service), which no persistent unit owns; keeping mouse-iperf3@5200 enabled' "${TMP}/up.out"; then
    pass "an orphan-held port keeps mouse-iperf3 enabled and names the holder (never disabled behind it)"
else
    fail "#19022: orphan port enable/disable/reset = $(iperf_counts) (want 12 0 0, 5200 kept, holder named); output:
$(<"${TMP}/up.out")"
fi
run_up "$LOSS_ENV" STUB_IPERF_OWNERS='5201 unreachable 127.0.0.1:5201 users:(("iperf3",pid=78,fd=3))'$'\n'"$(owner_table mine 5200 "${ALL_IPERF[@]:2}")" > /dev/null
if [[ "$(iperf_counts)" == "12 0 0" ]] \
        && grep -q 'WARNING: iperf3 5201: listener(s) 127.0.0.1:5201 .* not on a target v4 address (172.16.80.201 172.16.80.202); keeping mouse-iperf3@5201 enabled' "${TMP}/up.out"; then
    pass "a listener on no target v4 address keeps mouse-iperf3 enabled and is named"
else
    fail "#19022: unreachable port enable/disable/reset = $(iperf_counts) (want 12 0 0, warning); output:
$(<"${TMP}/up.out")"
fi
run_up "$LOSS_ENV" STUB_IPERF_OWNERS= > /dev/null
if [[ "$(iperf_counts)" == "12 0 0" ]] \
        && grep -q "WARNING: iperf3 owner classifier gave no answer for port(s) ${ALL_IPERF[*]} on" "${TMP}/up.out"; then
    pass "an empty owner table installs all 12 as before AND names every unclassified port"
else
    fail "#19022: empty owner table enable/disable/reset = $(iperf_counts) (want 12 0 0, all 12 named); output:
$(<"${TMP}/up.out")"
fi
run_up "$LOSS_ENV" STUB_IPERF_OWNERS="$(head -n 6 <<<"$SOCKET_TABLE")" > /dev/null
if [[ "$(iperf_counts)" == "6 6 6" ]] \
        && grep -q 'WARNING: iperf3 owner classifier gave no answer for port(s) 5206 5207 5208 5209 5210 5211 on' "${TMP}/up.out"; then
    pass "a partial owner table names exactly the unclassified ports"
else
    fail "#19022: partial owner table enable/disable/reset = $(iperf_counts) (want 6 6 6, 5206-5211 named); output:
$(<"${TMP}/up.out")"
fi
st="$(run_status STUB_IPERF_OWNERS="$SOCKET_TABLE")"
[[ "$st" == *"iperf3:   12 / 12 per-class ports served (0 mouse-iperf3, 12 by another unit)"* ]] \
    && pass "status counts ports served by socket units (no false 0 / 12)" \
    || fail "#19022: status iperf3 line wrong for the socket-unit shape:
${st}"
st="$(run_status STUB_IPERF_OWNERS="${ORPHAN_5200}"$'\n'"$(owner_table mine "${ALL_IPERF[@]:1}")")"
[[ "$st" == *"iperf3:   11 / 12 per-class ports served (11 mouse-iperf3, 0 by another unit)"* \
   && "$st" == *"iperf3:   5200 NOT served: held by orphan pid=77(run-u7.service)"* ]] \
    && pass "status does not count an orphan-held port as served, and names it" \
    || fail "#19022: status counts or hides an orphan-held port:
${st}"
st="$(run_status STUB_IPERF_OWNERS="$(head -n 3 <<<"$SOCKET_TABLE")")"
[[ "$st" == *"iperf3:   unknown / 12 per-class ports served (no classification for port(s) 5203 5204 5205 5206 5207 5208 5209 5210 5211"* ]] \
    && pass "status prints unknown, not a count, when classification is partial" \
    || fail "#19022: status prints a definite count for a partial classification:
${st}"

have_netns() {
    command -v unshare >/dev/null 2>&1 && command -v ip >/dev/null 2>&1 \
        && command -v ss >/dev/null 2>&1 && unshare -rn true 2>/dev/null
}
netns_skip() { # <what>
    if [[ "${XPF_REQUIRE_NETNS:-0}" == 1 ]]; then
        fail "$1 need unshare, ip, ss and unprivileged user namespaces (XPF_REQUIRE_NETNS=1)"
    else
        echo "SKIP: $1 (no unshare/ip/ss or unprivileged user namespaces)"
    fi
}

# --- 7b. the REAL on-target classifier, against real listeners (#19022) ----
# IPERF_PORT_OWNER_SCRIPT is read from mouse-target-setup.sh (sourced: it
# only defines) and run under `sh` in a private netns. The listeners are
# real sockets that real `ss` reports; only `systemctl` is a stub
# (whoami/is-enabled/list-sockets), mapping each listener's pid to a unit.
# 127.0.0.3 plays the target's v4 address. The shapes:
#   5200 own unit (enabled)                 -> mine
#   5201 nothing                            -> free
#   5202 dual-stack, held by systemd + socket unit -> other iperf3@5202.socket
#   5203 wildcard, transient (not enabled)  -> orphan, pid named
#   5204 nothing; 15204/52040 held + listed as sockets -> free (no suffix match)
#   5205 127.0.0.1 only (enabled unit)      -> unreachable
#   5206 IPv6-only [::] (enabled unit)      -> unreachable
#   5207 wildcard, another enabled service  -> other iperf3-custom.service
#   5208 own unit bound to 127.0.0.3 only   -> mine
mkdir -p "${TMP}/sysbin" "${TMP}/cls"
BPFRX_CLUSTER_ENV= bash -c 'source "$1" && printf "%s" "$IPERF_PORT_OWNER_SCRIPT"' _ "$SUBJECT" > "${TMP}/cls/owner.sh"
cat > "${TMP}/sysbin/systemctl" <<'STUB'
#!/usr/bin/env bash
case "$1" in
  whoami) awk -v p="$2" '$1 == p { print $2; f = 1 } END { exit !f }' "${STUB_UNITS:?}" ;;
  is-enabled) awk -v u="$2" '$1 == u { print $2; f = 1 } END { if (!f) print "disabled"; exit !f }' "${STUB_ENABLED:?}" ;;
  list-sockets) cat "${STUB_SOCKETS:?}" ;;
  *) exit 1 ;;
esac
STUB
chmod +x "${TMP}/sysbin/systemctl"
printf '%s\n' 'mouse-iperf3@5200.service enabled' 'mouse-iperf3@5208.service enabled' \
    'run-u7.service transient' 'decoy.service enabled' 'lo-only.service enabled' \
    'v6-only.service enabled' 'iperf3-custom.service enabled' > "${TMP}/cls/enabled"
printf '%s\n' '[::]:5202 iperf3@5202.socket iperf3@5202.service' \
    '[::]:15204 decoy@15204.socket decoy@15204.service' \
    '[::]:52040 decoy@52040.socket decoy@52040.service' > "${TMP}/cls/sockets"
cat > "${TMP}/cls/listen.py" <<'PY'
import socket, sys, time
# listen.py <ready-file> <family,addr,port>...; family 4 | 6 (dual-stack) | 6only
ready, specs = sys.argv[1], sys.argv[2:]
held = []
for spec in specs:
    fam, addr, port = spec.split(",")
    s = socket.socket(socket.AF_INET if fam == "4" else socket.AF_INET6, socket.SOCK_STREAM)
    if fam != "4":
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1 if fam == "6only" else 0)
    s.bind((addr, int(port)))
    s.listen()
    held.append(s)
open(ready, "w").close()
time.sleep(120)
PY
if ! have_netns; then
    netns_skip "#19022: real-classifier cells"
elif ! head -n 1 "${TMP}/cls/owner.sh" | grep -q 'iperf-port-owner'; then
    fail "#19022: could not read IPERF_PORT_OWNER_SCRIPT from ${SUBJECT} (sourcing it must only define); got: $(head -c 200 "${TMP}/cls/owner.sh")"
else
    cls_out="$(timeout 60 unshare -rn bash -c '
        export PATH="$1:/usr/sbin:/sbin:$PATH"
        d="$2"
        ip link set lo up || exit 90
        : > "$d/units"
        start() { # <name> <unit> <spec>...
            local name="$1" unit="$2" i
            shift 2
            python3 "$d/listen.py" "$d/ready.$name" "$@" &
            echo "$! $unit" >> "$d/units"
            for i in $(seq 50); do [ -e "$d/ready.$name" ] && return 0; sleep 0.1; done
            echo "listener $name never became ready" >&2
            return 1
        }
        start mine  mouse-iperf3@5200.service 4,0.0.0.0,5200 \
          && start sysd init.scope 6,::,5202 \
          && start orph run-u7.service 4,0.0.0.0,5203 \
          && start decoy decoy.service 4,0.0.0.0,15204 4,0.0.0.0,52040 \
          && start lo lo-only.service 4,127.0.0.1,5205 \
          && start v6 v6-only.service 6only,::,5206 \
          && start en iperf3-custom.service 4,0.0.0.0,5207 \
          && start mine2 mouse-iperf3@5208.service 4,127.0.0.3,5208 || exit 91
        STUB_UNITS="$d/units" STUB_ENABLED="$d/enabled" STUB_SOCKETS="$d/sockets" \
            sh -c "$(cat "$d/owner.sh")" sh 127.0.0.3 5200 5201 5202 5203 5204 5205 5206 5207 5208
        rc=$?
        echo "ORPHAN_PID $(awk "\$2 == \"run-u7.service\" { print \$1 }" "$d/units")"
        kill $(awk "{ print \$1 }" "$d/units") 2>/dev/null
        exit "$rc"
    ' _ "${TMP}/sysbin" "${TMP}/cls" 2>&1)"
    cls_rc=$?
    orphan_pid="$(awk '$1 == "ORPHAN_PID" { print $2 }' <<<"$cls_out")"
    cls_want() { # <port> <class> [detail-glob]
        local line
        line="$(awk -v p="$1" '$1 == p { print; exit }' <<<"$cls_out")"
        if [[ "$line" == "$1 $2"* && ( -z "${3:-}" || "$line" == $3 ) ]]; then
            pass "classifier: $1 -> $2${3:+ (${3})}"
        else
            fail "#19022: real classifier: port $1 want '$2'${3:+ matching ${3}}, got '${line}' (rc=${cls_rc}); full output:
${cls_out}"
        fi
    }
    cls_want 5200 mine
    cls_want 5201 free
    cls_want 5202 "other iperf3@5202.socket"
    cls_want 5203 orphan "*pid=${orphan_pid:-NONE}(run-u7.service)*"
    cls_want 5204 free
    cls_want 5205 unreachable '*127.0.0.1:5205*'
    cls_want 5206 unreachable '*\[::\]:5206*'
    cls_want 5207 "other iperf3-custom.service"
    cls_want 5208 mine
fi

# --- 8. the UDP probe echo replies FROM the address it was sent to (#19022) -
# The REAL mouse-target-echo.py, run in a private unprivileged netns (its
# fixed ports cannot collide with the host there). The defect: the echo's
# UDP socket was bound to 0.0.0.0 and replied with a plain sendto(), so the
# kernel chose the route's preferred source. On loss the target holds .201
# (primary) and .202 (the alias every harness targets); a probe to .202 got
# its answer from .201, which matched no firewall session and which the
# probe's connected socket discards, so every loss H1 Group 1c was VOID.
# Here 127.0.0.1 is the primary and 127.0.0.3 the alias: 127/8 is local but
# only 127.0.0.1 is the route's source. Cell C runs the harness's own
# udp_session_probe.py (a connected socket) to the alias. Each control on the
# primary address separates "wrong source" from "echo not running". SKIP
# without unshare/ip/ss or unprivileged user namespaces (have_netns); XPF_REQUIRE_NETNS=1
# turns that SKIP into a failure.
cat > "${TMP}/echo-client.py" <<'PY'
import socket, subprocess, sys, time
probe_script, probe_log = sys.argv[1], sys.argv[2]
PORT, BOOT, ALIAS4, ALIAS6 = 6201, "0123456789abcdef0123456789abcdef", "127.0.0.3", "2001:db8:1902:2::3"
fails = 0
def report(ok, label, detail=""):
    global fails
    print(f"ok: {label}" if ok else f"FAIL: {label}: {detail}", flush=True)
    fails += 0 if ok else 1
def ask(family, bind, dest, payloads, timeout=2.0):
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.bind((bind, 0))
    s.settimeout(timeout)
    me = s.getsockname()[:2]
    try:
        for p in payloads:
            s.sendto(p.encode(), (dest, PORT))
        data, src = s.recvfrom(4096)
        return data.decode(), src[:2], me
    except socket.timeout:
        return None, None, me
    finally:
        s.close()
def cell(label, family, bind, dest, seq):
    data, src, me = ask(family, bind, dest, [f"XPFUDP1 st19022 {BOOT} {seq}"])
    want = f"XPFUDP1 st19022 {BOOT} {seq} {me[0]} {me[1]}"
    report(data == want and src == (dest, PORT), label,
           f"sent {me[0]}:{me[1]} -> {dest}:{PORT}; reply {data!r} from {src}, want {want!r} from {(dest, PORT)}")
deadline = time.monotonic() + 10
while ask(socket.AF_INET, "127.0.0.1", "127.0.0.1", [f"XPFUDP1 ready {BOOT} 0"], 0.2)[0] is None:
    if time.monotonic() > deadline:
        report(False, "echo answers on 127.0.0.1:6201", "no reply in 10 s")
        sys.exit(1)
cell("A: IPv4 control, sent to the primary 127.0.0.1, answered from it", socket.AF_INET, "127.0.0.1", "127.0.0.1", 1)
cell(f"B: IPv4 sent to the alias {ALIAS4} is answered FROM {ALIAS4}, payload unchanged", socket.AF_INET, "127.0.0.1", ALIAS4, 2)
probe = subprocess.Popen([sys.executable, probe_script, "run", "--target", ALIAS4, "--run-id", "st19022",
                          "--logfile", probe_log, "--interval", "0.05"])
time.sleep(1.5)
probe.terminate(); probe.wait(5)
log = open(probe_log).read()
base = subprocess.run([sys.executable, probe_script, "baseline", probe_log], capture_output=True, text=True)
report(base.returncode == 0 and any(l.startswith("REPLY ") for l in log.splitlines()),
       f"C: udp_session_probe.py to the alias {ALIAS4} logs answered sequences (the H1 Group 1c baseline)",
       f"baseline rc={base.returncode} {base.stdout.strip()} {base.stderr.strip()}; log head {log[:200]!r}")
cell("D: IPv6 control, sent to ::1, answered from it", socket.AF_INET6, "::1", "::1", 3)
cell(f"E: IPv6 sent to {ALIAS6} is answered FROM it", socket.AF_INET6, "::1", ALIAS6, 4)
data, src, me = ask(socket.AF_INET, "127.0.0.1", ALIAS4, [f"XPFUDP2 st19022 {BOOT} 5", f"XPFUDP1 st19022 {BOOT} 6"])
report(data is not None and data.split()[3] == "6", "F: a wrong-magic datagram is not answered",
       f"first reply {data!r}")
sys.exit(1 if fails else 0)
PY
if ! have_netns; then
    netns_skip "#19022: echo reply-source cells"
else
    echo_out="$(timeout 60 unshare -rn bash -c '
        export PATH=/usr/sbin:/sbin:$PATH
        ip link set lo up && ip -6 addr add 2001:db8:1902:2::3/128 dev lo || exit 90
        python3 "$1" > "$3" 2>&1 &
        echo_pid=$!
        python3 "$2" "$4" "$5"; rc=$?
        kill "$echo_pid" 2>/dev/null; wait "$echo_pid" 2>/dev/null
        exit "$rc"
    ' _ "${SCRIPT_DIR}/mouse-target-echo.py" "${TMP}/echo-client.py" "${TMP}/echo.log" \
        "${SCRIPT_DIR}/udp_session_probe.py" "${TMP}/probe.log" 2>&1)"
    echo_rc=$?
    printf '%s\n' "$echo_out"
    echo_ok="$(grep -c '^ok: ' <<<"$echo_out")"
    if [[ "$echo_rc" == 0 && "$echo_ok" == 6 ]]; then
        pass "#19022: the UDP probe echo answers from the address each datagram was sent to (6/6 cells)"
    else
        fail "#19022: UDP probe echo reply-source cells: rc=${echo_rc}, ${echo_ok}/6 ok; echo log:
$(cat "${TMP}/echo.log" 2>/dev/null)"
    fi
fi

if [[ $fails -eq 0 ]]; then
    echo "mouse-target-setup selftest: all checks passed"
    exit 0
fi
echo "mouse-target-setup selftest: ${fails} check(s) FAILED" >&2
exit 1
