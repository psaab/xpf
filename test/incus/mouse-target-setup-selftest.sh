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
  info)
    # Instance exists, unless STUB_INFO=absent (incus's not-found error) or
    # STUB_INFO_FLAKY=<file>: the FIRST call fails transiently (#19022).
    if [[ "${STUB_INFO:-}" == absent ]]; then
      echo 'Error: Failed to fetch instance "x" in project "default": Instance not found' >&2; exit 1
    fi
    if [[ -n "${STUB_INFO_FLAKY:-}" && ! -e "$STUB_INFO_FLAKY" ]]; then
      : > "$STUB_INFO_FLAKY"; echo 'Error: websocket: close 1006 (abnormal closure)' >&2; exit 1
    fi
    exit 0 ;;
  list) echo "xpf-mouse-target,RUNNING"; exit 0 ;;
  config) exit 0 ;;                     # eth0 device already present
  file) exit 0 ;;
  exec)
    exec_ref="${2:-}"
    shift; shift; [[ "${1:-}" == "--" ]] && shift
    cmd="$*"
    echo "$cmd" >> "${STUB_EXEC_LOG:?}"
    # The same exec keyed by its target instance, first line only (#19022):
    # with-cluster.sh also execs on the firewall VMs.
    printf '%s :: %s\n' "$exec_ref" "${cmd%%$'\n'*}" >> "${STUB_EXEC_LOG}.ref"
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
      *"iperf-listeners (#19022)"*)
        # The listener scan: run for REAL (real `ss`, real sockets) in the
        # netns cells (STUB_REAL_LISTENERS=1); elsewhere the exec fails and
        # prints nothing, i.e. the listeners cannot be listed.
        [[ "${STUB_REAL_LISTENERS:-}" == 1 ]] && exec "$@"
        exit 1 ;;
      *"unit-state (#19022)"*)
        # STUB_REAL_UNITSTATE=1: run the REAL POSIX parser against a stub
        # `systemctl show` (STUB_SYSBIN). Otherwise canned parsed rows,
        # "<port> <load> <file> <active>": STUB_UNIT_STATE=FAIL makes the
        # exec fail; unset gives 12 already-stood-down units (live tcp/udp).
        [[ "${STUB_REAL_UNITSTATE:-}" == 1 ]] && PATH="${STUB_SYSBIN:?}:$PATH" exec "$@"
        case "${STUB_UNIT_STATE-}" in
          FAIL) exit 1 ;;
          "") for p in $(seq 5200 5211); do echo "$p loaded disabled inactive"; done ;;
          *) printf '%s\n' "$STUB_UNIT_STATE" ;;
        esac
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
    : > "$ilog"; : > "$elog"; : > "${elog}.ref"
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

# --- 7. who serves iperf3 5200-5211 is DECLARED (#19022) -------------------
# MOUSE_TARGET_IPERF_PROVIDER (cluster env): `units` (loss) installs and
# enables mouse-iperf3@52xx exactly as before. `socket` (tcp, udp) is a target
# that serves those ports itself through iperf3@52xx.socket. There `up`
# installed mouse-iperf3@52xx anyway and every one crash-looped on the busy
# port. Now `up` changes NO mouse-iperf3 unit there. Before any change it
# REFUSES while one of ours is enabled or active, or their state is
# unreadable, and prints the exact disable commands. At the end it REFUSES
# unless each port has a listener on the target v4 address. A runtime
# ownership classifier and then an automatic stand-down/restore each kept
# drawing new edge cases, so both are gone; every runtime check is read-only.
ALL_IPERF=(5200 5201 5202 5203 5204 5205 5206 5207 5208 5209 5210 5211)
iperf_counts() { # -> "<enable> <disable> <reset>" mouse-iperf3 commands in the exec log
    printf '%s %s %s' "$(grep -c 'systemctl enable --now mouse-iperf3@' "${TMP}/exec.log")" \
        "$(grep -c 'systemctl disable --now mouse-iperf3@' "${TMP}/exec.log")" \
        "$(grep -c 'systemctl reset-failed mouse-iperf3@' "${TMP}/exec.log")"
}
template_written() { grep -q "mouse-iperf3@.service' <<" "${TMP}/exec.log"; }
TCP_ENV=(BPFRX_CLUSTER_ENV=test/incus/tcp-userspace-cluster.env STUB_HELD=172.16.80.210)

# 7a. units (loss): master's behaviour, untouched.
run_up BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env > /dev/null
if [[ "$(<"${TMP}/rc")" == 0 && "$(iperf_counts)" == "12 0 0" ]] && template_written; then
    pass "provider units (loss): template written, 12 mouse-iperf3 enabled, none disabled"
else
    fail "#19022: provider units: rc=$(<"${TMP}/rc") enable/disable/reset = $(iperf_counts) (want 0, 12 0 0, template); output:
$(<"${TMP}/up.out")"
fi
# 7b. an undeclared value refuses before anything runs.
run_up BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env MOUSE_TARGET_IPERF_PROVIDER=sockets > /dev/null
if [[ "$(<"${TMP}/rc")" == 2 && ! -s "${TMP}/exec.log" ]] \
        && grep -q "REFUSE: MOUSE_TARGET_IPERF_PROVIDER must be units or socket, got 'sockets'" "${TMP}/up.out"; then
    pass "an undeclared provider value refuses (rc 2) before any exec"
else
    fail "#19022: provider 'sockets' was not refused up front (rc=$(<"${TMP}/rc")); output:
$(<"${TMP}/up.out")"
fi
exec_changes() { # a state-changing exec ON THE TARGET
    grep -E '^tcp:xpf-tcp-target :: ' "${TMP}/exec.log.ref" \
        | grep -qE 'apt-get|cat > |chmod|systemctl (enable|disable|restart|start|stop|daemon-reload|reset-failed)'
}
incus_changes() { # an incus-level change to the target: lifecycle, devices, config, files (Codex P3)
    grep -E '^(init|launch|start|stop|restart|delete|rename|config (device )?(add|set|unset|remove|edit)|file (push|delete|create)) ' "${TMP}/incus.log" \
        | grep -q 'tcp:xpf-tcp-target'
}
changes_made() { exec_changes || incus_changes; }
# 7c. socket, our units all stood down, but the listeners cannot be listed:
# REFUSE, no unit touched, with the socket-unit restore command.
run_up "${TCP_ENV[@]}" > /dev/null
# Positive control for changes_made (7g/7h/7k): this `up` passed the unit
# precheck and DID change the target before the listener refusal, both by
# exec (apt-get, unit files) and at the incus level (`incus start`, the echo
# push), so each half of changes_made must see it.
if [[ "$(<"${TMP}/rc")" != 0 && "$(iperf_counts)" == "0 0 0" ]] && ! template_written && exec_changes && incus_changes \
        && grep -q "REFUSE: MOUSE_TARGET_IPERF_PROVIDER=socket, but tcp:xpf-tcp-target has no TCP listener on 172.16.80.210 for port(s) none; listeners could not be listed for port(s) ${ALL_IPERF[*]}; no mouse-iperf3 unit was changed" "${TMP}/up.out" \
        && grep -qF "systemctl enable --now iperf3@\$p.socket" "${TMP}/up.out"; then
    pass "provider socket, listeners unlistable: REFUSE with no unit touched, and the socket-unit restore command"
else
    fail "#19022: provider socket with an unlistable target: rc=$(<"${TMP}/rc") enable/disable/reset = $(iperf_counts) (want !0, 0 0 0, refusal + restore hint); output:
$(<"${TMP}/up.out")"
fi
# 7g. socket on a target where some of OUR units are enabled or active
# (5205 started by hand, 5207 enabled but inactive, which would start at the
# next boot and compete with the socket unit (R10 F2), 5210 enabled+active,
# 5211 a crash-looping leftover): REFUSE before ANY change, naming exactly
# those units and printing the exact commands. `up` stands nothing down.
run_up "${TCP_ENV[@]}" STUB_UNIT_STATE="$(for p in "${ALL_IPERF[@]}"; do
        case $p in 5205) echo "$p loaded disabled active" ;; 5207) echo "$p loaded enabled inactive" ;;
                   5210) echo "$p loaded enabled active" ;; 5211) echo "$p loaded enabled failed" ;;
                   *) echo "$p loaded disabled inactive" ;; esac; done)" > /dev/null
if [[ "$(<"${TMP}/rc")" != 0 ]] && ! changes_made \
        && grep -qF "REFUSE: MOUSE_TARGET_IPERF_PROVIDER=socket, but tcp:xpf-tcp-target has mouse-iperf3 unit(s) enabled or active: mouse-iperf3@5205(active,disabled) mouse-iperf3@5207(inactive,enabled) mouse-iperf3@5210(active,enabled) mouse-iperf3@5211(failed,enabled). Under \`socket\`, \`up\` changes no mouse-iperf3 unit; nothing was changed." "${TMP}/up.out" \
        && grep -qF "incus exec tcp:xpf-tcp-target -- sh -c 'systemctl disable --now mouse-iperf3@5205; systemctl reset-failed mouse-iperf3@5205; systemctl disable --now mouse-iperf3@5207; systemctl reset-failed mouse-iperf3@5207; systemctl disable --now mouse-iperf3@5210; systemctl reset-failed mouse-iperf3@5210; systemctl disable --now mouse-iperf3@5211; systemctl reset-failed mouse-iperf3@5211'" "${TMP}/up.out"; then
    pass "provider socket with enabled/active mouse-iperf3 units: REFUSE before any change, naming them with the exact disable + reset-failed commands"
else
    fail "#19022: provider socket with live mouse-iperf3 units: rc=$(<"${TMP}/rc"), changes made: $(changes_made && echo yes || echo no); output:
$(<"${TMP}/up.out")"
fi
# 7h. socket with our units' state unreadable: REFUSE before any change.
run_up "${TCP_ENV[@]}" STUB_UNIT_STATE=FAIL > /dev/null
if [[ "$(<"${TMP}/rc")" != 0 ]] && ! changes_made \
        && grep -q "REFUSE: MOUSE_TARGET_IPERF_PROVIDER=socket, but the state of mouse-iperf3@<port>.service on tcp:xpf-tcp-target could not be read for port(s) ${ALL_IPERF[*]} (is the instance running?); nothing was changed" "${TMP}/up.out"; then
    pass "provider socket with unreadable unit state: REFUSE before any change"
else
    fail "#19022: unreadable unit state was not refused before any change (rc=$(<"${TMP}/rc")); output:
$(<"${TMP}/up.out")"
fi

# 7j. status under `socket` lists a LIVE unit and not a disabled+failed one
# (E1): the positive control for 7d's "status lists none".
st="$(run_status "${TCP_ENV[@]}" STUB_UNIT_STATE="$(for p in "${ALL_IPERF[@]}"; do
        case $p in 5210) echo "$p loaded enabled active" ;; 5211) echo "$p loaded disabled failed" ;;
                   *) echo "$p loaded disabled inactive" ;; esac; done)")"
if [[ "$st" == *"iperf3:   mouse-iperf3 units enabled or running under \`socket\` (\`up\` refuses until they are stood down): 5210(active,enabled)"* \
      && "$st" != *"5211(failed,disabled)"* ]]; then
    pass "socket status lists the live 5210 and not the disabled+failed 5211"
else
    fail "#19022 E1: socket status unit listing wrong:
${st}"
fi

# 7k. a transient failure of the existence check refuses (Codex P2). The
# existence decision is made ONCE: before, a first `incus info` that failed
# skipped socket_unit_precheck, and a second that succeeded treated the
# target as existing, so live units survived and `up` returned 0.
LIVE_5210="$(for p in "${ALL_IPERF[@]}"; do if [[ $p == 5210 ]]; then echo "$p loaded enabled active"; else echo "$p loaded disabled inactive"; fi; done)"
rm -f "${TMP}/info-flaky"
run_up "${TCP_ENV[@]}" STUB_INFO_FLAKY="${TMP}/info-flaky" STUB_UNIT_STATE="$LIVE_5210" > /dev/null
if [[ "$(<"${TMP}/rc")" != 0 && -e "${TMP}/info-flaky" ]] && ! changes_made \
        && grep -q 'REFUSE: could not tell whether tcp:xpf-tcp-target exists (incus info: Error: websocket: close 1006 (abnormal closure)' "${TMP}/up.out"; then
    pass "a flaky first incus info REFUSES before any change (one existence decision)"
else
    fail "#19022: a flaky existence check was not refused before any change (rc=$(<"${TMP}/rc"), changes: $(changes_made && echo yes || echo no)); output:
$(<"${TMP}/up.out")"
fi
# 7l. incus's not-found answer is ABSENT: the instance is created, and the
# unit precheck does not run (a new instance has no units, so even staged
# live rows must not refuse).
run_up "${TCP_ENV[@]}" STUB_INFO=absent STUB_UNIT_STATE="$LIVE_5210" > /dev/null
if grep -q '^init images:debian/trixie tcp:xpf-tcp-target' "${TMP}/incus.log" \
        && ! grep -q 'has mouse-iperf3 unit(s) enabled or active' "${TMP}/up.out"; then
    pass "incus not-found reads as absent: the target is created, no unit precheck"
else
    fail "#19022: an absent target was not created (or was prechecked); output:
$(<"${TMP}/up.out")"
fi
# 7m/7n. the REAL unit-state POSIX parser (Codex P3) against a stub
# `systemctl show` that prints Key=Value lines, one port in a different
# property order. 7m: activating, enabled-runtime and enabled+active are
# live; inactive+disabled, not-found (empty UnitFileState) and
# disabled+failed are not. 7n: `systemctl show` failing for 5207 makes
# exactly 5207 unreadable.
mkdir -p "${TMP}/sysbin"
cat > "${TMP}/sysbin/systemctl" <<'SYSTEMCTL'
#!/usr/bin/env bash
# systemctl show -p LoadState -p UnitFileState -p ActiveState mouse-iperf3@<p>.service
[[ "$1" == show ]] || exit 1
unit="${!#}"; p="${unit#mouse-iperf3@}"; p="${p%.service}"
[[ " ${STUB_SHOW_FAIL:-} " == *" $p "* ]] && exit 1
line="$(awk -v p="$p" '$1 == p { $1 = ""; print; exit }' "${STUB_SHOW_TABLE:?}")"
[[ -n "$line" ]] || line=" LoadState=loaded ActiveState=inactive UnitFileState=disabled"
tr ' ' '\n' <<<"${line# }"
SYSTEMCTL
chmod +x "${TMP}/sysbin/systemctl"
printf '%s\n' '5201 LoadState=not-found ActiveState=inactive UnitFileState=' \
    '5202 LoadState=loaded ActiveState=failed UnitFileState=disabled' \
    '5203 LoadState=loaded ActiveState=activating UnitFileState=disabled' \
    '5204 UnitFileState=enabled-runtime ActiveState=inactive LoadState=loaded' \
    '5205 LoadState=loaded ActiveState=active UnitFileState=enabled' > "${TMP}/show-table"
REAL_UNITS=(STUB_REAL_UNITSTATE=1 STUB_SYSBIN="${TMP}/sysbin" STUB_SHOW_TABLE="${TMP}/show-table")
run_up "${TCP_ENV[@]}" "${REAL_UNITS[@]}" > /dev/null
if [[ "$(<"${TMP}/rc")" != 0 ]] && ! changes_made \
        && grep -qF 'has mouse-iperf3 unit(s) enabled or active: mouse-iperf3@5203(activating,disabled) mouse-iperf3@5204(inactive,enabled-runtime) mouse-iperf3@5205(active,enabled). ' "${TMP}/up.out"; then
    pass "real unit-state parser: activating, enabled-runtime, enabled+active live; inactive, not-found, disabled+failed not"
else
    fail "#19022: real unit-state parser misread the states (rc=$(<"${TMP}/rc")); output:
$(<"${TMP}/up.out")"
fi
run_up "${TCP_ENV[@]}" "${REAL_UNITS[@]}" STUB_SHOW_FAIL=5207 > /dev/null
if [[ "$(<"${TMP}/rc")" != 0 ]] && ! changes_made \
        && grep -q 'could not be read for port(s) 5207 (is the instance running?); nothing was changed' "${TMP}/up.out"; then
    pass "real unit-state parser: a failed systemctl show leaves exactly that port unreadable, refused"
else
    fail "#19022: real unit-state parser with a failing show for 5207 (rc=$(<"${TMP}/rc")); output:
$(<"${TMP}/up.out")"
fi

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

# 7d-7f. REAL listeners in a private netns: the listener scan runs real `ss`
# against real sockets; every systemctl call is recorded by the incus stub.
# The netns holds the target addresses on lo (.201/.202 loss, .210 tcp).
mkdir -p "${TMP}/ns"
cat > "${TMP}/ns/listen.py" <<'PY'
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
cat > "${TMP}/ns/run.sh" <<'NS'
#!/usr/bin/env bash
# run.sh <listen-specs> <command...>: inside a fresh netns, hold real
# listeners for the command's lifetime.
set -u
specs="$1"; shift
d="$(cd "$(dirname "$0")" && pwd)"
export PATH="/usr/sbin:/sbin:$PATH"
ip link set lo up || exit 90
for a in 172.16.80.201 172.16.80.202 172.16.80.210; do ip addr add "${a}/32" dev lo || exit 90; done
rm -f "$d/ready"; pid=""
if [[ -n "$specs" ]]; then
    # shellcheck disable=SC2086
    python3 "$d/listen.py" "$d/ready" $specs &
    pid=$!
    for _ in $(seq 50); do [[ -e "$d/ready" ]] && break; sleep 0.1; done
    [[ -e "$d/ready" ]] || { echo "netns listeners never became ready" >&2; kill "$pid"; exit 91; }
fi
"$@"; rc=$?
[[ -n "$pid" ]] && kill "$pid" 2>/dev/null
exit "$rc"
NS
run_ns() { # run_ns <listen-specs> <up|status> [ENV=VAL ...]: output ${TMP}/up.out, rc ${TMP}/rc
    local specs="$1" verb="$2"
    shift 2
    : > "${TMP}/incus.log"; : > "${TMP}/exec.log"; : > "${TMP}/exec.log.ref"
    timeout 90 unshare -rn bash "${TMP}/ns/run.sh" "$specs" \
        env PATH="${TMP}/bin:/usr/sbin:/sbin:${PATH}" STUB_INCUS_LOG="${TMP}/incus.log" \
        STUB_EXEC_LOG="${TMP}/exec.log" STUB_REAL_LISTENERS=1 "${LOCK_ENV[@]}" BPFRX_CLUSTER_ENV= \
        "$@" bash "$SUBJECT" "$verb" > "${TMP}/up.out" 2>&1
    echo "$?" > "${TMP}/rc"
}
specs_for() { # specs_for <family,addr> <port>...
    local fa="$1" p; shift
    for p in "$@"; do printf '%s,%s ' "$fa" "$p"; done
}
if ! have_netns; then
    netns_skip "#19022: provider cells with real listeners"
else
    # 7d. socket, every port served by a dual-stack `*` listener (the shape
    # systemd's iperf3@52xx.socket has on tcp/udp). Our units: 5200-5205
    # absent (not-found), 5206-5210 already stood down, and 5211 `loaded
    # disabled failed`: the state an operator reaches with `disable --now`
    # alone, since that cannot clear `failed` (E1). `up` proceeds, changes no
    # mouse-iperf3 unit, and status does not list 5211.
    UNITS_7D="$(for p in 5200 5201 5202 5203 5204 5205; do echo "$p not-found - inactive"; done
                for p in 5206 5207 5208 5209 5210; do echo "$p loaded disabled inactive"; done
                echo "5211 loaded disabled failed")"
    run_ns "$(specs_for 6,:: "${ALL_IPERF[@]}")" up "${TCP_ENV[@]}" STUB_UNIT_STATE="$UNITS_7D"
    if [[ "$(<"${TMP}/rc")" == 0 && "$(iperf_counts)" == "0 0 0" ]] && ! template_written \
            && ! grep -q 'mouse-iperf3@' <(grep -E '^systemctl ' "${TMP}/exec.log") \
            && grep -q 'iperf3 provider socket: all 12 ports have a listener on 172.16.80.210; no mouse-iperf3 unit installed or changed' "${TMP}/up.out" \
            && grep -q 'iperf3:   provider socket; 12 / 12 per-class ports have a listener on 172.16.80.210' "${TMP}/up.out" \
            && ! grep -q 'mouse-iperf3 units enabled or running under' "${TMP}/up.out"; then
        pass "provider socket, all 12 listening, our units absent, stood down or disabled+failed (5211): proceeds untouched, status lists none"
    else
        fail "#19022: provider socket, all listening: rc=$(<"${TMP}/rc") enable/disable/reset = $(iperf_counts) (want 0, 0 0 0); output:
$(<"${TMP}/up.out")"
    fi
    # 7e. socket, three ports not reachable on .210: 5203 has no listener
    # (0.0.0.0:52030 is a decoy a substring port filter would take for it),
    # 5205 is 127.0.0.1 only, 5206 is IPv6-only. 5207 bound to .210 itself
    # counts. The refusal names exactly 5203 5205 5206 and touches nothing.
    run_ns "$(specs_for 6,:: 5200 5201 5202 5204 5208 5209 5210 5211) 4,0.0.0.0,52030 4,127.0.0.1,5205 6only,::,5206 4,172.16.80.210,5207" \
        up "${TCP_ENV[@]}"
    if [[ "$(<"${TMP}/rc")" != 0 && "$(iperf_counts)" == "0 0 0" ]] \
            && grep -q 'REFUSE: MOUSE_TARGET_IPERF_PROVIDER=socket, but tcp:xpf-tcp-target has no TCP listener on 172.16.80.210 for port(s) 5203 5205 5206; no mouse-iperf3 unit was changed' "${TMP}/up.out"; then
        pass "provider socket, missing/decoy/127.0.0.1-only/IPv6-only: REFUSE naming exactly 5203 5205 5206, nothing touched"
    else
        fail "#19022: provider socket did not refuse exactly 5203 5205 5206 untouched (rc=$(<"${TMP}/rc"), enable/disable/reset = $(iperf_counts)); output:
$(<"${TMP}/up.out")"
    fi
    # 7f. units status (loss, two target addresses): a listener must cover
    # EVERY target v4 address (5210 on .201+.202 counts, 5211 on .202 only
    # does not), and our units are counted as master did: 5201 failed.
    run_ns "$(specs_for 4,0.0.0.0 5200 5201 5202 5203 5204 5205 5206 5207 5208 5209) 4,172.16.80.201,5210 4,172.16.80.202,5210 4,172.16.80.202,5211" \
        status BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
        STUB_UNIT_STATE="$(for p in "${ALL_IPERF[@]}"; do if [[ $p == 5201 ]]; then echo "$p loaded enabled failed"; else echo "$p loaded enabled active"; fi; done)"
    if grep -q 'iperf3:   provider units; 11 / 12 per-class ports have a listener on 172.16.80.201 172.16.80.202' "${TMP}/up.out" \
            && grep -q 'iperf3:   NO listener on 172.16.80.201 172.16.80.202 for port(s) 5211$' "${TMP}/up.out" \
            && grep -q 'iperf3:   11 / 12 mouse-iperf3 units active$' "${TMP}/up.out" \
            && grep -q 'iperf3:   mouse-iperf3 not active+enabled: 5201(failed,enabled)$' "${TMP}/up.out"; then
        pass "units status: per-address listener coverage AND the active mouse-iperf3 count (5201 failed is shown)"
    else
        fail "#19022: units status (coverage + unit count); output:
$(<"${TMP}/up.out")"
    fi
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
