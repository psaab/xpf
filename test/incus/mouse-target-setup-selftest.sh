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
    || fail "#18576: the loss env claims the deprecated .200 on a host that does not hold it:
$unit"
[[ "$unit" == *"addr replace 172.16.80.202/24"* && "$unit" != *"172.16.80.200"* ]] \
    && pass "loss env derives the .202 alias and never claims the dual-held .200 anew"

# --- 1d. the deprecated .200 pin is KEPT while held (#18576) --------------
# A container restart must not strand the consumers that still name .200
# until its expiry, so a host that holds it keeps its pin beside .202.
unit="$(run_up BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env STUB_HELD="172.16.80.201 172.16.80.202 172.16.80.200")"
[[ "$unit" == *"addr replace 172.16.80.202/24"* && "$unit" == *"addr replace 172.16.80.200/24"* ]] \
    && pass "loss env keeps the held deprecated .200 pinned beside .202" \
    || fail "#18576: a held deprecated .200 is dropped from the unit (a restart strands its consumers):
$unit"

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
[[ "$st" == *"claim:    every pinned v4 address was claim-probed (no skip recorded)"* ]] \
    && pass "status says so when no skip is recorded" \
    || fail "#18576: status has no claim line without a skip:
${st}"
# A held address is not re-probed: the loss shape (.201 + .202 held) with a
# foreign reply staged for .202 still pins, since .202 is not new.
unit="$(run_up BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env STUB_FOREIGN=172.16.80.202)"
[[ "$(<"${TMP}/rc")" == 0 && "$unit" == *"addr replace 172.16.80.202/24"* ]] && ! grep -q 'python3 - ' "${TMP}/exec.log" \
    && pass "held addresses are not re-probed" \
    || fail "#18576: a held address was probed (or the loss shape refused):
$(<"${TMP}/up.out")"

if [[ $fails -eq 0 ]]; then
    echo "mouse-target-setup selftest: all checks passed"
    exit 0
fi
echo "mouse-target-setup selftest: ${fails} check(s) FAILED" >&2
exit 1
