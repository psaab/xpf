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
      *"ip -4 addr show"*) printf 'inet 172.16.80.201/24 scope global eth0\ninet 172.16.80.202/24 scope global secondary eth0\n'; exit 0 ;;
      *systemctl*is-active*) echo active; exit 0 ;;
      *list-units*) echo "mouse-iperf3@5200.service loaded active running"; exit 0 ;;
      *) exit 0 ;;
    esac ;;
esac
exit 0
STUB
chmod +x "${TMP}/bin/incus"

run_up() { # run_up [ENV=VAL ...] -> prints the recorded unit payload
    local ilog="${TMP}/incus.log" elog="${TMP}/exec.log"
    : > "$ilog"; : > "$elog"
    env PATH="${TMP}/bin:${PATH}" STUB_INCUS_LOG="$ilog" STUB_EXEC_LOG="$elog" \
        BPFRX_CLUSTER_ENV= "$@" bash "$SUBJECT" up > /dev/null 2>&1
    # The unit payload crosses as ONE multi-line argv (heredoc in sh -c);
    # the stub log holds it whole — extract from its header to the UNIT end.
    awk '/mouse-addr\.service/{f=1} f{print} f&&/^UNIT/{exit}' "$elog"
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
    || fail "#18576: the loss env still pins .200, which the external v6 box also answers ARP for:
$unit"
[[ "$unit" == *"addr replace 172.16.80.202/24"* && "$unit" != *"172.16.80.200"* ]] \
    && pass "loss env derives the .202 alias and never pins the dual-held .200"

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
unit="$(run_up TARGET_ALIAS_V4= MOUSE_TARGET_V4=172.16.80.201 MOUSE_TARGET_V6=2001:559:8585:80::201 MOUSE_TARGET_VLAN=80)"
[[ "$unit" == *"addr replace 172.16.80.201/24"* && "$unit" != *"172.16.80.200"* ]] \
    || fail "empty TARGET_ALIAS_V4 still emits an alias (or lost the pin):
$unit"
[[ "$unit" == *"addr replace 172.16.80.201/24"* && "$unit" != *"172.16.80.200"* ]] \
    && pass "empty TARGET_ALIAS_V4 disables the alias"

if [[ $fails -eq 0 ]]; then
    echo "mouse-target-setup selftest: all checks passed"
    exit 0
fi
echo "mouse-target-setup selftest: ${fails} check(s) FAILED" >&2
exit 1
