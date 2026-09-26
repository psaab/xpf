#!/usr/bin/env bash
# #8447 open question 1: is RULE SHAPE a factor, or is the defect purely
# `persistent-nat` on the pool?
#
# Every arm in the triage that found #8447 used the RETARGETED CATCH-ALL rule
# (`lan-to-wan/snat`, match 0.0.0.0/0). So "persistent-nat stops sessions
# installing" was measured only in that shape. This runs the same A/B behind a
# DEDICATED `from`-matched rule -- #8280's shape, which is known to install
# pool-mode sessions on this cluster -- so the two differ in rule shape and
# nothing else.
#
#   sessions still fail -> rule shape is eliminated; the defect is persistent-nat.
#   sessions install     -> #8447 narrows to "persistent-nat on a CATCH-ALL rule",
#                           a different and smaller bug.
#
# WHY IT RETARGETS AN EXISTING RULE RATHER THAN ADDING ONE. Source-NAT rules are
# first-match-wins and the config's `pool-snat` is already ordered BEFORE the
# catch-all. A rule added here would land after it and never match, so the run
# would measure rule ORDERING while appearing to measure rule shape. `pool-snat`
# already matches 10.0.61.240/28 and is the rule #8280 exercises.
#
# The traffic must be SOURCED from 10.0.61.240 for that rule to match, which is
# why this adds the address to the LAN host exactly as the #8280 phase does, and
# uses iperf3 (which can bind a source) rather than bash /dev/tcp (which cannot).
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/incus/cluster-cell.sh
source "${SCRIPT_DIR}/cluster-cell.sh"
xpf_enter_destructive_cluster_cell "pnat-rule-shape-8447 $*" "$0" "$@"
# shellcheck source=test/incus/cluster-env.sh
source "${SCRIPT_DIR}/cluster-env.sh"
# shellcheck source=test/incus/deploy-lib.sh
source "${SCRIPT_DIR}/deploy-lib.sh"
# shellcheck source=test/incus/cos-apply-lib.sh
source "${SCRIPT_DIR}/cos-apply-lib.sh"

LAN_CLIENT="${LAN_CLIENT:-$CLUSTER_LAN_HOST}"
TARGET="${TARGET:-$IPERF_TARGET4}"
POOL_SRC="${POOL_SRC:-10.0.61.240}"
POOL_PORT="${POOL_PORT:-5210}"
POOL_NAME="${POOL_NAME:-shape8447}"
POOL_ADDR="${POOL_ADDR:-172.16.80.13}"
POOL_LOW="${POOL_LOW:-51500}"; POOL_HIGH="${POOL_HIGH:-51599}"
PNAT_TIMEOUT="${PNAT_TIMEOUT:-300}"
# The config's existing DEDICATED, from-matched, correctly-ordered pool rule.
SNAT_RULESET="${SNAT_RULESET:-lan-to-wan}"; SHAPE_RULE="${SHAPE_RULE:-pool-snat}"
ORIG_POOL="${ORIG_POOL:-pool-snat-pool}"

info() { echo "==> $*"; }
fw_cli() { incus exec "$1" -- /usr/local/sbin/cli -c "$2" 2>/dev/null; }
primary_node() {
	local status secondary
	status="$(fw_cli "$FW0" "show chassis cluster status" || true)"
	secondary="$(printf '%s\n' "$status" | deploy_rolling_secondary_node)"
	if [ "$secondary" = "0" ]; then echo "$FW1"; else echo "$FW0"; fi
}
PRIMARY="$(primary_node)"
LAN_IF="$(incus exec "$LAN_CLIENT" -- bash -c \
	"ip -4 -o route get ${LAN_GW:-10.0.61.1} 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p'" | tr -d '\r')"
[ -n "$LAN_IF" ] || { echo "FATAL: could not resolve the LAN interface" >&2; exit 2; }

restore() {
	info "Restoring ${SHAPE_RULE} -> ${ORIG_POOL} and removing ${POOL_SRC}"
	incus exec "$LAN_CLIENT" -- pkill -9 -f "iperf3.*-B ${POOL_SRC}" 2>/dev/null || true
	incus exec "$LAN_CLIENT" -- bash -c "ip addr del ${POOL_SRC}/24 dev ${LAN_IF} 2>/dev/null" || true
	local node
	for node in "$FW0" "$FW1"; do
		incus exec "$node" -- /usr/local/sbin/cli >/dev/null 2>&1 <<EOF || true
configure
rollback 0
delete security nat source rule-set ${SNAT_RULESET} rule ${SHAPE_RULE} then source-nat pool
set security nat source rule-set ${SNAT_RULESET} rule ${SHAPE_RULE} then source-nat pool ${ORIG_POOL}
delete security nat source pool ${POOL_NAME}
commit
exit
quit
EOF
	done
}
trap restore EXIT

incus exec "$LAN_CLIENT" -- bash -c "ip addr add ${POOL_SRC}/24 dev ${LAN_IF} 2>/dev/null" || true
info "#8447 rule-shape probe: dedicated rule ${SHAPE_RULE} (from ${POOL_SRC}) on $PRIMARY"

# arm: 0 = plain pool, 1 = + persistent-nat. Echoes "sessions poolsessions".
run_arm() {
	local persistent="$1" pnat="" n pn
	if [ "$persistent" = 1 ]; then
		pnat="set security nat source pool ${POOL_NAME} persistent-nat permit any-remote-host
set security nat source pool ${POOL_NAME} persistent-nat inactivity-timeout ${PNAT_TIMEOUT}"
	fi
	incus exec "$PRIMARY" -- /usr/local/sbin/cli >/tmp/shape8447.out 2>&1 <<EOF || true
configure
rollback 0
delete security nat source pool ${POOL_NAME}
set security nat source pool ${POOL_NAME} address ${POOL_ADDR}/32
set security nat source pool ${POOL_NAME} port range low ${POOL_LOW} high ${POOL_HIGH}
${pnat}
delete security nat source rule-set ${SNAT_RULESET} rule ${SHAPE_RULE} then source-nat pool
set security nat source rule-set ${SNAT_RULESET} rule ${SHAPE_RULE} then source-nat pool ${POOL_NAME}
commit
exit
quit
EOF
	# #6440: marker gate, not exit status — the piped CLI is a REPL that prints
	# "error: ..." and still exits 0, so a failed arm would otherwise look applied.
	cos_require_markers "arm apply on $PRIMARY" /tmp/shape8447.out "$COS_MARKER_COMMIT" \
		|| { echo "COMMIT-FAILED 0 0"; return; }
	fw_cli "$PRIMARY" "clear security flow session" >/dev/null 2>&1 || true
	incus exec "$LAN_CLIENT" -- bash -c \
		"nohup iperf3 --forceflush --connect-timeout 5000 -B ${POOL_SRC} -t 20 -c ${TARGET} -p ${POOL_PORT} -P 2 >/tmp/shape-iperf.log 2>&1 &" || true
	sleep 8
	n="$(fw_cli "$PRIMARY" "show security flow session source-prefix ${POOL_SRC}" | grep -c "^Session ID:" || true)"
	pn="$(fw_cli "$PRIMARY" "show security flow session source-prefix ${POOL_SRC}" | grep -c "${POOL_ADDR}" || true)"
	incus exec "$LAN_CLIENT" -- pkill -9 -f "iperf3.*-B ${POOL_SRC}" 2>/dev/null || true
	echo "OK ${n:-0} ${pn:-0}"
}

read -r c_ok c_n c_pn <<<"$(run_arm 0)"
printf '  %-34s commit=%-14s sessions=%-4s pool-translated=%s\n' "dedicated rule / PLAIN pool" "$c_ok" "$c_n" "$c_pn"
read -r p_ok p_n p_pn <<<"$(run_arm 1)"
printf '  %-34s commit=%-14s sessions=%-4s pool-translated=%s\n' "dedicated rule / PERSISTENT-NAT" "$p_ok" "$p_n" "$p_pn"

echo
echo "======================================"
if [ "$c_ok" != OK ] || [ "$p_ok" != OK ]; then
	echo "VOID: a config arm did not commit, so the comparison is between a fixture and nothing."
elif [ "${c_pn:-0}" -eq 0 ]; then
	echo "VOID: the PLAIN-pool control installed no pool-translated session behind the"
	echo "  dedicated rule, so this cell cannot attribute the persistent-nat arm's result"
	echo "  to persistent-nat. Fix the control before reading the test arm."
elif [ "${p_pn:-0}" -eq 0 ]; then
	echo "RULE SHAPE ELIMINATED: persistent-nat blocks session installation behind a"
	echo "  DEDICATED from-matched rule too (control installed ${c_pn}, test installed 0)."
	echo "  #8447 is about persistent-nat, not about the catch-all."
else
	echo "RULE SHAPE MATTERS: behind a dedicated rule, persistent-nat installs sessions"
	echo "  (${p_pn} pool-translated). #8447 narrows to persistent-nat on a CATCH-ALL rule."
fi
echo "======================================"
