#!/usr/bin/env bash
# #8341 diagnostic: is a pool-mode persistent-NAT binding NEVER MINTED, or
# minted and RECLAIMED before it can be observed?
#
# WHY THE DISTINCTION IS THE WHOLE QUESTION. #7360's acceptance smoke reports
# "the ACTIVE minted no persistent-NAT binding", but its evidence is a single
# query taken ~3s AFTER three transient `exec 3<>/dev/tcp` opens have already
# returned. That supports "no binding observable at t+3s" and not "no binding
# was ever minted" -- and the two have different fixes. On this same cluster the
# #8280 phase of `make test-failover` DOES observe a pool-mode session
# (`PortAllocator::claim ran`), and the difference between the runs is that
# iperf3 keeps retrying, so a session is present when the query lands.
#
# THREE STATES, NOT TWO. The obvious framing is minted-vs-not, but there is a
# third that the existing message cannot express and that has a different cause:
#
#   A. no SESSION at all for the client -> the packet never reached the NAT
#      path; the defect is upstream of the allocator entirely.
#   B. session present, no BINDING at any tick -> the flow reaches NAT and
#      persistent-NAT declines to mint. The current story.
#   C. binding present at some tick, absent later -> minted then reclaimed.
#      The current story is WRONG and #8405's GARP is aimed at the wrong half.
#
# METHOD. Hold the observation window open rather than sampling faster: a
# BLOCKING connect to a port that never answers keeps the kernel retransmitting
# SYNs for ~2 minutes, so the half-open session (and any binding it mints) is
# live for the whole poll rather than for a few milliseconds. Sampling faster
# against a transient open would only make the race narrower, not decidable.
#
# Read-only with respect to traffic; it applies the same pool config #7360's
# smoke does and restores on exit. It does NOT fail anything over.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/incus/cluster-cell.sh
source "${SCRIPT_DIR}/cluster-cell.sh"
xpf_enter_destructive_cluster_cell "pnat-mint-observability-8341 $*" "$0" "$@"
# cluster-env.sh resolves FW0/FW1/CLUSTER_LAN_HOST and remote-qualifies them
# (#5024); deploy-lib.sh provides deploy_rolling_secondary_node.
# shellcheck source=test/incus/cluster-env.sh
source "${SCRIPT_DIR}/cluster-env.sh"
# shellcheck source=test/incus/deploy-lib.sh
source "${SCRIPT_DIR}/deploy-lib.sh"
# shellcheck source=test/incus/cos-apply-lib.sh
source "${SCRIPT_DIR}/cos-apply-lib.sh"

LAN_CLIENT="${LAN_CLIENT:-$CLUSTER_LAN_HOST}"
TARGET="${TARGET:-$IPERF_TARGET4}"
POOL_NAME="${POOL_NAME:-pnat8341}"
# #16468: the pool is DISCOVERED, not assumed from WAN_VIP4. WAN_VIP4 is the
# reth0.50 VIP, but this probe's TARGET sits behind reth0.80, so a SYN
# translated to the WAN VIP was never answered -- the #9729 confound
# persistent-nat-failover.sh resolve_pool already fixed for its sibling.
# By default reuse the committed source pool proxy-ARPed on the unit
# carrying TARGET; setting POOL_ADDR selects a dedicated POOL_NAME instead.
POOL_MODE="reuse"
if [ -n "${POOL_ADDR:-}" ]; then POOL_MODE="dedicated"; fi
POOL_ADDR="${POOL_ADDR:-}"
POOL_LOW="${POOL_LOW:-51200}"
POOL_HIGH="${POOL_HIGH:-51299}"
PNAT_TIMEOUT="${PNAT_TIMEOUT:-300}"
SNAT_RULESET="${SNAT_RULESET:-lan-to-wan}"
SNAT_RULE="${SNAT_RULE:-snat}"
# The port to hold a connection to. DEFAULTS TO A LIVE LISTENER (5201), not a
# dead one, and that is a correction rather than a preference: a dead port makes
# connect() sit in SYN-retransmit, which holds the window open but ALSO changes
# whether a session is installed at all. Measured with a dead port the probe
# reported "no session at any tick" — a verdict that could equally have been
# caused by the dead port as by the pool, which is a confound of the probe's own
# making. With a live listener the only variable left is interface-SNAT vs pool.
PROBE_PORT="${PROBE_PORT:-5201}"
POLL_SECS="${POLL_SECS:-40}"

info() { echo "==> $*"; }
fw_cli() { incus exec "$1" -- /usr/local/sbin/cli -c "$2" 2>/dev/null; }
die() { echo "FATAL: $*" >&2; exit 2; }

# reachable_source_pool / resolve_pool mirror persistent-nat-failover.sh
# (#9729/#16468): print "<pool> <address>" for the first committed source
# pool whose /32 is proxy-ARPed on an interface unit whose subnet contains
# $TARGET; resolve_pool settles POOL_NAME/POOL_ADDR before any commit.
reachable_source_pool() {
	fw_cli "$1" "show configuration | display set" | TARGET="$TARGET" python3 -c '
import ipaddress, os, re, sys
target = ipaddress.ip_address(os.environ["TARGET"])
lines = sys.stdin.read().splitlines()
nets = {}
for l in lines:
    m = re.match(r"set interfaces (\S+) unit (\d+) family inet address (\S+)", l)
    if m:
        nets.setdefault(m.group(1) + "." + m.group(2), []).append(ipaddress.ip_interface(m.group(3)).network)
arped = set()
for l in lines:
    m = re.match(r"set security nat proxy-arp interface (\S+) address (\S+)", l)
    if m and any(target in n for n in nets.get(m.group(1), [])):
        arped.add(m.group(2).split("/")[0])
for l in lines:
    m = re.match(r"set security nat source pool (\S+) address (\S+)/32$", l)
    if m and m.group(2) in arped:
        print(m.group(1), m.group(2))
        break
'
}

resolve_pool() {
	if [ "$POOL_MODE" = "dedicated" ]; then
		info "pool: dedicated ${POOL_NAME} at ${POOL_ADDR}/32, ports ${POOL_LOW}-${POOL_HIGH} (POOL_ADDR set)"
		return
	fi
	local found
	found="$(reachable_source_pool "$PRIMARY" || true)"
	[ -n "$found" ] || die "no committed source pool is proxy-ARPed on the interface carrying $TARGET, so no pool address is known to route back; set POOL_ADDR to one that does"
	POOL_NAME="${found%% *}"
	POOL_ADDR="${found##* }"
	info "pool: reusing ${POOL_NAME} at ${POOL_ADDR}/32 (proxy-ARPed on the unit carrying $TARGET); persistent-nat is added for this run only"
}

primary_node() {
	local status secondary
	status="$(fw_cli "$FW0" "show chassis cluster status" || true)"
	secondary="$(printf '%s\n' "$status" | deploy_rolling_secondary_node)"
	if [ "$secondary" = "0" ]; then echo "$FW1"; else echo "$FW0"; fi
}
PRIMARY="$(primary_node)"

restore_config() {
	info "Restoring interface SNAT on both nodes"
	# A reused pool is the cluster's own and must survive; only the
	# persistent-nat this run added is removed. A dedicated pool is deleted.
	local restore_pool_line="delete security nat source pool ${POOL_NAME}"
	if [ "$POOL_MODE" = "reuse" ]; then
		restore_pool_line="delete security nat source pool ${POOL_NAME} persistent-nat"
	fi
	local node
	for node in "$FW0" "$FW1"; do
		incus exec "$node" -- /usr/local/sbin/cli >/dev/null 2>&1 <<EOF || true
configure
rollback 0
delete security nat source rule-set ${SNAT_RULESET} rule ${SNAT_RULE} then source-nat pool
set security nat source rule-set ${SNAT_RULESET} rule ${SNAT_RULE} then source-nat interface
${restore_pool_line}
commit
exit
quit
EOF
	done
}
trap restore_config EXIT

info "#8341 mint-observability probe on $PRIMARY (client $LAN_CLIENT -> $TARGET:$PROBE_PORT)"
resolve_pool
# A reused pool keeps its committed address/ports; only a dedicated pool is
# created here (same shape as persistent-nat-failover.sh pnat_config_session).
POOL_CREATE=""
if [ "$POOL_MODE" = "dedicated" ]; then
	POOL_CREATE="delete security nat source pool ${POOL_NAME}
set security nat source pool ${POOL_NAME} address ${POOL_ADDR}/32
set security nat source pool ${POOL_NAME} port range low ${POOL_LOW} high ${POOL_HIGH}
"
fi
incus exec "$PRIMARY" -- /usr/local/sbin/cli >/tmp/pnat8341-apply.out 2>&1 <<EOF || true
configure
rollback 0
${POOL_CREATE}set security nat source pool ${POOL_NAME} persistent-nat permit any-remote-host
set security nat source pool ${POOL_NAME} persistent-nat inactivity-timeout ${PNAT_TIMEOUT}
delete security nat source rule-set ${SNAT_RULESET} rule ${SNAT_RULE} then source-nat interface
set security nat source rule-set ${SNAT_RULESET} rule ${SNAT_RULE} then source-nat pool ${POOL_NAME}
commit
exit
quit
EOF
# #6440: gate on the CLI's success MARKER, never on the session's exit status.
# The piped-stdin CLI is a REPL: it prints "error: ..." for a failed command and
# still exits 0, so an exit-status gate cannot fire. cos_require_markers is the
# single source of the marker set.
if ! cos_require_markers "pool apply on $PRIMARY" /tmp/pnat8341-apply.out "$COS_MARKER_COMMIT"; then
	echo "FATAL: pool config did not commit; not probing a fixture that was never applied" >&2
	sed -n '1,40p' /tmp/pnat8341-apply.out >&2
	exit 2
fi
info "pool ${POOL_NAME} (${POOL_ADDR}) committed"

SRC_IP="$(incus exec "$LAN_CLIENT" -- bash -lc "ip -4 -o addr show scope global | awk 'NR==1{split(\$4,a,\"/\"); print a[1]}'")"
info "client source IP: $SRC_IP"

# Hold the window open: a blocking connect that will sit in SYN-retransmit.
info "starting a BLOCKING connect (held ~${POLL_SECS}s) so the observation window is stable"
incus exec "$LAN_CLIENT" -- bash -lc \
	"nohup timeout $((POLL_SECS + 20)) bash -c 'exec 3<>/dev/tcp/${TARGET}/${PROBE_PORT}; sleep $((POLL_SECS + 10))' >/dev/null 2>&1 &" || true

echo
printf '%-6s %-10s %-12s %-28s %s\n' "t(s)" "sessions" "bindings" "translated to" "our binding (src -> natport)"
FIRST_SEEN=""; LAST_SEEN=""; ANY_SESSION=0
t=0
while [ "$t" -lt "$POLL_SECS" ]; do
	# COUNT THIS PROBE'S FLOW, NOT EVERY SESSION MENTIONING THE CLIENT.
	# Measured: a bare `grep -c "$SRC_IP"` counts unrelated background UDP from
	# the same host (seen translated to 172.16.50.8/udp) and reported 1-2
	# "sessions" on a run where the probe's own TCP flow produced none — a
	# count that looks like evidence while measuring something else. Scope it
	# to the destination and protocol this probe actually generates.
	sess="$(fw_cli "$PRIMARY" "show security flow session destination-prefix ${TARGET}" 2>/dev/null \
		| grep -F "$SRC_IP" | grep -c "tcp" || true)"
	tbl="$(fw_cli "$PRIMARY" "show security nat source persistent-nat-table" 2>/dev/null)"
	nb="$(printf '%s\n' "$tbl" | awk '/^Total persistent NAT bindings:/ {print $5; exit} /^No persistent NAT bindings/ {print 0; exit}')"
	ours="$(printf '%s\n' "$tbl" | awk -v ip="$SRC_IP" '$1 == ip {print $1" -> "$4; exit}')"
	# CONTROL: which address did the session actually get translated to? A
	# "no binding" verdict is only about persistent NAT if the POOL rule
	# matched at all — an interface-translated session (reth0.80's own
	# 172.16.80.8) would explain the absent binding without implicating the
	# mint path, and the two are indistinguishable from a session COUNT.
	xlat="$(fw_cli "$PRIMARY" "show security flow session destination-prefix ${TARGET}" 2>/dev/null \
		| grep -A2 -F "$SRC_IP" | awk '/Out:/ {print $4}' | head -1)"
	[ "${sess:-0}" -gt 0 ] && ANY_SESSION=1
	if [ -n "$ours" ]; then
		[ -z "$FIRST_SEEN" ] && FIRST_SEEN="$t"
		LAST_SEEN="$t"
	fi
	printf '%-6s %-10s %-12s %-28s %s\n' "$t" "${sess:-?}" "${nb:-?}" "${xlat:-<none>}" "${ours:-<none>}"
	sleep 2; t=$((t + 2))
done

echo
echo "======================================"
if [ -n "$FIRST_SEEN" ]; then
	echo "VERDICT C: the binding WAS minted — first observed at t=${FIRST_SEEN}s, last at t=${LAST_SEEN}s."
	echo "  '#8341: the active minted no binding' is therefore an artifact of WHEN the"
	echo "  query was taken, not of minting. The defect is downstream of the allocator."
elif [ "$ANY_SESSION" = 1 ]; then
	echo "VERDICT B: sessions for $SRC_IP existed but NO binding appeared at any tick."
	echo "  The flow reaches the NAT path and persistent-NAT declines to mint. The"
	echo "  current story holds, and the mint path is where to look."
else
	echo "VERDICT A: no session for $SRC_IP at any tick, so no binding could be minted."
	echo "  The packet never reached the NAT path — the defect is upstream of the"
	echo "  allocator entirely, and neither the mint path nor #8405's GARP is implicated."
fi
echo "======================================"
