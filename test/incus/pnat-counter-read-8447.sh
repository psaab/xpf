#!/usr/bin/env bash
# #8447 unknown 2: is the flow REFUSED at admission, or INSTALLED and then
# reclaimed? Reads the persistent-NAT admission counter pair from a live node
# under a persistent-NAT pool.
#
# THREE OUTCOMES, and the third is a real answer rather than a failed run:
#
#   declined > 0            -> the allocator SAW the flow and refused it. The
#                              defect is in the persistent-NAT admission path.
#   admitted > 0            -> the allocator admitted it, so the session was
#                              installed and something downstream tore it down.
#   both == 0               -> `allocate_translation` was never reached with
#                              persistent_nat set. The refusal is UPSTREAM of the
#                              allocator entirely, which relocates the whole
#                              investigation and is consistent with the earlier
#                              "no session at all" result.
#
# THE SAME-CELL CONTROL MATTERS. "Both zero" is only informative if traffic
# reached the NAT path at all, so the run first applies a PLAIN pool on the same
# rule and confirms pool-translated sessions install. Without that, both-zero is
# equally consistent with "the client sent nothing".
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/incus/cluster-cell.sh
source "${SCRIPT_DIR}/cluster-cell.sh"
xpf_enter_destructive_cluster_cell "pnat-counter-read-8447 $*" "$0" "$@"
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
POOL_NAME="${POOL_NAME:-cnt8447}"
POOL_ADDR="${POOL_ADDR:-172.16.80.13}"
POOL_LOW="${POOL_LOW:-51600}"; POOL_HIGH="${POOL_HIGH:-51699}"
PNAT_TIMEOUT="${PNAT_TIMEOUT:-300}"
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

# Counters for OUR pool, read from the node's Prometheus surface.
#
# NOT from /api/v1/security/nat/pools: that endpoint returns a NARROWER
# projection (NATPoolStatsInfo -- name/address/used-ports/is-interface) and does
# not carry these counters at all. A parser aimed there returns "absent" for a
# pool that exists and is being refused, which is indistinguishable from a
# helper that predates the counters. /metrics carries the raw pair, labelled by
# pool.
counters() {   # -> "admitted declined"
	incus exec "$PRIMARY" -- bash -lc \
		"curl -s --max-time 5 http://127.0.0.1:8080/metrics" 2>/dev/null \
		| awk -v pool="${POOL_NAME}" '
			$0 ~ /^xpf_userspace_source_nat_pool_persistent_admitted_total/ && index($0, "pool=\"" pool "\"") { a=$NF }
			$0 ~ /^xpf_userspace_source_nat_pool_persistent_declined_total/ && index($0, "pool=\"" pool "\"") { d=$NF }
			END { if (a == "" && d == "") print "ABSENT ABSENT"; else printf "%d %d\n", a+0, d+0 }' \
		2>/dev/null || echo "ERR ERR"
}

# #8447 follow-up: the rule-match quartet, process-global and unlabelled.
# `consulted` is the one that settles what the admission pair could not: it
# counts every packet that REACHED source-NAT, so a zero in the others can be
# told from "nothing arrived". Read as a DELTA around the traffic, because the
# counters are cumulative for the life of the helper and an absolute would
# include every packet since boot.
match_counters() {   # -> "consulted matched unavailable no_match"
	incus exec "$PRIMARY" -- bash -lc \
		"curl -s --max-time 5 http://127.0.0.1:8080/metrics" 2>/dev/null \
		| awk '
			/^xpf_userspace_source_nat_match_consulted_total/ { c=$NF }
			/^xpf_userspace_source_nat_match_matched_total/ { m=$NF }
			/^xpf_userspace_source_nat_match_unavailable_total/ { u=$NF }
			/^xpf_userspace_source_nat_match_no_match_total/ { n=$NF }
			END { if (c=="" ) print "ABSENT ABSENT ABSENT ABSENT"; else printf "%d %d %d %d\n", c+0, m+0, u+0, n+0 }' \
		2>/dev/null || echo "ERR ERR ERR ERR"
}

run_arm() {   # persistent(0|1) -> "sessions pooltranslated admitted declined dConsulted dMatched dUnavail dNoMatch"
	local persistent="$1" pnat="" n pn adm dec
	if [ "$persistent" = 1 ]; then
		pnat="set security nat source pool ${POOL_NAME} persistent-nat permit any-remote-host
set security nat source pool ${POOL_NAME} persistent-nat inactivity-timeout ${PNAT_TIMEOUT}"
	fi
	incus exec "$PRIMARY" -- /usr/local/sbin/cli >/tmp/cnt8447.out 2>&1 <<EOF || true
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
	cos_require_markers "arm apply on $PRIMARY" /tmp/cnt8447.out "$COS_MARKER_COMMIT" \
		|| { echo "COMMIT-FAILED 0 0 0"; return; }
	# ASSERT THE FIXTURE IS WHAT WE THINK IT IS. A passing commit marker says
	# the session committed, NOT that this arm's stanza is in the running
	# config -- and an arm whose persistent-nat did not take looks exactly like
	# "persistent-nat works fine": a session installs and the counters stay 0,
	# because the allocation went down the non-persistent path. Measured: one
	# run reported precisely that and contradicted every earlier arm.
	local seen
	# Brace-counted, not indentation-guessed. Measured: a `^        }` guess
	# terminated the scan at the end of the pool's nested `port { ... }` block,
	# before reaching `persistent-nat`, and reported the fixture as not applied
	# on a config that had applied correctly -- a false negative that would
	# have been read as a defect in the feature.
	seen="$(fw_cli "$PRIMARY" "show configuration security nat source" \
		| awk -v p="pool ${POOL_NAME} {" '
			index($0,p) { f=1 }
			f { d += gsub(/{/,"{"); d -= gsub(/}/,"}") }
			f && /persistent-nat/ { print "yes"; exit }
			f && d <= 0 { exit }')"
	if [ "$persistent" = 1 ] && [ "$seen" != yes ]; then
		echo "FIXTURE-NOT-APPLIED 0 0 0"; return
	fi
	if [ "$persistent" = 0 ] && [ "$seen" = yes ]; then
		echo "FIXTURE-CONTAMINATED 0 0 0"; return
	fi
	fw_cli "$PRIMARY" "clear security flow session" >/dev/null 2>&1 || true
	local mc0 mc1 c0 m0 u0 n0 c1 m1 u1 n1
	mc0="$(match_counters)"; read -r c0 m0 u0 n0 <<<"$mc0"
	incus exec "$LAN_CLIENT" -- bash -c \
		"nohup iperf3 --forceflush --connect-timeout 5000 -B ${POOL_SRC} -t 20 -c ${TARGET} -p ${POOL_PORT} -P 2 >/tmp/cnt-iperf.log 2>&1 &" || true
	sleep 10
	n="$(fw_cli "$PRIMARY" "show security flow session source-prefix ${POOL_SRC}" | grep -c "^Session ID:" || true)"
	pn="$(fw_cli "$PRIMARY" "show security flow session source-prefix ${POOL_SRC}" | grep -c "${POOL_ADDR}" || true)"
	read -r adm dec <<<"$(counters)"
	mc1="$(match_counters)"; read -r c1 m1 u1 n1 <<<"$mc1"
	incus exec "$LAN_CLIENT" -- pkill -9 -f "iperf3.*-B ${POOL_SRC}" 2>/dev/null || true
	if [ "$c0" = ABSENT ] || [ "$c1" = ABSENT ]; then
		echo "${n:-0} ${pn:-0} ${adm:-ERR} ${dec:-ERR} ABSENT ABSENT ABSENT ABSENT"
	else
		echo "${n:-0} ${pn:-0} ${adm:-ERR} ${dec:-ERR} $((c1-c0)) $((m1-m0)) $((u1-u0)) $((n1-n0))"
	fi
}

fmt='  %-22s %-9s %-10s %-9s %-9s %-11s %-9s %-13s %s\n'
# shellcheck disable=SC2059
printf "$fmt" "arm" "sessions" "pool-xlat" "admitted" "declined" "d.consulted" "d.matched" "d.unavailable" "d.no_match"
read -r c_n c_pn c_adm c_dec c_dc c_dm c_du c_dn <<<"$(run_arm 0)"
printf "$fmt" "PLAIN (control)" "$c_n" "$c_pn" "$c_adm" "$c_dec" "$c_dc" "$c_dm" "$c_du" "$c_dn"
read -r p_n p_pn p_adm p_dec p_dc p_dm p_du p_dn <<<"$(run_arm 1)"
printf "$fmt" "PERSISTENT-NAT" "$p_n" "$p_pn" "$p_adm" "$p_dec" "$p_dc" "$p_dm" "$p_du" "$p_dn"

echo
echo "======================================"
if [ "${c_pn:-0}" -eq 0 ] 2>/dev/null; then
	echo "VOID: the PLAIN-pool control installed no pool-translated session, so traffic"
	echo "  did not reach the NAT path at all and 'both zero' below would say nothing."
elif [ "${p_n}" = FIXTURE-NOT-APPLIED ] || [ "${c_n}" = FIXTURE-CONTAMINATED ]; then
	echo "VOID: the arm's config was not what it claimed (${p_n}/${c_n}). An arm whose"
	echo "  persistent-nat did not take is indistinguishable from persistent-nat working."
elif [ "${p_adm}" = ERR ] || [ "${p_adm}" = ABSENT ]; then
	echo "VOID: could not read the counters (${p_adm}). The deployed helper may predate"
	echo "  them, or the pool row is absent from the REST surface."
elif [ "${p_dec:-0}" -gt 0 ] 2>/dev/null; then
	echo "ANSWER: DECLINED AT ADMISSION (declined=${p_dec}, admitted=${p_adm})."
	echo "  allocate_translation saw the flow and refused it. The defect is in the"
	echo "  persistent-NAT admission path."
elif [ "${p_adm:-0}" -gt 0 ] 2>/dev/null; then
	echo "ANSWER: ADMITTED, THEN TORN DOWN (admitted=${p_adm}, declined=${p_dec})."
	echo "  The allocator installed the translation and something downstream removed"
	echo "  it. The defect is NOT in the admission path."
else
	echo "ANSWER: NEITHER — both admission counters are zero while the control"
	echo "  installed ${c_pn} pool-translated session(s). allocate_translation is never"
	echo "  reached with persistent_nat set."
	echo
	if [ "${p_dc}" = ABSENT ]; then
		echo "  Rule-match quartet: ABSENT (helper predates it) — cannot say WHERE."
	elif [ "${p_dc:-0}" -eq 0 ] 2>/dev/null; then
		echo "  AND consulted=0: no packet REACHED source-NAT during the persistent arm"
		echo "  (control arm saw ${c_dc}). The defect is upstream of source-NAT entirely,"
		echo "  and this issue is not a NAT bug."
	else
		echo "  BUT consulted=${p_dc}: packets DID reach source-NAT and it answered"
		echo "  matched=${p_dm} unavailable=${p_du} no_match=${p_dn}. The decision is IN"
		echo "  the match path, between rule match and the allocator call."
	fi
fi
echo "======================================"
