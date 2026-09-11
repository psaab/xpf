#!/usr/bin/env bash
# xpf DHCP HA lease-survives-failover smoke (#2261, #2239/#2260 validation).
#
# This codifies the ONE thing the Go unit tests cannot prove: with the
# `set chassis cluster dhcp-lease-synchronization` knob ON, a REAL Kea 3.0.x on
# the promoted node must LOAD the standby's pre-seeded memfile with no parse
# error and the LAN DHCP client must keep its binding across a hard failover.
# The byte-exactness of the memfile CSV header is pinned as an EXTERNAL golden in
# Go (pkg/dhcpserver TestKeaMemfileHeadersMatchKea30xSchema); this script is the
# LIVE end-to-end acceptance that remains lab-gated (plan-deferred-lab on #2261)
# because it needs a DHCP-client fixture + knob-ON cluster session.
#
# It is intentionally NOT wired into `make test` / CI: it reboots a node on the
# SHARED loss cluster and depends on a DHCP client + a `dhcp-local-server`
# config that the default smoke config does not carry. Run it by hand in a lab
# window with those prerequisites in place.
#
# Acceptance (per #2261):
#   (a) the promoted node's Kea LOADS the pre-seeded memfile with NO parse error
#       (keaMemfileHeader{4,6} column order byte-exact for the live loader);
#   (b) the client KEEPS its address + remaining lifetime (no re-DISCOVER);
#   (c) the promoted node does NOT re-hand the in-use address to a 2nd client
#       (the duplicate-allocation window is closed by the pre-seed).
# What is automated (#9729):
#   - (a) is anchored on a POSITIVE Kea memfile load event on the promoted node
#     after the failover, then on the absence of load errors since then;
#   - (c) runs BEFORE (b). A second client DISCOVERs on the promoted node and
#     must not be handed the first client's address. Run the other way round,
#     the first client's own re-request would occupy that address whether or
#     not the lease synced, and (c) could not fail;
#   - (b) is judged on the dhclient exchange: a REQUEST for the synced address
#     answered by an ACK, with no NAK and no fresh DISCOVER. Keeping the same
#     address alone is weak, because an allocator can hand a returning client
#     the first free address again;
#   - v4 throughout. A v6 lease is asserted only with DHCP_V6=1 on a fixture
#     that answers DHCPv6; IA_PD is not automated and is not claimed.
# Roles are derived from the RG0 row, and the promotion is asserted before
# (a), (b) or (c) is read on the survivor.
#
# Fixture: when the lab config lacks the lease-sync knob, the run commits it
# together with a dhcp-local-server group on the LAN unit, and removes both on
# exit (DHCP_PROVISION=0 refuses instead). The clients run in network
# namespaces on macvlans over the LAN host's DHCP_CLIENT_IFACE, with a dhclient
# script that only assigns the leased address. The shared LAN host's own
# address, routes and resolv.conf are never touched.
#
# Usage:
#   ./test/incus/dhcp-lease-failover.sh
#   DHCP_CLIENT_IFACE=eth1 ./test/incus/dhcp-lease-failover.sh   # macvlan parent on the LAN host

set -euo pipefail

# #1875/#4020: DESTRUCTIVE smoke — reboots the primary on the SHARED loss
# cluster. Re-exec under incus-admin, then serialize behind the cluster lock so
# a concurrent deploy/smoke queues instead of colliding with our reboot.
_CELL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=cluster-cell.sh
source "${_CELL_DIR}/cluster-cell.sh"
xpf_enter_destructive_cluster_cell "dhcp-lease-failover $*" "$0" "$@"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/incus/cluster-env.sh
source "${SCRIPT_DIR}/cluster-env.sh"
# shellcheck source=test/incus/cos-apply-lib.sh
source "${SCRIPT_DIR}/cos-apply-lib.sh"

# LAN DHCP client fixture (the container/host that DISCOVERs behind the reth).
# The default smoke LAN host is a STATIC address; a lab run points this at a
# host configured to DHCP off the firewall's dhcp-local-server pool.
DHCP_CLIENT="${DHCP_CLIENT:-$CLUSTER_LAN_HOST}"
# Default eth0 (the loss LAN host presents its DHCP client on eth0, not eth1);
# override with DHCP_CLIENT_IFACE=<if> for a fixture that uses a different NIC.
DHCP_CLIENT_IFACE="${DHCP_CLIENT_IFACE:-eth0}"
# Kea memfile paths on the firewall nodes (see pkg/dhcpserver leaseFile()).
KEA_MEMFILE4="${KEA_MEMFILE4:-/var/lib/kea/kea-leases4.csv}"
KEA_MEMFILE6="${KEA_MEMFILE6:-/var/lib/kea/kea-leases6.csv}"
REBOOT_WAIT="${REBOOT_WAIT:-60}"
# How long to wait for the lease-sync push to pre-seed the standby. The push is
# change-polled every 2s and fully re-sent every 30s (pkg/daemon
# daemon_dhcp_lease_sync.go), so 30s covers a missed change poll.
LEASE_SYNC_WAIT="${LEASE_SYNC_WAIT:-30}"
DHCP_V6="${DHCP_V6:-0}"
# #9729 fixture provisioning (see the header).
DHCP_PROVISION="${DHCP_PROVISION:-1}"
DHCP_LAN_UNIT="${DHCP_LAN_UNIT:-reth1.0}"
DHCP_SUBNET="${DHCP_SUBNET:-10.0.61.0/24}"
DHCP_RANGE_LOW="${DHCP_RANGE_LOW:-10.0.61.150}"
DHCP_RANGE_HIGH="${DHCP_RANGE_HIGH:-10.0.61.199}"
DHCP_GROUP="g9729"
DHCP_POOL="p9729"
NS_A="dhcp9729a"
NS_B="dhcp9729b"
IF_A="dhc9729a"
IF_B="dhc9729b"
CLIENT_SCRIPT="/run/dhclient-9729-script"
PROVISIONED_KNOB=0
PROVISIONED_GROUP=0

# Golden Kea 3.0.x headers — MUST stay in lockstep with the Go golden
# (pkg/dhcpserver/lease_sync.go keaMemfileHeader{4,6} + the
# TestKeaMemfileHeadersMatchKea30xSchema literals). If Kea ever bumps its CSV
# schema, update BOTH the Go golden and these two lines together.
GOLDEN_HEADER4="address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id"
GOLDEN_HEADER6="address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,lease_type,iaid,prefix_len,fqdn_fwd,fqdn_rev,hostname,hwaddr,state,user_context,hwtype,hwaddr_source,pool_id"

PASS=0
FAIL=0
ERRORS=()
info() { echo "==> $*"; }
pass() { echo "  PASS  $*"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL  $*"; FAIL=$((FAIL + 1)); ERRORS+=("$*"); }
die()  { echo "FATAL: $*" >&2; exit 2; }

ssh_fw() { incus exec "$1" -- bash -lc "$2"; }

# rg0_primary_node <query-node> prints the node holding RG0 primary as seen from
# <query-node>, or nothing when the RG0 row cannot be read (#9729).
rg0_primary_node() {
	local status row0 row1
	status="$(ssh_fw "$1" '/usr/local/sbin/cli -c "show chassis cluster status" 2>/dev/null' || true)"
	row0="$(printf '%s\n' "$status" | awk '/^Redundancy group:[[:space:]]/ {rg=$3; next} rg=="0" && $1=="node0" {print tolower($3); exit}')"
	row1="$(printf '%s\n' "$status" | awk '/^Redundancy group:[[:space:]]/ {rg=$3; next} rg=="0" && $1=="node1" {print tolower($3); exit}')"
	case "$row0/$row1" in
	primary*/*) echo "$FW0" ;;
	*/primary*) echo "$FW1" ;;
	esac
}

# ---------------------------------------------------------------------------
# Preflight — the lab prerequisites this smoke cannot self-provision.
# ---------------------------------------------------------------------------
preflight() {
	info "Preflight: lease-sync knob + dhcp-local-server (provisioned for this run when absent)"
	local cfg
	cfg="$(ssh_fw "$FW0" '/usr/local/sbin/cli -c "show configuration chassis cluster" 2>/dev/null' || true)"
	if grep -q "dhcp-lease-synchronization" <<<"$cfg"; then
		pass "dhcp-lease-synchronization is already enabled on $FW0 (lab config, left as it is)"
		return
	fi
	if [ "$DHCP_PROVISION" != "1" ]; then
		cat >&2 <<EOF
LAB PREREQUISITE MISSING: dhcp-lease-synchronization is not enabled, and
DHCP_PROVISION=0 forbids committing it for the run. Either unset DHCP_PROVISION
or enable it on both nodes with a dhcp-local-server pool on the LAN, e.g.:

  set chassis cluster dhcp-lease-synchronization
  set system services dhcp-local-server group g0 interface reth1.0
  set system services dhcp-local-server group g0 pool p0 subnet 10.0.61.0/24
  set system services dhcp-local-server group g0 pool p0 address-range low 10.0.61.150 high 10.0.61.199

See pkg/dhcpserver/README.md (#2239 lease-sync).
EOF
		die "prerequisites not met (knob OFF, DHCP_PROVISION=0)"
	fi
	provision_dhcp
}

dhcp_config_session() { # <with_group 0|1>
	echo configure
	echo "rollback 0"
	echo "set chassis cluster dhcp-lease-synchronization"
	if [ "$1" = "1" ]; then
		echo "set system services dhcp-local-server group ${DHCP_GROUP} interface ${DHCP_LAN_UNIT}"
		echo "set system services dhcp-local-server group ${DHCP_GROUP} pool ${DHCP_POOL} subnet ${DHCP_SUBNET}"
		echo "set system services dhcp-local-server group ${DHCP_GROUP} pool ${DHCP_POOL} address-range low ${DHCP_RANGE_LOW} high ${DHCP_RANGE_HIGH}"
	fi
	echo commit
	echo exit
	echo quit
}

# provision_dhcp commits the fixture on the RG0 primary; config sync carries it.
#
# It adds ONLY what is missing. The loss lab already serves 10.0.61.0/24 from its
# own dhcp-local-server group, and a second group for the same subnet commits
# clean but makes Kea refuse its whole config ("subnet with the prefix of
# '10.0.61.0/24' already exists"), so no DHCP is served at all (#9729 run 3).
# So the group is added only when the lab has none, and the knob always.
provision_dhcp() {
	local node out with_group=0 existing
	node="$(rg0_primary_node "$FW0")"
	[ -n "$node" ] || node="$(rg0_primary_node "$FW1")"
	[ -n "$node" ] || die "cannot read the RG0 primary to commit the DHCP fixture on"
	existing="$(ssh_fw "$node" '/usr/local/sbin/cli -c "show configuration system services dhcp-local-server | display set" 2>/dev/null' || true)"
	if ! grep -q "dhcp-local-server group .* pool .* subnet" <<<"$existing"; then
		with_group=1
	fi
	out="$(mktemp)"
	# Set before the attempt, so a commit that fails half-way is still rolled back.
	PROVISIONED_KNOB=1
	PROVISIONED_GROUP=$with_group
	dhcp_config_session "$with_group" | incus exec "$node" -- /usr/local/sbin/cli >"$out" 2>&1 || true
	# Gate on the marker, never the exit status (#6440).
	if ! cos_require_markers "dhcp fixture apply on $node" "$out" "$COS_MARKER_COMMIT"; then
		cat "$out" >&2
		rm -f "$out"
		die "committing the DHCP fixture failed on $node"
	fi
	rm -f "$out"
	if [ "$with_group" = "1" ]; then
		pass "DHCP fixture committed on $node for this run: lease-sync knob, group ${DHCP_GROUP} on ${DHCP_LAN_UNIT}, ${DHCP_RANGE_LOW}-${DHCP_RANGE_HIGH}"
	else
		pass "lease-sync knob committed on $node for this run; the lab's own dhcp-local-server group serves the clients"
	fi
	sleep 10
}

# restore_dhcp runs on EXIT: the client namespaces always go, and the fixture is
# removed only if this run committed it. Both nodes are tried, because the
# primary may have moved and a secondary simply refuses.
restore_dhcp() {
	ns_down "$NS_A"
	ns_down "$NS_B"
	incus exec "$DHCP_CLIENT" -- rm -f "$CLIENT_SCRIPT" >/dev/null 2>&1 || true
	[ "$PROVISIONED_KNOB" = "1" ] || return 0
	info "Restoring: removing what this run committed (knob; group=${PROVISIONED_GROUP})"
	local node
	for node in "$FW0" "$FW1"; do
		{
			echo configure
			echo "rollback 0"
			echo "delete chassis cluster dhcp-lease-synchronization"
			if [ "$PROVISIONED_GROUP" = "1" ]; then
				echo "delete system services dhcp-local-server group ${DHCP_GROUP}"
			fi
			echo commit
			echo exit
			echo quit
		} | incus exec "$node" -- /usr/local/sbin/cli >/dev/null 2>&1 || true
	done
}

# install_client_script puts a dhclient script on the LAN host that ONLY
# assigns or removes the leased IPv4 address: no routes, no resolv.conf.
install_client_script() {
	incus exec "$DHCP_CLIENT" -- sh -c "cat > '$CLIENT_SCRIPT' && chmod 0755 '$CLIENT_SCRIPT'" <<'SCRIPT'
#!/bin/sh
# xpf #9729 dhclient script: assign the leased IPv4 address only.
case "$reason" in
PREINIT) ip link set "$interface" up ;;
BOUND|RENEW|REBIND|REBOOT)
	if [ -n "$old_ip_address" ] && [ "$old_ip_address" != "$new_ip_address" ]; then
		ip -4 addr del "$old_ip_address/$old_subnet_mask" dev "$interface" 2>/dev/null
	fi
	ip -4 addr replace "$new_ip_address/$new_subnet_mask" dev "$interface"
	;;
EXPIRE|FAIL|RELEASE|STOP)
	if [ -n "$old_ip_address" ]; then
		ip -4 addr del "$old_ip_address/$old_subnet_mask" dev "$interface" 2>/dev/null
	fi
	;;
esac
exit 0
SCRIPT
}

# ns_up <ns> <ifname>: a namespace holding a macvlan over DHCP_CLIENT_IFACE.
# Every command inside a namespace goes through `nsenter --net=/run/netns/<ns>`,
# never `ip netns exec`: the latter remounts /sys, which the unprivileged LAN host
# container refuses ("mount of /sys failed: Operation not permitted", #9729).
ns_up() {
	ssh_fw "$DHCP_CLIENT" "ip netns del '$1' 2>/dev/null; ip link del '$2' 2>/dev/null; ip netns add '$1' && ip link add '$2' link '$DHCP_CLIENT_IFACE' type macvlan mode bridge && ip link set '$2' netns '$1' && nsenter --net=/run/netns/'$1' ip link set lo up && nsenter --net=/run/netns/'$1' ip link set '$2' up"
}

# ns_dhclient <ns> <ifname> [dhclient args]: one v4 attempt inside the
# namespace, printing dhclient's exchange. dhclient backgrounds itself once bound.
ns_dhclient() {
	local ns="$1" ifn="$2"
	shift 2
	ssh_fw "$DHCP_CLIENT" "timeout 90 nsenter --net=/run/netns/'$ns' dhclient -1 -v -sf '$CLIENT_SCRIPT' -pf '/run/dhclient-$ns.pid' -lf '/run/dhclient-$ns.leases' $* '$ifn' 2>&1"
}

# ns_addr4 <ns> <ifname> prints the namespace interface's IPv4 address, if any.
ns_addr4() {
	ssh_fw "$DHCP_CLIENT" "nsenter --net=/run/netns/'$1' ip -4 -o addr show dev '$2' | awk '{print \$4}' | cut -d/ -f1 | head -1" || true
}

# ns_down <ns> stops the namespace's clients and deletes it (the macvlan goes with it).
ns_down() {
	ssh_fw "$DHCP_CLIENT" "for f in /run/dhclient-$1.pid /run/dhclient6-$1.pid; do [ -f \$f ] && kill \$(cat \$f) 2>/dev/null; rm -f \$f; done; rm -f /run/dhclient-$1.leases /run/dhclient6-$1.leases; ip netns del '$1' 2>/dev/null; true" >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------------------
# (a) Byte-exactness gate — the standby memfile header must match the golden
#     BEFORE we ever fail over. This is the live analog of the Go golden test.
# ---------------------------------------------------------------------------
assert_memfile_header() {
	local node="$1" path="$2" golden="$3" fam="$4" hdr
	hdr="$(ssh_fw "$node" "head -n1 '$path' 2>/dev/null" || true)"
	if [[ -z "$hdr" ]]; then
		fail "v$fam pre-seed memfile absent/empty on $node ($path)"
		return
	fi
	if [[ "$hdr" == "$golden" ]]; then
		pass "v$fam pre-seed header on $node is byte-exact against Kea 3.0.x golden"
	else
		fail "v$fam pre-seed header on $node DRIFTED from golden
       got:  $hdr
       want: $golden"
	fi
}

main() {
	trap restore_dhcp EXIT
	preflight

	PRIMARY="$(rg0_primary_node "$FW0")"
	[ -n "$PRIMARY" ] || PRIMARY="$(rg0_primary_node "$FW1")"
	[ -n "$PRIMARY" ] || die "cannot read the RG0 primary from either node"
	if [ "$PRIMARY" = "$FW0" ]; then STANDBY="$FW1"; else STANDBY="$FW0"; fi
	info "roles: RG0 primary=$PRIMARY standby=$STANDBY"

	info "1) Client A DISCOVERs a lease from the RG0 primary ($PRIMARY) Kea"
	install_client_script || die "could not install the dhclient script on $DHCP_CLIENT"
	ns_up "$NS_A" "$IF_A" || die "could not create client namespace $NS_A on $DHCP_CLIENT"
	ns_dhclient "$NS_A" "$IF_A" || die "v4 DHCP DISCOVER failed for client A"
	local addr4
	addr4="$(ns_addr4 "$NS_A" "$IF_A")"
	[[ -n "$addr4" ]] || die "client A acquired no v4 address"
	pass "client A acquired v4 lease $addr4"
	if [ "$DHCP_V6" = "1" ]; then
		ssh_fw "$DHCP_CLIENT" "timeout 90 nsenter --net=/run/netns/'$NS_A' dhclient -6 -1 -v -pf '/run/dhclient6-$NS_A.pid' -lf '/run/dhclient6-$NS_A.leases' '$IF_A'" || die "v6 DHCP SOLICIT failed (DHCP_V6=1)"
		pass "client A acquired a v6 lease"
	fi

	info "2) Wait for the lease-sync push to pre-seed the standby, then gate byte-exactness"
	# #9729 run 4: a fixed 3s sleep read the standby memfile before the
	# asynchronous push landed, and the post-failover cells then proved the
	# lease HAD synced. Poll for the leased address instead of guessing.
	local seeded=0 waited=0
	while [ "$waited" -lt "$LEASE_SYNC_WAIT" ]; do
		if ssh_fw "$STANDBY" "grep -q '^${addr4},' '$KEA_MEMFILE4'" 2>/dev/null; then
			seeded=1
			break
		fi
		sleep 1
		waited=$((waited + 1))
	done
	assert_memfile_header "$STANDBY" "$KEA_MEMFILE4" "$GOLDEN_HEADER4" 4
	if [ "$DHCP_V6" = "1" ]; then
		assert_memfile_header "$STANDBY" "$KEA_MEMFILE6" "$GOLDEN_HEADER6" 6
	fi
	if [ "$seeded" = "1" ]; then
		pass "leased address $addr4 present in standby pre-seed memfile after ${waited}s"
	else
		fail "leased address $addr4 not present in standby pre-seed memfile after ${LEASE_SYNC_WAIT}s"
	fi

	info "3) Hard failover — reboot the RG0 primary ($PRIMARY)"
	local since
	since="$(ssh_fw "$STANDBY" 'date +%s' || true)"
	[[ "$since" =~ ^[0-9]+$ ]] || die "cannot read the standby clock"
	incus restart "$PRIMARY" --force || die "reboot $PRIMARY failed"
	sleep "$REBOOT_WAIT"
	local promoted
	promoted="$(rg0_primary_node "$STANDBY")"
	if [ "$promoted" != "$STANDBY" ]; then
		fail "no promotion observed: RG0 primary reads '${promoted:-unreadable}' on $STANDBY after rebooting $PRIMARY"
		echo "  DHCP lease-failover test: $PASS passed, $FAIL failed"
		exit 1
	fi
	pass "the standby $STANDBY was promoted to RG0 primary"

	info "4) (a) promoted node ($STANDBY) Kea loads the memfile after the failover, without errors"
	local waited=0 loaded=0
	while [ "$waited" -lt "$REBOOT_WAIT" ]; do
		if ssh_fw "$STANDBY" "journalctl -u kea-dhcp4-server --since @$since 2>/dev/null | grep -q DHCPSRV_MEMFILE_LEASE_FILE_LOAD"; then
			loaded=1
			break
		fi
		sleep 5
		waited=$((waited + 5))
	done
	if [ "$loaded" = "1" ]; then
		pass "Kea on $STANDBY logged a memfile lease-file load after the failover"
		if ssh_fw "$STANDBY" "journalctl -u kea-dhcp4-server --since @$since 2>/dev/null | grep -iE 'ROW_ERROR|error|parse|malformed'"; then
			fail "Kea reported a memfile load error on the promoted node"
		else
			pass "no Kea memfile load error on the promoted node since the failover"
		fi
	else
		fail "no Kea memfile lease-file load event on $STANDBY within ${REBOOT_WAIT}s of the failover (kea-dhcp4-server ActiveEnterTimestamp: $(ssh_fw "$STANDBY" 'systemctl show -p ActiveEnterTimestamp --value kea-dhcp4-server' 2>/dev/null || echo unknown)); (a) cannot be judged on a load that did not happen"
	fi

	info "5) (c) a second client must NOT be handed client A's in-use address by the promoted node"
	ns_up "$NS_B" "$IF_B" || die "could not create client namespace $NS_B on $DHCP_CLIENT"
	local addr_b=""
	if ns_dhclient "$NS_B" "$IF_B"; then
		addr_b="$(ns_addr4 "$NS_B" "$IF_B")"
	fi
	if [[ -z "$addr_b" ]]; then
		fail "client B acquired no lease from the promoted node, so (c) cannot be judged"
	elif [[ "$addr_b" == "$addr4" ]]; then
		fail "the promoted node handed client A's in-use address $addr4 to client B (lease NOT synced)"
	else
		pass "client B got $addr_b, not client A's in-use $addr4"
	fi

	info "6) (b) client A re-requests its address from the promoted node: REQUEST + ACK, no NAK, no DISCOVER"
	ssh_fw "$DHCP_CLIENT" "nsenter --net=/run/netns/'$NS_A' dhclient -x -sf '$CLIENT_SCRIPT' -pf '/run/dhclient-$NS_A.pid' -lf '/run/dhclient-$NS_A.leases' '$IF_A'" >/dev/null 2>&1 || true
	local renew addr4b
	renew="$(ns_dhclient "$NS_A" "$IF_A" || true)"
	addr4b="$(ns_addr4 "$NS_A" "$IF_A")"
	if grep -q "DHCPREQUEST for ${addr4}" <<<"$renew" && grep -q "DHCPACK of ${addr4}" <<<"$renew" &&
		! grep -qE "DHCPNAK|DHCPDISCOVER" <<<"$renew" && [[ "$addr4b" == "$addr4" ]]; then
		pass "client A kept $addr4 across the failover by REQUEST/ACK, with no NAK and no DISCOVER"
	else
		fail "client A did not keep $addr4 by REQUEST/ACK (now '${addr4b:-none}'); exchange: $(tr '\n' ' ' <<<"$renew" | cut -c1-400)"
	fi

	echo
	# #9729: the canonical line the ha-smoke ledger adapter parses.
	echo "  DHCP lease-failover test: $PASS passed, $FAIL failed"
	if ((FAIL > 0)); then
		printf ' - %s\n' "${ERRORS[@]}" >&2
		exit 1
	fi
}

main "$@"
