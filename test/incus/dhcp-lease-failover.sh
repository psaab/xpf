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
# Sourced (selftests) vs executed (live runs) is the ONLY mode switch, and it
# is structural: there is deliberately no environment bypass. No exported
# variable can flip a live run into selftest mode (#10122). BASH_SOURCE[0] is
# this file; $0 is this file only when executed (directly or via `bash
# file`), and the caller otherwise (an interactive shell, `bash -c`, or
# another script when sourced).
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	xpf_enter_destructive_cluster_cell "dhcp-lease-failover $*" "$0" "$@"
fi

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
# Cleanup polling is immediate-success and deadline-bounded. The defaults leave
# the happy path unchanged while allowing a slow commit to settle in the lab.
DHCP_RESTORE_WAIT="${DHCP_RESTORE_WAIT:-30}"
DHCP_RESTORE_POLL="${DHCP_RESTORE_POLL:-2}"
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

# Structured early-abort cause (#10122). The FIRST abort wins: the run wrapper
# captures 2>&1, and the ha-smoke/smoke-cells adapters attach the first
# `ABORT_CAUSE=<value>` marker to a summary-less or rc-disagreeing VOID, so the
# ledger row names the ORIGINAL failure instead of a downstream cleanup
# complaint. A last-`FATAL:` fallback stays in the adapter for output that
# predates markers.
ABORT_CAUSE=""
note_abort_cause() { # <cause>: record once, print the marker once.
	if [[ -n "$ABORT_CAUSE" ]]; then
		return 0
	fi
	local cause="$1"
	cause=${cause//$'\t'/ }
	cause=${cause//$'\n'/ }
	ABORT_CAUSE="$cause"
	printf 'ABORT_CAUSE=%s\n' "$ABORT_CAUSE" >&2 || true
	return 0
}

# A `set -e` death outside die() still names its command. Installed by main();
# cleanup disables it (cleanup FATALs record explicit causes instead). ERR is
# inherited into command substitutions by `set -E`, but only the main shell may
# publish the marker; otherwise `x=$(false)` emits once in the child and once
# for the failed assignment in the parent.
_ABORT_MAIN_BASHPID=""
on_gate_err() { # <command> <rc>, from the ERR trap.
	[[ "$BASHPID" == "$_ABORT_MAIN_BASHPID" ]] || return 0
	note_abort_cause "ERR: ${1:-unknown} (rc=${2:-?})" || true
}
install_abort_trap() {
	_ABORT_MAIN_BASHPID="$BASHPID"
	set -E
	trap 'on_gate_err "$BASH_COMMAND" "$?"' ERR
}

die()  { note_abort_cause "gate: $*"; echo "FATAL: owner=test-dhcp-lease-failover: $*" >&2; exit 2; }

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

# The reboot moves every redundancy group that was primary on the node we
# restart. Record all owners (and their manual-pin state) before provisioning
# anything, then restore and verify that exact state from the EXIT trap. A
# destructive smoke that leaves the shared cluster inverted poisons the next
# lane even when its own cells passed (#10122).
declare -A ORIGINAL_RG_PRIMARY=()
declare -A ORIGINAL_RG_MANUAL=()
ORIGINAL_STATE_RECORDED=0

cluster_status() {
	local status
	status="$(ssh_fw "$FW0" '/usr/local/sbin/cli -c "show chassis cluster status" 2>/dev/null' || true)"
	[[ -n "$status" ]] || status="$(ssh_fw "$FW1" '/usr/local/sbin/cli -c "show chassis cluster status" 2>/dev/null' || true)"
	printf '%s\n' "$status"
}

# Parse the chassis-cluster status table into RG, node, role, manual-pin rows.
# Keeping this parser pure lets the fixture selftest exercise the exact
# production cleanup selector against a captured status, without a live cluster.
cluster_state_rows() {
	awk '
		/^Redundancy group:[[:space:]]/ { rg=$3; next }
		$1 ~ /^node[01]$/ { print rg, $1, $3, $5 }
	'
}

cluster_primary_node_from_status() {
	local want="$1"
	awk -v want="$want" '$1 == want && $3 == "primary" { print $2; exit }'
}

record_cluster_state() {
	local status rg node role manual owners=""
	status="$(cluster_status)"
	while read -r rg node role manual; do
		[[ "$role" == "primary" ]] || continue
		ORIGINAL_RG_PRIMARY["$rg"]="$node"
		ORIGINAL_RG_MANUAL["$rg"]="$manual"
	done < <(printf '%s\n' "$status" | cluster_state_rows)
	[[ -n "${ORIGINAL_RG_PRIMARY[0]:-}" ]] ||
		die "cannot record the original RG0 owner before the destructive run"
	ORIGINAL_STATE_RECORDED=1
	for rg in "${!ORIGINAL_RG_PRIMARY[@]}"; do
		owners+=" RG${rg}=${ORIGINAL_RG_PRIMARY[$rg]}/manual=${ORIGINAL_RG_MANUAL[$rg]}"
	done
	info "recorded original cluster ownership:${owners}"
}

declare -a ORIGINAL_DHCP_CHASSIS=()
declare -a ORIGINAL_DHCP_LOCAL=()
CONFIG_STATE_RECORDED=0

record_dhcp_config_state() {
	local i node
	for i in 0 1; do
		if [[ "$i" == "0" ]]; then node="$FW0"; else node="$FW1"; fi
		if ! ORIGINAL_DHCP_CHASSIS[i]="$(ssh_fw "$node" '/usr/local/sbin/cli -c "show configuration chassis cluster | display set" 2>/dev/null')"; then
			die "cannot snapshot chassis configuration on $node before the destructive run"
		fi
		if ! ORIGINAL_DHCP_LOCAL[i]="$(ssh_fw "$node" '/usr/local/sbin/cli -c "show configuration system services dhcp-local-server | display set" 2>/dev/null')"; then
			die "cannot snapshot dhcp-local-server configuration on $node before the destructive run"
		fi
	done
	CONFIG_STATE_RECORDED=1
	info "snapshotted DHCP fixture configuration on both nodes before provisioning"
}

verify_dhcp_config() {
	[[ "$CONFIG_STATE_RECORDED" == "1" ]] || return 0
	local deadline=$((SECONDS + DHCP_RESTORE_WAIT))
	local i node chassis local_config mismatch attempt=1
	local -a last_chassis=() last_local=()
	while :; do
		mismatch=0
		for i in 0 1; do
			if [[ "$i" == "0" ]]; then node="$FW0"; else node="$FW1"; fi
			chassis="$(ssh_fw "$node" '/usr/local/sbin/cli -c "show configuration chassis cluster | display set" 2>/dev/null' || true)"
			local_config="$(ssh_fw "$node" '/usr/local/sbin/cli -c "show configuration system services dhcp-local-server | display set" 2>/dev/null' || true)"
			last_chassis[i]="$chassis"
			last_local[i]="$local_config"
			if [[ "$chassis" != "${ORIGINAL_DHCP_CHASSIS[$i]}" ||
				"$local_config" != "${ORIGINAL_DHCP_LOCAL[$i]}" ]]; then
				mismatch=1
			fi
		done
		if ((mismatch == 0)); then
			info "cleanup verified DHCP fixture configuration matches the pre-run snapshots"
			return 0
		fi
		if ((SECONDS >= deadline)); then
			note_abort_cause "cleanup:config-restore-timeout"
			echo "FATAL: cleanup did not restore DHCP configuration before the ${DHCP_RESTORE_WAIT}s deadline; owner=test-dhcp-lease-failover" >&2
			for i in 0 1; do
				if [[ "$i" == "0" ]]; then node="$FW0"; else node="$FW1"; fi
				echo "  $node chassis before: ${ORIGINAL_DHCP_CHASSIS[$i]}" >&2
				echo "  $node chassis after:  ${last_chassis[$i]}" >&2
				echo "  $node local before:   ${ORIGINAL_DHCP_LOCAL[$i]}" >&2
				echo "  $node local after:    ${last_local[$i]}" >&2
			done
			return 1
		fi
		info "cleanup waiting for DHCP configuration restore (attempt $attempt)"
		sleep "$DHCP_RESTORE_POLL"
		attempt=$((attempt + 1))
	done
}

verify_client_namespaces() {
	local ns state ssh_rc
	for ns in "$NS_A" "$NS_B"; do
		ssh_rc=0
		state="$(ssh_fw "$DHCP_CLIENT" "if test -e /run/netns/'$ns'; then echo PRESENT; else echo ABSENT; fi")" || ssh_rc=$?
		if ((ssh_rc != 0)) || [[ "$state" != "PRESENT" && "$state" != "ABSENT" ]]; then
			note_abort_cause "cleanup:client-namespace-unverifiable"
			echo "FATAL: cleanup could not verify DHCP client namespace $ns on $DHCP_CLIENT (transport rc=$ssh_rc); owner=test-dhcp-lease-failover" >&2
			return 1
		fi
		if [[ "$state" == "PRESENT" ]]; then
			note_abort_cause "cleanup:client-namespace-left"
			echo "FATAL: cleanup left DHCP client namespace $ns behind on $DHCP_CLIENT; owner=test-dhcp-lease-failover" >&2
			return 1
		fi
	done
	info "cleanup verified DHCP client namespaces are absent"
	return 0
}

restore_cluster_state() {
	[[ "$ORIGINAL_STATE_RECORDED" == "1" ]] || return 0
	local rg target_node current_node current_instance target_instance
	local status all_ok current_role current_manual try

	# A hard reboot can leave every RG on the survivor. Transfer each one
	# back from its current primary, after clearing stale manual pins on both
	# nodes. The request is intentionally made on the current primary: this is
	# the same CLI shape used by the existing HA failover gates.
	for rg in "${!ORIGINAL_RG_PRIMARY[@]}"; do
		target_node="${ORIGINAL_RG_PRIMARY[$rg]}"
		current_node="$(cluster_status | cluster_state_rows | cluster_primary_node_from_status "$rg")"
		[[ "$current_node" == "$target_node" ]] && continue
		for node in "$FW0" "$FW1"; do
			incus exec "$node" -- /usr/local/sbin/cli -c \
				"request chassis cluster failover reset redundancy-group $rg" \
				>/dev/null 2>&1 || true
		done
		case "$current_node" in
		node0) current_instance="$FW0" ;;
		node1) current_instance="$FW1" ;;
		*) note_abort_cause "cleanup:current-rg-owner-unreadable"; echo "FATAL: cleanup cannot identify the current RG${rg} primary; owner=test-dhcp-lease-failover" >&2; return 1 ;;
		esac
		incus exec "$current_instance" -- /usr/local/sbin/cli -c \
			"request chassis cluster failover redundancy-group $rg" \
			>/dev/null 2>&1 || true
	done

	# The transfer request creates a manual pin. Wait for ownership to land
	# before clearing it; resetting immediately races the election and can
	# leave the cluster on the survivor even though the CLI returned success.
	all_ok=0
	for ((try = 0; try < 30; try++)); do
		status="$(cluster_status)"
		all_ok=1
		for rg in "${!ORIGINAL_RG_PRIMARY[@]}"; do
			current_node="$(printf '%s\n' "$status" | cluster_state_rows | cluster_primary_node_from_status "$rg")"
			[[ "$current_node" == "${ORIGINAL_RG_PRIMARY[$rg]}" ]] || all_ok=0
		done
		((all_ok)) && break
		sleep 2
	done
	if (( ! all_ok )); then
		note_abort_cause "cleanup:rg-owner-restore-timeout"
		echo "FATAL: cleanup could not restore the recorded cluster owners before pin cleanup; owner=test-dhcp-lease-failover" >&2
		printf '%s\n' "$status" >&2
		return 1
	fi

	# Reproduce the recorded manual state only after every owner is correct.
	# The normal lab state has manual=no, so reset both nodes to clear the
	# transfer pins; a pre-existing manual=yes state is explicitly re-pinned.
	for rg in "${!ORIGINAL_RG_PRIMARY[@]}"; do
		target_node="${ORIGINAL_RG_PRIMARY[$rg]}"
		if [[ "${ORIGINAL_RG_MANUAL[$rg]:-no}" == "yes" ]]; then
			case "$target_node" in
			node0) target_instance="$FW0" ;;
			node1) target_instance="$FW1" ;;
			*) note_abort_cause "cleanup:recorded-rg-owner-invalid"; echo "FATAL: cleanup has an invalid recorded RG${rg} owner '$target_node'; owner=test-dhcp-lease-failover" >&2; return 1 ;;
			esac
			incus exec "$target_instance" -- /usr/local/sbin/cli -c \
				"request chassis cluster failover redundancy-group $rg node ${target_node#node}" \
				>/dev/null 2>&1 || true
		else
			for node in "$FW0" "$FW1"; do
				incus exec "$node" -- /usr/local/sbin/cli -c \
					"request chassis cluster failover reset redundancy-group $rg" \
					>/dev/null 2>&1 || true
			done
		fi
	done

	for ((try = 0; try < 30; try++)); do
		status="$(cluster_status)"
		all_ok=1
		for rg in "${!ORIGINAL_RG_PRIMARY[@]}"; do
			current_node=""
			current_role=""
			read -r current_node current_role current_manual < <(
				printf '%s\n' "$status" | cluster_state_rows |
					awk -v want="$rg" '$1 == want && $3 == "primary" { print $2, $3, $4; exit }'
			) || true
			if [[ "$current_node" != "${ORIGINAL_RG_PRIMARY[$rg]}" ||
				"$current_role" != "primary" ||
				"$current_manual" != "${ORIGINAL_RG_MANUAL[$rg]}" ]]; then
				all_ok=0
			fi
		done
		if ((all_ok)); then
			info "cleanup verified original cluster ownership and manual-pin state"
			return 0
		fi
		sleep 2
	done
	note_abort_cause "cleanup:cluster-state-restore-timeout"
	echo "FATAL: cleanup could not restore the recorded cluster ownership/manual-pin state; owner=test-dhcp-lease-failover" >&2
	printf '%s\n' "$status" >&2
	return 1
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
	local cleanup_failed=0
	ns_down "$NS_A"
	ns_down "$NS_B"
	incus exec "$DHCP_CLIENT" -- rm -f "$CLIENT_SCRIPT" >/dev/null 2>&1 || true
	if [ "$PROVISIONED_KNOB" = "1" ]; then
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
	fi
	verify_client_namespaces || cleanup_failed=1
	verify_dhcp_config || cleanup_failed=1
	if ! restore_cluster_state; then
		cleanup_failed=1
	fi
	# A cleanup failure must make the wrapper record VOID rather than
	# publishing a PASS while the shared lab or its fixture remains dirty.
	((cleanup_failed == 0)) || return 1
}

cleanup_on_exit() {
	local run_rc="$?"
	trap - EXIT ERR
	set +e
	restore_dhcp
	local cleanup_rc="$?"
	if ((cleanup_rc != 0)); then
		note_abort_cause "cleanup:restore-failed"
		echo "DHCP failover cleanup failed after the detailed cause; owner=test-dhcp-lease-failover" >&2
		exit 2
	fi
	exit "$run_rc"
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

# lease_sync_count <node> <field> prints one column of the "DHCP leases" row of
# `show chassis cluster statistics`: field 3 is Sent, field 4 is Received
# (#9791). The counters reset when cluster comms restart, so compare values read
# in the same window, never across a reboot.
lease_sync_count() {
	ssh_fw "$1" '/usr/local/sbin/cli -c "show chassis cluster statistics" 2>/dev/null' | awk -v f="$2" '$1 == "DHCP" && $2 == "leases" { print $f; exit }'
}

# ns_down <ns> stops the namespace's clients and deletes it (the macvlan goes with it).
ns_down() {
	# #9729: RELEASE the v4 lease first. Every run's client is a fresh random MAC,
	# and an unreleased lease stays bound for its full lifetime (86400s in the lab),
	# so reruns filled the pool with dead owners whose addresses got reused.
	ssh_fw "$DHCP_CLIENT" "if [ -e /run/netns/'$1' ] && [ -f /run/dhclient-$1.leases ]; then timeout 15 nsenter --net=/run/netns/'$1' dhclient -r -sf '$CLIENT_SCRIPT' -pf /run/dhclient-$1.pid -lf /run/dhclient-$1.leases \$(nsenter --net=/run/netns/'$1' ip -o link show | awk -F': ' '{sub(/@.*/, \"\", \$2)} \$2 != \"lo\" {print \$2; exit}') 2>/dev/null; fi; for f in /run/dhclient-$1.pid /run/dhclient6-$1.pid; do [ -f \$f ] && kill \$(cat \$f) 2>/dev/null; rm -f \$f; done; rm -f /run/dhclient-$1.leases /run/dhclient6-$1.leases; ip netns del '$1' 2>/dev/null; true" >/dev/null 2>&1 || true
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
	install_abort_trap
	trap cleanup_on_exit EXIT
	record_cluster_state
	record_dhcp_config_state
	preflight

	local original_rg0
	PRIMARY="$(rg0_primary_node "$FW0")"
	[ -n "$PRIMARY" ] || PRIMARY="$(rg0_primary_node "$FW1")"
	[ -n "$PRIMARY" ] || die "cannot read the RG0 primary from either node"
	case "${ORIGINAL_RG_PRIMARY[0]}" in
	node0) original_rg0="$FW0" ;;
	node1) original_rg0="$FW1" ;;
	*) die "recorded RG0 owner is invalid: ${ORIGINAL_RG_PRIMARY[0]}" ;;
	esac
	[ "$PRIMARY" = "$original_rg0" ] ||
		die "RG0 owner changed during preflight (was $original_rg0, now $PRIMARY)"
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

	info "2) Gate the standby memfile header byte-exactness (Kea 3.0.x golden)"
	# #9729 run 6: this step used to also look for the leased address in the
	# standby memfile before the failover, and passed on a row for the SAME address
	# held by a previous run's client. The standby rewrites that file only at
	# takeover (the #5040 pre-seed), so no pre-takeover row check can see this
	# lease. The binding is asserted after promotion instead (step 4b).
	assert_memfile_header "$STANDBY" "$KEA_MEMFILE4" "$GOLDEN_HEADER4" 4
	if [ "$DHCP_V6" = "1" ]; then
		assert_memfile_header "$STANDBY" "$KEA_MEMFILE6" "$GOLDEN_HEADER6" 6
	fi
	local mac_a
	# Read the MAC over netlink inside the namespace, the way ns_addr4 reads the
	# address. /sys/class/net lists the devices of the network namespace that
	# MOUNTED sysfs, so `nsenter --net ... cat /sys/class/net/<if>/address` cannot
	# see the namespace's macvlan (#9791 lab run 1: "cannot read client A's MAC").
	# `ip netns exec` would remount sysfs, but the LAN host is an unprivileged
	# container that may not ("mount of /sys failed: Operation not permitted",
	# run 2).
	mac_a="$(ssh_fw "$DHCP_CLIENT" "nsenter --net=/run/netns/'$NS_A' ip -o link show dev '$IF_A'" 2>/dev/null | grep -o 'link/ether [0-9a-f:]*' | cut -d' ' -f2 | head -1 || true)"
	[[ -n "$mac_a" ]] || die "cannot read client A's MAC"

	# #9791: the reboot below tests the takeover pre-seed only if client A's
	# grant has reached the standby. The primary pushes its full lease set on a
	# 2 s change poll, and each set the standby receives bumps a counter visible
	# on that node. So gate the reboot on the standby RECEIVING a set after the
	# grant. Without this gate, "the pre-seed dropped A's binding" and "A's
	# binding never left the primary" fail step 4b identically.
	local rx_at_grant rx_now="" sent_now waited=0
	rx_at_grant="$(lease_sync_count "$STANDBY" 4 || true)"
	[[ "$rx_at_grant" =~ ^[0-9]+$ ]] || die "cannot read the standby's DHCP lease-sync Received counter from 'show chassis cluster statistics'"
	while (( waited < 30 )); do
		rx_now="$(lease_sync_count "$STANDBY" 4 || true)"
		if [[ "$rx_now" =~ ^[0-9]+$ ]] && (( rx_now > rx_at_grant )); then
			break
		fi
		sleep 2
		waited=$((waited + 2))
	done
	sent_now="$(lease_sync_count "$PRIMARY" 3 || true)"
	if [[ "$rx_now" =~ ^[0-9]+$ ]] && (( rx_now > rx_at_grant )); then
		# One more change-poll tick: a push already in flight at the grant can
		# land first, carrying the set read before the grant.
		sleep 4
		pass "the standby received a DHCP lease set after client A's grant (standby received ${rx_at_grant} -> $(lease_sync_count "$STANDBY" 4 || true); primary sent ${sent_now})"
	else
		fail "the standby received NO DHCP lease set within 30s of client A's grant (standby received stayed ${rx_at_grant}; primary sent ${sent_now}) — lease sync did not deliver, so a step-4b failure below is not evidence about the pre-seed (#9791)"
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
		# Match Kea's memfile LOAD failures by message id, not any line carrying
		# "error". #9791 lab run 4 failed this cell on DHCP4_BUFFER_RECEIVE_FAIL
		# ("Value of the length of the IP header must not be lower than 5
		# words"): a packet-receive error on the raw socket, unrelated to loading
		# the lease file. DHCPSRV_MEMFILE_* is the memfile backend's id family, so
		# its ERROR/FAIL members, a discarded row, and a server init or config
		# load failure are what (a) is about.
		if ssh_fw "$STANDBY" "journalctl -u kea-dhcp4-server --since @$since 2>/dev/null | grep -E 'DHCPSRV_MEMFILE_[A-Z_]*(ERROR|FAIL)|ROW_ERROR|DHCP4_(INIT_FAIL|CONFIG_LOAD_FAIL)'"; then
			fail "Kea reported a memfile load error on the promoted node"
		else
			pass "no Kea memfile load error on the promoted node since the failover"
		fi
	else
		fail "no Kea memfile lease-file load event on $STANDBY within ${REBOOT_WAIT}s of the failover (kea-dhcp4-server ActiveEnterTimestamp: $(ssh_fw "$STANDBY" 'systemctl show -p ActiveEnterTimestamp --value kea-dhcp4-server' 2>/dev/null || echo unknown)); (a) cannot be judged on a load that did not happen"
	fi

	info "4b) the promoted node's lease file binds $addr4 to client A ($mac_a)"
	# The pre-seed writes the union of the local and held peer leases at takeover;
	# the LAST row for an address is the binding Kea keeps. A row naming another
	# MAC is a stale owner, which then refuses client A's renewal (#9791).
	local last_row
	last_row="$(ssh_fw "$STANDBY" "grep '^${addr4},' '$KEA_MEMFILE4' | tail -1" 2>/dev/null || true)"
	if [[ "$(cut -d, -f2 <<<"$last_row")" == "$mac_a" ]]; then
		pass "promoted lease file binds $addr4 to client A ($mac_a)"
	else
		fail "promoted lease file binds $addr4 to '$(cut -d, -f2 <<<"$last_row")', not client A ($mac_a); a stale owner would refuse A's renewal (#9791)"
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
		fail "client A did not keep $addr4 by REQUEST/ACK (now '${addr4b:-none}'); DHCP messages: $(grep -E 'DHCP(DISCOVER|OFFER|REQUEST|ACK|NAK|DECLINE|RELEASE)' <<<"$renew" | tr '\n' ';' | cut -c1-600)"
		# #9729 run 5: diagnose rather than guess. Show the client's MAC and what the
		# promoted node's Kea holds for both addresses at this moment.
		echo "  -- client A MAC: $(ssh_fw "$DHCP_CLIENT" "nsenter --net=/run/netns/'$NS_A' ip -br link show dev '$IF_A'" 2>/dev/null | awk '{print $3}')" >&2
		echo "  -- promoted Kea memfile rows for $addr4 / ${addr4b:-none}:" >&2
		ssh_fw "$STANDBY" "grep -E '^(${addr4}|${addr4b:-0.0.0.0}),' '$KEA_MEMFILE4' | tail -6" >&2 || true
	fi

	echo
	# #9729: the canonical line the ha-smoke ledger adapter parses.
	echo "  DHCP lease-failover test: $PASS passed, $FAIL failed"
	if ((FAIL > 0)); then
		printf ' - %s\n' "${ERRORS[@]}" >&2
		exit 1
	fi
}

# Executed only (see the sourced-vs-executed guard above): sourcing defines
# the functions and returns without taking the lock or running the gate.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	main "$@"
fi
