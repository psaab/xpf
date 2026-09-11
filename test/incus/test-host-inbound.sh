#!/usr/bin/env bash
# xpf on-wire host-inbound smoke — #6936 (residual of #4422).
#
# Covers the two legs the pkg/config host-inbound suite structurally cannot:
# host-inbound resolved on a TAGGED VLAN sub-unit, and admission UNCHANGED
# across an HA failover. Commits nothing. Full rationale — including why a
# DENY cell is scored against a same-address positive control and why the
# failover leg diffs the matrix rather than re-scoring it — is in the block
# below the lock preamble and in docs/host-inbound-service-matrix.md.
#
# Usage:
#   ./test/incus/test-host-inbound.sh                  # matrix only (fast)
#   ./test/incus/test-host-inbound.sh --with-failover  # + HA-failover leg
#
# Env:
#   HI_PROBE_TIMEOUT=3   seconds a TCP cell waits before scoring TIMEOUT
#   HI_SETTLE=8          seconds to let VRRP settle after a manual failover

set -euo pipefail

case "${1:-}" in
-h | --help)
	sed -n '2,17p' "$0"
	exit 0
	;;
esac

# #1875/#4020: with --with-failover this smoke MOVES REDUNDANCY GROUPS on the
# SHARED loss cluster. Re-exec under the incus-admin group if needed, then
# serialize as a #1875 lock cell so a concurrent deploy/smoke cannot collide
# with our failover (it queues behind a held /tmp/xpf-cluster.lock). Taken
# unconditionally rather than only for the failover leg: the matrix run pushes
# a file into the LAN prober and reads cluster state, and a lock cell that is
# sometimes taken is a lock cell nobody can reason about.
_CELL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=cluster-cell.sh
source "${_CELL_DIR}/cluster-cell.sh"
xpf_enter_destructive_cluster_cell "test-host-inbound $*" "$0" "$@"

# WHAT THIS COVERS THAT THE UNIT TESTS CANNOT
#
# pkg/config carries a large host-inbound suite (host_inbound_per_iface_3362,
# host_inbound_view_3654, host_inbound_tokens, ...). Every one of them shows
# what the COMPILER produced. None can show what the BOX ADMITTED. #6936 names
# the two on-wire legs that were never covered:
#
#   VLAN            — tagged sub-unit addresses (reth0.50 / reth0.80) are
#                     host-inbound targets, not just the untagged interface.
#                     Every probe ARRIVES on lan (the prober is the LAN host),
#                     and since #9637 host-inbound is judged by the zone a
#                     packet arrives on, whichever zone owns the address it
#                     names. So every cell is scored against lan's posture:
#                     ssh ADMIT at every address, the wan-owned sub-units
#                     included; telnet DENY everywhere, because no zone admits
#                     it; ping ADMIT as the same-address control. Before
#                     #9637 a tcp/22 probe to a wan address was dropped by the
#                     address owner's posture. That was the over-refusal #9637
#                     measured on this cluster, and this table used to assert
#                     it.
#   HA failover     — admission is UNCHANGED after the redundancy groups move
#                     to the peer node. The failure mode is silent: an
#                     admission that quietly stops working after a failover
#                     looks, to a prober, exactly like a service that is
#                     correctly denied.
#
# HOW THE SILENT FAILURE MODE IS KEPT VISIBLE
#
# A probe cannot observe a deny. It observes SILENCE, and "the firewall dropped
# it" and "my prober never reached the firewall" are the same reading. So:
#
#   * every DENY cell is scored against a POSITIVE CONTROL at the SAME
#     ADDRESS, SAME FAMILY, SAME RUN, SAME PROBER — an ICMP echo to that exact
#     address. A DENY cell whose control did not answer is scored FAIL
#     (blind), never PASS. host-inbound-lib.sh makes that verdict total and
#     host-inbound-selftest.sh drives the middle row.
#   * the prober distinguishes an RST from a timeout. xpfd binds its own
#     listeners on 127.0.0.1 only, so an admitted probe of a non-listening
#     port comes back as an RST — a packet-carrying POSITIVE signal that
#     host-inbound let it through. Without that, "admitted, nothing listening"
#     and "dropped" would be the same timeout.
#   * the failover leg asserts the matrix is IDENTICAL across the failover,
#     not merely that it still passes. A run where every admission silently
#     died would still satisfy every DENY cell; only the diff sees it.
#
# It commits NOTHING. It reads the already-committed cluster config, derives
# its probe targets from it, and refuses to run if the zone posture it depends
# on has changed — so it can neither dirty the shared cluster nor silently
# assert a stale matrix.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/incus/cluster-env.sh
source "${SCRIPT_DIR}/cluster-env.sh"
# shellcheck source=test/incus/host-inbound-lib.sh
source "${SCRIPT_DIR}/host-inbound-lib.sh"

WITH_FAILOVER=0
for arg in "$@"; do
	case "$arg" in
	--with-failover) WITH_FAILOVER=1 ;;
	-h | --help) ;; # handled before the lock preamble
	*)
		echo "unknown argument: $arg" >&2
		exit 2
		;;
	esac
done

HI_PROBE_TIMEOUT="${HI_PROBE_TIMEOUT:-3}"
HI_SETTLE="${HI_SETTLE:-8}"
PROBE_SRC="${SCRIPT_DIR}/host_inbound_probe.py"
REMOTE_PROBE="/tmp/xpf-host_inbound_probe.py"
CLI=/usr/local/sbin/cli

PASS=0
FAIL=0
ERRORS=()

info() { echo "==> $*"; }
pass() { echo "  PASS  $*"; PASS=$((PASS + 1)); }
fail() {
	echo "  FAIL  $*"
	FAIL=$((FAIL + 1))
	ERRORS+=("$*")
}
die() {
	echo "FATAL: $*" >&2
	exit 2
}

# score <verdict-line> — map a "PASS <why>" / "FAIL <why>" line from the lib
# onto this script's counters. The lib's verdicts are TOTAL, so the catch-all
# is unreachable in principle; it is here because a verdict word this script
# does not recognise must be an error, not a silent skip.
score() {
	local label="$1" verdict="$2"
	case "$verdict" in
	PASS\ *) pass "${label}: ${verdict#PASS }" ;;
	FAIL\ *) fail "${label}: ${verdict#FAIL }" ;;
	*) fail "${label}: verdict helper returned an unrecognised line: ${verdict:-<empty>}" ;;
	esac
}

# ── Phase 0: preconditions ───────────────────────────────────────────

[[ -f "$PROBE_SRC" ]] || die "prober missing: $PROBE_SRC"

# `grep -q` would exit on the first match and SIGPIPE `incus info`; under
# `set -o pipefail` the pipeline then reports the WRITER's failure and a
# RUNNING instance reads as down. Consume the whole stream (the same shape
# test-active-active.sh uses) so the check measures the status, not the pipe.
for inst in "$FW0" "$FW1" "$CLUSTER_LAN_HOST"; do
	[[ "$(incus info "$inst" 2>/dev/null | grep -o "RUNNING" | head -1)" == "RUNNING" ]] \
		|| die "$inst is not RUNNING — bring the cluster up first (make cluster-deploy)"
done
info "cluster instances up: $FW0, $FW1, $CLUSTER_LAN_HOST"

# Read the ACTIVE config in flat-set form. `display set` gives whole-line
# tokens, so the posture questions below are exact-line matches rather than
# brace parsing.
ZONE_SETS="$(incus exec "$FW0" -- "$CLI" -c "show configuration security zones | display set" 2>/dev/null || true)"
IFACE_SETS="$(incus exec "$FW0" -- "$CLI" -c "show configuration interfaces | display set" 2>/dev/null || true)"

hi_config_readable "$ZONE_SETS" \
	|| die "could not read 'show configuration security zones | display set' from $FW0 — the matrix's expectations are unverified, so refusing to run (an unreadable config answers every ABSENT question the way a healthy one does)"
hi_config_readable_iface "$IFACE_SETS" \
	|| die "could not read 'show configuration interfaces | display set' from $FW0 — probe targets are derived from it"
info "read $(grep -c . <<<"$ZONE_SETS") zone and $(grep -c . <<<"$IFACE_SETS") interface set-lines from $FW0"

# The matrix below is only correct for this posture. Check it rather than
# assume it: on a shared cluster the config is not this script's to own, and
# an expectation table that has silently gone stale reports a clean pass while
# asserting the wrong thing.
info "Phase 0: zone posture the matrix depends on"
score "posture lan/ssh" "$(hi_zone_service_verdict "$ZONE_SETS" lan ssh PRESENT)"
score "posture lan/ping" "$(hi_zone_service_verdict "$ZONE_SETS" lan ping PRESENT)"
score "posture wan/ping" "$(hi_zone_service_verdict "$ZONE_SETS" wan ping PRESENT)"
score "posture wan/ssh" "$(hi_zone_service_verdict "$ZONE_SETS" wan ssh ABSENT)"
score "posture lan/telnet" "$(hi_zone_service_verdict "$ZONE_SETS" lan telnet ABSENT)"
score "posture wan/telnet" "$(hi_zone_service_verdict "$ZONE_SETS" wan telnet ABSENT)"
# #9637: every probe arrives on the LAN host's segment, reth1. The ssh cells
# below are scored against that zone's posture, so the zone must own reth1.
PROBER_ZONE=lan
# The committed config spells the member either `reth1` or `reth1.0`, and an
# interface-level host-inbound override follows it on the same line (the loss
# cluster's own config reads `... interfaces reth1 host-inbound-traffic ...`).
if grep -qE "^set security zones security-zone ${PROBER_ZONE} interfaces reth1(\.0)?( |$)" <<<"$ZONE_SETS"; then
	pass "posture ${PROBER_ZONE}/reth1: the prober's ingress interface is in ${PROBER_ZONE}, whose posture scores every ssh cell"
else
	fail "posture ${PROBER_ZONE}/reth1: ${PROBER_ZONE} no longer owns the prober's ingress interface — the ssh cells would be scored against the wrong zone"
fi
for tagged in reth0.50 reth0.80; do
	if grep -qxF "set security zones security-zone wan interfaces ${tagged}" <<<"$ZONE_SETS"; then
		pass "posture wan/${tagged}: the wan zone owns the tagged sub-unit (this is the VLAN leg's subject)"
	else
		fail "posture wan/${tagged}: the wan zone no longer owns this VLAN sub-unit — the VLAN cells below would measure some other zone's posture"
	fi
done
[[ "$FAIL" -eq 0 ]] || die "zone posture precondition failed — update the expectation table rather than weakening a cell"

# ── Phase 1: derive probe targets from the box's own config ──────────

declare -A TARGET_ADDR TARGET_FAMILY TARGET_ZONE
add_target() {
	local name="$1" iface="$2" unit="$3" family="$4" zone="$5" addr
	addr="$(hi_iface_address "$IFACE_SETS" "$iface" "$unit" "$family")"
	[[ -n "$addr" ]] \
		|| die "no ${family} address configured on ${iface} unit ${unit} — cannot derive the ${name} probe target (refusing to fall back to a hard-coded lab address, which would silently probe something else)"
	TARGET_ADDR[$name]="$addr"
	TARGET_FAMILY[$name]="$family"
	TARGET_ZONE[$name]="$zone"
}

# reth1 is UNTAGGED and in the lan zone (admits ssh + ping): the positive
# controls and the per-service discrimination cells.
add_target lan-v4 reth1 0 inet lan
add_target lan-v6 reth1 0 inet6 lan
# reth0.50 / reth0.80 are TAGGED sub-units in the wan zone (admits ping, not
# ssh): the VLAN leg, both tags, both families.
add_target wan-vlan50-v4 reth0 50 inet wan
add_target wan-vlan50-v6 reth0 50 inet6 wan
add_target wan-vlan80-v4 reth0 80 inet wan
add_target wan-vlan80-v6 reth0 80 inet6 wan

TARGET_ORDER=(lan-v4 lan-v6 wan-vlan50-v4 wan-vlan50-v6 wan-vlan80-v4 wan-vlan80-v6)
for t in "${TARGET_ORDER[@]}"; do
	info "target ${t} = ${TARGET_ADDR[$t]} (zone ${TARGET_ZONE[$t]}, ${TARGET_FAMILY[$t]})"
done

# Remove first: an existing 0755 file from a previous run makes the push fail
# with "permission denied" (the same shape test-fbf-steering.sh guards with an
# `rm -f` before its own push).
incus exec "$CLUSTER_LAN_HOST" -- rm -f "$REMOTE_PROBE" >/dev/null 2>&1 || true
incus file push --mode 0755 "$PROBE_SRC" "${CLUSTER_LAN_HOST}${REMOTE_PROBE}" >/dev/null \
	|| die "could not push the prober to $CLUSTER_LAN_HOST"

# ── Phase 2: the matrix ──────────────────────────────────────────────

# run_matrix <label>
#   Probe every cell once and echo "<cell-name> <observation>" lines on stdout.
#   Diagnostics go to stderr so the caller can capture the observations
#   cleanly for hi_matrix_stable_verdict.
run_matrix() {
	local label="$1" t addr specs=() probe_out ping_out obs
	for t in "${TARGET_ORDER[@]}"; do
		addr="${TARGET_ADDR[$t]}"
		specs+=("${addr}|22" "${addr}|23")
	done
	echo "==> [${label}] TCP cells: ${#specs[@]}" >&2
	probe_out="$(incus exec "$CLUSTER_LAN_HOST" --env "HI_PROBE_TIMEOUT=${HI_PROBE_TIMEOUT}" \
		-- python3 "$REMOTE_PROBE" "${specs[@]}" 2>&1 || true)"
	echo "$probe_out" | sed 's/^/    /' >&2

	for t in "${TARGET_ORDER[@]}"; do
		addr="${TARGET_ADDR[$t]}"
		# ICMP: the per-target positive control. -n so a broken resolver
		# cannot stall the cell; 3 packets so a single loss is not the
		# whole reading.
		if [[ "${TARGET_FAMILY[$t]}" == inet6 ]]; then
			ping_out="$(incus exec "$CLUSTER_LAN_HOST" -- ping -6 -n -c 3 -W 2 "$addr" 2>&1 || true)"
		else
			ping_out="$(incus exec "$CLUSTER_LAN_HOST" -- ping -4 -n -c 3 -W 2 "$addr" 2>&1 || true)"
		fi
		obs="$(hi_classify_ping "$ping_out")"
		printf '%s %s\n' "${t}-ping" "$obs"
		printf '%s %s\n' "${t}-ssh" "$(hi_classify_probe "$probe_out" "$addr" 22)"
		printf '%s %s\n' "${t}-telnet" "$(hi_classify_probe "$probe_out" "$addr" 23)"
	done
}

# score_matrix <label> <observations>
#   Apply the expectation table. Each DENY cell is controlled by the ping cell
#   at the SAME address — not by a global "the cluster is up" check, because a
#   route that stopped reaching THIS address would make every DENY cell at it
#   pass for the wrong reason.
score_matrix() {
	local label="$1" obs_lines="$2" t control ssh_expect
	for t in "${TARGET_ORDER[@]}"; do
		control="$(awk -v c="${t}-ping" '$1 == c { print $2; exit }' <<<"$obs_lines")"
		control="${control:-BLIND}"
		# ping is admitted in BOTH zones, so every ping cell is an ADMIT
		# cell; it is simultaneously the control for the two TCP cells at
		# this address.
		score "[${label}] ${t}-ping (control)" \
			"$(hi_cell_verdict ADMIT "$control" "$control")"
		# #9637: judged by the INGRESS zone. Every probe arrives on
		# ${PROBER_ZONE}, whose posture (asserted above) admits ssh, so ssh is
		# an ADMIT cell at every address. Scoring by the zone that OWNS the
		# address was the destination-only model #9637 replaced.
		ssh_expect=ADMIT
		score "[${label}] ${t}-ssh (arrives on ${PROBER_ZONE}, owned by ${TARGET_ZONE[$t]} -> ${ssh_expect})" \
			"$(hi_cell_verdict "$ssh_expect" "$(awk -v c="${t}-ssh" '$1 == c { print $2; exit }' <<<"$obs_lines")" "$control")"
		# telnet is admitted by NO zone here. On the lan address this is
		# the strongest cell in the file: same address, same prober, one
		# port admitted and another not — a reading no routing or
		# reachability story can explain away.
		score "[${label}] ${t}-telnet (no zone admits telnet -> DENY)" \
			"$(hi_cell_verdict DENY "$(awk -v c="${t}-telnet" '$1 == c { print $2; exit }' <<<"$obs_lines")" "$control")"
	done
}

rg_primary() {
	local rg="$1"
	incus exec "$FW0" -- "$CLI" -c "show chassis cluster status" 2>/dev/null |
		awk -v rg="$rg" '
			$0 ~ ("Redundancy group: " rg " ,") { inrg = 1; next }
			inrg && /Redundancy group:/ { inrg = 0 }
			inrg && $3 == "primary" { print $1; exit }'
}

info "Phase 1: host-inbound matrix (baseline)"
BASELINE="$(run_matrix baseline)"
score_matrix baseline "$BASELINE"

# ── Phase 3: the HA-failover leg ─────────────────────────────────────

if [[ "$WITH_FAILOVER" -eq 1 ]]; then
	FAILED_OVER=0
	restore_primacy() {
		[[ "$FAILED_OVER" -eq 1 ]] || return 0
		echo "==> Restoring node0 primacy for RG1/RG2" >&2
		local rg
		for rg in 1 2; do
			incus exec "$FW0" -- "$CLI" -c "request chassis cluster failover reset redundancy-group $rg" >/dev/null 2>&1 || true
			incus exec "$FW1" -- "$CLI" -c "request chassis cluster failover reset redundancy-group $rg" >/dev/null 2>&1 || true
			# `failover reset` only clears the MANUAL latch; with preempt
			# disabled the current master keeps the group, so an explicit
			# failover back to node 0 is required or the shared cluster is
			# left inverted for the next lane.
			incus exec "$FW0" -- "$CLI" -c "request chassis cluster failover redundancy-group $rg node 0" >/dev/null 2>&1 || true
		done
		sleep "$HI_SETTLE"
		for rg in 1 2; do
			incus exec "$FW0" -- "$CLI" -c "request chassis cluster failover reset redundancy-group $rg" >/dev/null 2>&1 || true
			incus exec "$FW1" -- "$CLI" -c "request chassis cluster failover reset redundancy-group $rg" >/dev/null 2>&1 || true
		done
	}
	trap restore_primacy EXIT

	info "Phase 2: manual failover of RG1 (WAN/reth0) and RG2 (LAN/reth1) to node1"
	FAILED_OVER=1
	for rg in 1 2; do
		incus exec "$FW1" -- "$CLI" -c "request chassis cluster failover redundancy-group $rg node 1" 2>&1 | sed 's/^/    /'
	done
	sleep "$HI_SETTLE"
	for rg in 1 2; do
		if [[ "$(rg_primary "$rg")" == "node1" ]]; then
			pass "RG${rg} primary is node1 after the manual failover"
		else
			fail "RG${rg} primary is '$(rg_primary "$rg")' after the manual failover, expected node1 — the leg below would measure the pre-failover node and prove nothing"
		fi
	done

	info "Phase 3: host-inbound matrix (after failover to node1)"
	AFTER="$(run_matrix after-failover)"
	score_matrix after-failover "$AFTER"
	# The real assertion. Scoring each cell against its expectation is not
	# enough: a run in which every admission silently died still satisfies
	# every DENY cell. Only the diff against the pre-failover matrix sees an
	# admission that stopped working.
	score "matrix stability across failover" \
		"$(hi_matrix_stable_verdict baseline "$BASELINE" after-failover "$AFTER")"

	info "Phase 4: failing back to node0 and re-checking"
	restore_primacy
	FAILED_OVER=0
	trap - EXIT
	for rg in 1 2; do
		if [[ "$(rg_primary "$rg")" == "node0" ]]; then
			pass "RG${rg} primary is node0 after failback"
		else
			fail "RG${rg} primary is '$(rg_primary "$rg")' after failback, expected node0 — the SHARED cluster is left inverted for the next lane; fix it before leaving"
		fi
	done
	FAILBACK="$(run_matrix after-failback)"
	score_matrix after-failback "$FAILBACK"
	score "matrix stability across failback" \
		"$(hi_matrix_stable_verdict baseline "$BASELINE" after-failback "$FAILBACK")"
fi

# ── Summary ──────────────────────────────────────────────────────────

echo
echo "════════════════════════════════════════"
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo "════════════════════════════════════════"
if [[ "$FAIL" -gt 0 ]]; then
	echo
	echo "Failures:"
	for e in "${ERRORS[@]}"; do echo "  - $e"; done
	exit 1
fi
echo "PASS: on-wire host-inbound matrix complete"
