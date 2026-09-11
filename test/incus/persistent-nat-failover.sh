#!/usr/bin/env bash
# xpf persistent-NAT lease-survives-failover smoke (#7360).
#
# This codifies the one thing the unit fixtures cannot prove: that a REAL
# standby, fed by the live session-sync path, holds the persistence binding its
# peer minted — and that after a promotion the same client gets its previous
# translated port back on a NEW connection.
#
# TWO ASSERTIONS, AND THE FIRST IS THE SHARPER ONE.
#
#   (a) the STANDBY shows the binding while the peer is still primary. This
#       observes the mechanism directly: before #7360 the standby's
#       `persistent-nat-table` was empty no matter how many sessions it had
#       imported, because the synced reserve inserted a LiveAllocation with no
#       persistent_key and never touched persistent_by_source.
#   (b) after a failover, a NEW connection from the same client is translated to
#       the SAME source port.
#
# (b) MUST use a NEW connection. Holding an existing one open across the
# failover passes on unfixed code: #4388 already reserves the imported session's
# own translation, so the surviving connection keeps its port either way. What
# is lost is the LEASE that gives a SUBSEQUENT flow the same port. A smoke
# written against the surviving connection measures the half that already works.
#
# It is intentionally NOT wired into `make test` (it reboots a node on the
# SHARED loss cluster) and NOT into `make test-failover` (the default smoke
# config uses interface-mode source NAT and carries no persistent-NAT pool, so
# the assertions would be vacuous there). It applies its own pool rule inside
# the lock cell and restores the prior config on exit — see RESTORE below.
#
# STATUS (#9729): an earlier revision recorded this as not yet run green,
# blocked by the pool-mode SNAT return path on this cluster. Per #8573 and
# #8621 that topology blocker is gone and the acceptance was met once by a
# manual lab run. The script is now a Makefile gate
# (`make test-persistent-nat-failover`) that records a ledger row. It derives
# the RG0 primary and standby itself, and it asserts that the reboot really
# promoted the standby: with fw1 already primary at start (an ordinary
# leftover state on the shared cluster, #9452), the old hardcoded-fw0 flow
# compared the primary with itself, rebooted the standby and re-read an
# uninterrupted primary. That was a PASS that exercised neither sync nor
# promotion.
#
# The unit-level coverage does NOT depend on this: #7360's mechanism is bound by
# seven fail-on-revert cells in `userspace-dp/src/nat/tests_pool.rs` and a
# five-cell mutation matrix, and the cluster REGRESSION gate (`make
# test-failover`) is green. This script is the end-to-end acceptance on top of
# that, not the evidence for the fix.
#
# Usage:
#   ./test/incus/persistent-nat-failover.sh
set -euo pipefail

# #1875/#4020: DESTRUCTIVE — it fails a node over on the SHARED loss cluster.
# Serialize as a lock cell so a concurrent deploy/smoke queues behind us.
_CELL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=cluster-cell.sh
source "${_CELL_DIR}/cluster-cell.sh"
xpf_enter_destructive_cluster_cell "persistent-nat-failover $*" "$0" "$@"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/incus/cluster-env.sh
source "${SCRIPT_DIR}/cluster-env.sh"
# #6440: the piped-stdin CLI is a REPL that prints "error: ..." and still exits
# 0, so a config apply must be gated on the CLI's own SUCCESS MARKERS. Reuse the
# library rather than re-deriving them: the markers are pinned Go-side by
# cmd/cli/cos_apply_markers_6440_test.go, so a reworded CLI cannot silently
# un-arm this gate.
# shellcheck source=test/incus/cos-apply-lib.sh
source "${SCRIPT_DIR}/cos-apply-lib.sh"
# #4009: deploy_rolling_secondary_node reads `show chassis cluster status` and
# echoes the RG0 SECONDARY's node index. Reused here to find the PRIMARY, which
# is the only node that will accept `configure`.
# shellcheck source=test/incus/deploy-lib.sh
source "${SCRIPT_DIR}/deploy-lib.sh"

LAN_CLIENT="${LAN_CLIENT:-$CLUSTER_LAN_HOST}"
TARGET="${TARGET:-$IPERF_TARGET4}"
POOL_NAME="${POOL_NAME:-pnat7360}"
# A pool range distinct from anything the default config uses, so a leftover
# binding from another smoke cannot be mistaken for ours.
# The pool address must be one the upstream ROUTES BACK, or the SNAT'd flow's
# reply never returns and the smoke measures a broken path rather than the
# lease. An arbitrary in-subnet address (172.16.50.90) is not assigned to any
# interface and nothing answers ARP for it — measured: every connect failed
# while the pool was applied, on a target that is otherwise reachable. The WAN
# VIP follows the primary and is the address interface-mode SNAT would have
# used, so return traffic lands exactly as it does today.
POOL_ADDR="${POOL_ADDR:-$WAN_VIP4}"
POOL_LOW="${POOL_LOW:-51000}"
POOL_HIGH="${POOL_HIGH:-51099}"
PNAT_TIMEOUT="${PNAT_TIMEOUT:-300}"
# The cluster's zones are lan/wan (docs/ha-cluster-userspace.conf), not
# trust/untrust. The rule-set is INTERFACE-scoped on purpose: source-NAT rules
# are emitted in #4161 SCOPE-TIER order, interface-scoped (tier 0) before
# zone-scoped (tier 1), so this takes precedence over the cluster's existing
# zone-scoped `lan-to-wan` interface-SNAT rule WITHOUT deleting it. Removing
# that rule for the duration would leave the shared cluster without its SNAT if
# this script died mid-run.
# The cluster's existing zone-scoped SNAT rule (docs/ha-cluster-userspace.conf).
SNAT_RULESET="${SNAT_RULESET:-lan-to-wan}"
SNAT_RULE="${SNAT_RULE:-snat}"
REBOOT_WAIT="${REBOOT_WAIT:-60}"

PASS=0
FAIL=0
ERRORS=()
info() { echo "==> $*"; }
pass() { echo "  PASS  $*"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL  $*"; FAIL=$((FAIL + 1)); ERRORS+=("$*"); }
die()  { echo "FATAL: $*" >&2; exit 2; }

fw_cli() { incus exec "$1" -- /usr/local/sbin/cli -c "$2" 2>/dev/null; }
fw_sh()  { incus exec "$1" -- bash -lc "$2"; }

# The persistent-NAT binding for our client, as the node reports it.
# Columns: Source IP | SrcPort | NAT IP | NATPort | Pool | Timeout
# (pkg/natshow/persistent.go RenderPersistent).
binding_natport() {
	local node="$1" src_ip="$2"
	fw_cli "$node" "show security nat source persistent-nat-table" \
		| awk -v ip="$src_ip" '$1 == ip { print $4; exit }'
}

binding_count() {
	local node="$1"
	fw_cli "$node" "show security nat source persistent-nat-table" \
		| awk '/^Total persistent NAT bindings:/ { print $5; exit } /^No persistent NAT bindings/ { print 0; exit }'
}

# ---------------------------------------------------------------------------
# Config apply / restore. The shared cluster's committed config has no
# persistent-NAT pool, so we add one for the run and roll back after — the
# cluster is shared and the next lane's smoke must see what it expects.
# ---------------------------------------------------------------------------
CONFIG_APPLIED=0
PNAT_TMP="$(mktemp -d)"
PRIMARY=""
cleanup_tmp() { rm -rf "$PNAT_TMP"; }

# PER-POOL, not per-rule. `persistent-nat` is modelled under
# `security nat source pool <name>` (pkg/config/schema_security.go). The
# rule-level `then source-nat pool <name> persistent-nat { ... }` Junos spelling
# is deliberately NOT in setSchema, so a rule-level form is REJECTED at commit,
# and the leaf is `inactivity-timeout`, not `timeout`.
#
# RETARGET the cluster's EXISTING `lan-to-wan` rule rather than adding a new
# rule-set. Two reasons, both measured against the real compilers rather than
# guessed:
#
#   * an INTERFACE-scoped rule-set does not compile. `pkg/dataplane`'s
#     compileNAT requires a resolvable FromZone/ToZone and an interface-scoped
#     rule-set has neither, so it fails with `source NAT from-zone "" not
#     found`. (`pkg/config` accepts it — the two compilers disagree, so
#     validating against only the first is not enough.)
#   * a second ZONE-scoped rule-set would race the existing one for precedence.
#     Retargeting the rule that already matches is deterministic.
#
# `configure` FIRST: without it every `set` lands in operational mode and the
# REPL answers "unknown command: set" for each, then exits 0.
#
# `rollback 0` SECOND, and it is not belt-and-braces. A failed commit leaves its
# `set`s in the CANDIDATE, and the next session's `configure` picks that
# candidate up — so a run that died with one scope kind poisons the next with
# "the `from` clause mixes 2 scope kinds" (#4881), an error about config neither
# run wrote.
pnat_config_session() {
	cat <<EOF
configure
rollback 0
delete security nat source pool ${POOL_NAME}
set security nat source pool ${POOL_NAME} address ${POOL_ADDR}/32
set security nat source pool ${POOL_NAME} port range low ${POOL_LOW} high ${POOL_HIGH}
set security nat source pool ${POOL_NAME} persistent-nat permit any-remote-host
set security nat source pool ${POOL_NAME} persistent-nat inactivity-timeout ${PNAT_TIMEOUT}
delete security nat source rule-set ${SNAT_RULESET} rule ${SNAT_RULE} then source-nat interface
set security nat source rule-set ${SNAT_RULESET} rule ${SNAT_RULE} then source-nat pool ${POOL_NAME}
commit
exit
quit
EOF
}

# The PRIMARY is the only node that accepts `configure` — the secondary answers
# "node is not primary for RG0, configure on the primary node", and HA config
# sync carries the commit to the peer. Applying on both is not merely redundant,
# it FAILS on the standby.
primary_node() {
	local status secondary
	status="$(fw_cli "$FW0" "show chassis cluster status" || true)"
	secondary="$(printf '%s\n' "$status" | deploy_rolling_secondary_node)"
	if [ "$secondary" = "0" ]; then echo "$FW1"; else echo "$FW0"; fi
}

# rg0_primary_node <query-node> prints the node holding RG0 primary as seen from
# <query-node>, or nothing when the RG0 row cannot be read. Unlike primary_node
# it never defaults to fw0: asked on the survivor right after the primary was
# rebooted, a silent default would report "fw0 is primary" and fail a real
# promotion, or pass a missing one (#9729).
rg0_primary_node() {
	local status row0 row1
	status="$(fw_cli "$1" "show chassis cluster status" || true)"
	row0="$(printf '%s\n' "$status" | awk '/^Redundancy group:[[:space:]]/ {rg=$3; next} rg=="0" && $1=="node0" {print tolower($3); exit}')"
	row1="$(printf '%s\n' "$status" | awk '/^Redundancy group:[[:space:]]/ {rg=$3; next} rg=="0" && $1=="node1" {print tolower($3); exit}')"
	case "$row0/$row1" in
	primary*/*) echo "$FW0" ;;
	*/primary*) echo "$FW1" ;;
	esac
}

apply_pnat_config() {
	PRIMARY="$(primary_node)"
	if [ "$PRIMARY" = "$FW0" ]; then STANDBY="$FW1"; else STANDBY="$FW0"; fi
	info "roles: RG0 primary=$PRIMARY standby=$STANDBY"
	info "Retargeting ${SNAT_RULESET}/${SNAT_RULE} at a persistent-NAT pool on the PRIMARY ($PRIMARY)"
	local out="${PNAT_TMP}/apply.out"
	pnat_config_session | incus exec "$PRIMARY" -- /usr/local/sbin/cli >"$out" 2>&1 || true
	# Gate on the marker, never the exit status (#6440).
	cos_require_markers "persistent-nat apply on $PRIMARY" "$out" \
		"$COS_MARKER_COMMIT" || die "config apply failed on $PRIMARY"
	CONFIG_APPLIED=1
	pass "persistent-NAT pool ${POOL_NAME} committed on $PRIMARY (config sync carries it)"
	# Give config sync a window to land it on the peer before we assert on it.
	sleep 5
}

# UNCONDITIONAL: a failed commit leaves its `set`s in the candidate, and leaving
# them there is what poisons the next run. It also restores the cluster's own
# interface-mode SNAT explicitly rather than relying on a delete, because the
# loss cluster is SHARED and the next lane's smoke must find it as it was.
restore_config() {
	cleanup_tmp
	info "Restoring: discarding any candidate and re-establishing interface SNAT"
	# BOTH nodes, best-effort: the primary may have MOVED (this smoke fails one
	# over), and whichever node is secondary simply refuses with a message we
	# discard. Attempting both is what makes the restore independent of where
	# the primary ended up.
	local node
	for node in "$FW0" "$FW1"; do
		incus exec "$node" -- /usr/local/sbin/cli >/dev/null 2>&1 <<EOF || true
configure
rollback 0
delete security nat source rule-set ${SNAT_RULESET} rule ${SNAT_RULE} then source-nat pool
set security nat source rule-set ${SNAT_RULESET} rule ${SNAT_RULE} then source-nat interface
delete security nat source pool ${POOL_NAME}
commit
exit
quit
EOF
	done
}
trap restore_config EXIT

# ---------------------------------------------------------------------------
main() {
	info "persistent-NAT lease-survives-failover smoke (#7360)"
	info "cluster: $FW0 / $FW1   client: $LAN_CLIENT   target: $TARGET"

	apply_pnat_config

	# Open a connection so the active mints a lease, and learn our source IP as
	# the firewall sees it.
	info "Opening connections from the client so the active mints a lease"
	# Several attempts to different remote PORTS: the lease is keyed on the
	# source tuple (permit any-remote-host), so any of them mints it — and a
	# single connect to a port with no listener can be refused before the
	# firewall installs a session.
	local p
	for p in 5201 5202 443; do
		incus exec "$LAN_CLIENT" -- bash -lc \
			"timeout 3 bash -c 'exec 3<>/dev/tcp/${TARGET}/${p}' 2>/dev/null || true"
	done
	sleep 3

	local src_ip natport_before
	src_ip="$(incus exec "$LAN_CLIENT" -- bash -lc "ip -4 -o addr show scope global | awk 'NR==1{split(\$4,a,\"/\"); print a[1]}'")"
	[ -n "$src_ip" ] || die "could not determine the client's source IP"
	info "client source IP: $src_ip"

	natport_before="$(binding_natport "$PRIMARY" "$src_ip" || true)"
	if [ -z "$natport_before" ]; then
		# Anti-vacuity guard. Dump what the node actually saw, so a failure here
		# names the cause instead of costing another cluster window to find.
		echo "---- diagnostics: why no binding? ----" >&2
		echo "-- persistent-nat-table on $PRIMARY --" >&2
		fw_cli "$PRIMARY" "show security nat source persistent-nat-table" >&2 || true
		echo "-- source-nat rule as committed --" >&2
		fw_cli "$PRIMARY" "show configuration security nat source" >&2 || true
		echo "-- live sessions for this client --" >&2
		fw_cli "$PRIMARY" "show security flow session" 2>&1 | grep -F "$src_ip" | head -5 >&2 || true
		echo "-- connectivity probe --" >&2
		incus exec "$LAN_CLIENT" -- bash -lc \
			"timeout 5 bash -c 'exec 3<>/dev/tcp/${TARGET}/5201' && echo CONNECT-OK || echo CONNECT-FAILED" >&2 || true
		echo "---- end diagnostics ----" >&2
		fail "the ACTIVE minted no persistent-NAT binding for $src_ip — the fixture \
did not exercise persistent NAT, so every assertion below would be vacuous"
		summary
		return
	fi
	pass "active $PRIMARY holds a binding for $src_ip -> port $natport_before"

	# (a) THE DIRECT ASSERTION. Before #7360 this is empty however many sessions
	#     the standby imported.
	sleep 3
	local standby_port standby_count
	standby_count="$(binding_count "$STANDBY" || echo 0)"
	standby_port="$(binding_natport "$STANDBY" "$src_ip" || true)"
	if [ "$standby_port" = "$natport_before" ]; then
		pass "standby $STANDBY reconstructed the binding ($src_ip -> $standby_port)"
	else
		fail "standby $STANDBY has no matching persistent-NAT binding for $src_ip \
(count=$standby_count, port='${standby_port:-none}', expected $natport_before). \
This is #7360: the synced reserve published the session without joining a lease."
	fi

	# (b) Fail over, then a NEW connection from the same client.
	info "Failing over: rebooting the RG0 primary $PRIMARY"
	incus restart "$PRIMARY" --force >/dev/null 2>&1 || die "could not restart $PRIMARY"
	sleep "$REBOOT_WAIT"

	# #9729: the downstream port assertion is only meaningful if the standby was
	# PROMOTED. Ask the survivor, and refuse to go on without a promotion.
	local promoted
	promoted="$(rg0_primary_node "$STANDBY")"
	if [ "$promoted" = "$STANDBY" ]; then
		pass "the standby $STANDBY was promoted to RG0 primary"
	else
		fail "no promotion observed: RG0 primary reads '${promoted:-unreadable}' on $STANDBY after rebooting $PRIMARY -- the translated-port assertion would be vacuous"
		summary
		return
	fi

	info "Opening a NEW connection from the same client on the promoted node"
	incus exec "$LAN_CLIENT" -- bash -lc \
		"timeout 5 bash -c 'exec 3<>/dev/tcp/${TARGET}/5201' 2>/dev/null || true"
	sleep 2

	local natport_after
	natport_after="$(binding_natport "$STANDBY" "$src_ip" || true)"
	if [ "$natport_after" = "$natport_before" ]; then
		pass "the client kept its translated port across the failover ($natport_after)"
	else
		fail "translated port MOVED across the failover: $natport_before -> \
'${natport_after:-none}'. A NEW connection is the right probe here; an existing \
one keeps its port on unfixed code because #4388 reserves the imported \
session's own translation."
	fi

	summary
}

summary() {
	echo
	echo "======================================"
	# #9729: the canonical "<n> passed, <n> failed" line the ha-smoke ledger
	# adapter parses; the old "PASS: n FAIL: n" form was recorded as VOID.
	echo "  Persistent-NAT failover test: $PASS passed, $FAIL failed"
	for e in "${ERRORS[@]:-}"; do [ -n "$e" ] && echo "  - $e"; done
	echo "======================================"
	[ "$FAIL" -eq 0 ] || exit 1
}

main "$@"
