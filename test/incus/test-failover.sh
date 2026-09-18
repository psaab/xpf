#!/usr/bin/env bash
# xpf cluster failover test
#
# Validates that active TCP connections survive fw0 reboot.
# Requires: cluster nodes from BPFRX_CLUSTER_ENV running (default: loss userspace cluster).
# Requires: iperf3 server reachable at IPERF_TARGET (default from IPERF_TARGET4).
#
# Tests:
#   1. Start iperf3 -P2 through the firewall (LAN host → WAN target)
#   2. Verify sessions sync from primary (fw0) to secondary (fw1)
#   3. Reboot fw0 (unclean — no priority-0 burst)
#   4. Verify iperf3 survives (TCP connections maintained through failover)
#   5. Verify fw0 comes back as secondary (no auto-preempt)
#   6. Manual failover: fw0 becomes primary again, iperf3 survives
#
# Usage:
#   ./test/incus/test-failover.sh
#   IPERF_TARGET=10.1.2.3 ./test/incus/test-failover.sh

set -euo pipefail

# #1875/#4020: this DESTRUCTIVE smoke reboots / force-stops / fails
# over a node on the SHARED loss cluster. Re-exec under the
# incus-admin group if needed, then serialize as a #1875 lock cell
# so a concurrent deploy/smoke can't collide with our reboot (it
# queues behind a held /tmp/xpf-cluster.lock instead of colliding).
_CELL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=cluster-cell.sh
source "${_CELL_DIR}/cluster-cell.sh"
xpf_enter_destructive_cluster_cell "test-failover $*" "$0" "$@"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/incus/cluster-env.sh
source "${SCRIPT_DIR}/cluster-env.sh"
# #7368: deploy_reassert_node0_primary_ok (the per-RG primacy predicate #6591
# added) and failover_ownership_verdict, both covered by
# `make test-deploy-lib` against a mocked incus.
# shellcheck source=test/incus/deploy-lib.sh
source "${SCRIPT_DIR}/deploy-lib.sh"
# shellcheck source=test/incus/iperf-throughput-lib.sh
source "${SCRIPT_DIR}/iperf-throughput-lib.sh"

IPERF_TARGET="${IPERF_TARGET:-$IPERF_TARGET4}"
# #6934: the IPv6 transit target. cluster-env.sh has exported IPERF_TARGET6 all
# along and this gate never read it — every assertion here was IPv4-only, which
# is why an IPv6-specific failover regression reached a human as an ad-hoc
# observation instead of reddening this gate.
IPERF_TARGET6="${IPERF_TARGET6:-2001:559:8585:80::200}"
V6_PROBE_COUNT=5        # #6934: see check_v6_transit for why this is not 1
V6_PROBE_MIN=3          # received replies required to call the path up
V6_RECHECK_DELAY=30     # #6934: seconds between the two post-failover samples
# COUPLED TO #7770 — tighten this when that is fixed.
#
# 3-of-5 is not a general-purpose tolerance; it is calibrated to absorb one
# specific KNOWN defect. #7770: a LAN/WAN redundancy-group split drops the first
# packet of every new flow, symmetrically in v4 and v6, and does not self-heal
# (measured 12.5% on 8 packets, still 12.5% on a fresh probe 45s later, against
# 0% for a full failover). A 0%-loss assertion here would red on that rather
# than on anything this gate is scoped to.
#
# So once #7770 lands, this threshold is LOOSER than it needs to be and would
# hide a one-packet regression. Raise V6_PROBE_MIN to V6_PROBE_COUNT then.
#
# Written down because a tolerance whose reason is undocumented is
# indistinguishable from a tolerance nobody thought about — the next reader
# cannot tell "3 of 5 because a known defect costs exactly one packet" from
# "3 of 5 because the author was not sure", and only the first has an expiry.
IPERF_DURATION=120      # seconds — long enough to span retries + reboot + failback
IPERF_STREAMS=8
MIN_SESSIONS=4          # minimum established sessions (control + some data streams)
SYNC_WAIT=5             # seconds to wait for session sync sweep
REBOOT_WAIT=60          # max WALL-CLOCK seconds to wait for fw0 to come back (#1880)
MIN_THROUGHPUT=1.0      # Gbps — iperf3 must report at least this
# #7673: the CoS output filter classifies by DESTINATION PORT, and iperf3
# defaults to 5201 -- which cos-iperf-config.set maps to `iperf-100m`, a
# `transmit-rate 100m exact` class. Measuring a deliberately-100Mbit-shaped
# class against a 1.0 Gbps floor fails by construction, and it fails looking
# exactly like a forwarding regression (~92-94 Mbits/s, every failover
# assertion passing). 5211 is the `iperf-uncapped` term, whose scheduler
# carries no transmit-rate.
#
# This only bites once apply-cos-config.sh has been run, and the CoS config
# survives until the next deploy wipes it -- so the gate passed or failed
# depending on what the PREVIOUS agent left on the cluster. That is why it
# reproduced on master and read as a real regression.
#
# iperf-throughput-selftest.sh asserts this port still maps to an unshaped
# class, so the two files cannot drift apart silently.
IPERF_PORT="${IPERF_PORT:-5211}"

PASS=0
FAIL=0
ERRORS=()

info()  { echo "==> $*"; }
pass()  { echo "  PASS  $*"; PASS=$((PASS + 1)); }
fail()  { echo "  FAIL  $*"; FAIL=$((FAIL + 1)); ERRORS+=("$*"); }

die() { echo "FATAL: $*" >&2; exit 2; }

# check_v6_transit asserts IPv6 traffic still crosses the firewall (#6934).
#
# It probes the WAN-side target rather than the LAN VIP deliberately. Pinging
# the VIP exercises L2 and local delivery on the same segment and never crosses
# the fabric, so it stays green through exactly the failures this is here to
# catch — measured: during a LAN/WAN redundancy-group split the VIP answers with
# 0% loss while transit is degraded.
#
# The failure message deliberately does NOT blame the neighbour cache. That was
# this issue's first instinct for three rounds and it is measurably wrong here:
# on this LAN host the IPv4 and IPv6 neigh parameters are byte-identical, and
# poisoning the default gateway's entry with a bogus MAC costs 8.51s in IPv6
# against 8.71s in IPv4 — symmetric, and 8.5s rather than the ~30/~60s the old
# message asserted. A stale neighbour entry can produce a blackhole; it cannot
# produce a v4/v6 ASYMMETRY on this host, and it cannot produce a ~60s one.
# Measurements in docs/log/6934.md.
#
# It tolerates losing packets but not all of them, and that threshold is
# measured rather than picked. A cross-node split costs the FIRST packet of a
# new flow, reproducibly and without self-healing, so a `-c 1` probe would be
# flaky on a healthy-enough cluster while a "0% loss" assertion would red on a
# condition this gate is not scoped to. Requiring 3 of 5 separates a blackhole
# (0 received — the #6934 report) from that first-packet loss (4 of 5).
check_v6_transit() {
	local label="$1" out recv
	out=$(incus exec "$CLUSTER_LAN_HOST" -- ping6 -c "$V6_PROBE_COUNT" -W 1 "$IPERF_TARGET6" 2>&1 || true)
	recv=$(printf '%s\n' "$out" | sed -n 's/.* \([0-9][0-9]*\) received.*/\1/p' | head -1)
	[ -z "$recv" ] && recv=0
	if [ "$recv" -ge "$V6_PROBE_MIN" ]; then
		pass "IPv6 transit OK ${label} (${recv}/${V6_PROBE_COUNT} to ${IPERF_TARGET6})"
	else
		fail "IPv6 transit BLACKHOLED ${label}: only ${recv}/${V6_PROBE_COUNT} replies from ${IPERF_TARGET6}. Do NOT reach for a neighbour-cache explanation first: on this LAN host every neigh parameter is byte-identical between the families (base_reachable_time_ms 30000/30000, gc_stale_time 60/60, delay_first_probe_time 5/5, retrans_time_ms 1000/1000, ucast_solicit 3/3), and a deliberately poisoned gateway entry repairs in 8.51s for v6 against 8.71s for v4 — symmetric, and 8.5s rather than 30 or 60. A v6-ONLY failure therefore has to be somewhere the families genuinely differ, and the one place they do here is the default route: v4 is proto static, v6 is proto ra with a 180s lifetime refreshed every 10-30s. Capture ip -6 route / ip -6 neigh AND their v4 twins DURING the window (#6934, docs/log/6934.md)"
	fi
}
# #7368: a PRECONDITION failure is not a failover regression, and neither is an
# ownership/forwarding divergence. All three used to exit 2, so `FO_RC=2` was
# read as "failover broke" when it meant "the cluster was not in a state to
# test" — twice, on the shared gate, against changes that were not at fault.
die_precondition() { echo "FATAL[PRECONDITION]: $*" >&2; exit 2; }
die_divergence()   { echo "FATAL[DIVERGENCE]: $*" >&2; exit 3; }

instance_running() {
	local status
	status=$(incus info "$1" 2>/dev/null | grep -o "RUNNING" || true)
	[[ "$status" == "RUNNING" ]]
}

wait_for_instance() {
	local inst="$1" max="$2"
	for i in $(seq 1 "$max"); do
		if incus exec "$inst" -- systemctl is-active --quiet xpfd 2>/dev/null; then
			return 0
		fi
		sleep 1
	done
	return 1
}

# #9087: the #8297 proxy-ARP ownership check, EXTRACTED so it can run after
# every ownership change instead of only in the preflight.
#
# It used to run exactly once, before any failover happened. The run then
# crash-failed fw0 -> fw1, rejoined, and manually failed back fw1 -> fw0, and
# never re-read the entries. So a demotion that LEAKS the entry was invisible
# to a clean run BY CONSTRUCTION — the only observation point preceded every
# transition — and surfaced only as the NEXT run's preflight failing against
# the same binaries. A cell that can only observe the state that precedes every
# transition cannot see a transition defect.
#
# $1 is the phase label, so a failure names WHICH transition leaked rather than
# leaving the reader to guess which of three observation points fired.
check_proxy_arp_ownership() {
	local phase="$1"
	fw0_proxy=$(incus exec "$FW0" -- ip neigh show proxy 2>/dev/null | grep -c "$POOL_NAT_ADDR" || true)
	fw1_proxy=$(incus exec "$FW1" -- ip neigh show proxy 2>/dev/null | grep -c "$POOL_NAT_ADDR" || true)
	if [[ "$fw0_proxy" -ge 1 && "$fw1_proxy" -ge 1 ]]; then
		# The #8297 defect. Was a tracked known_gap until #8646 closed it; now a
		# plain failure, because a regression here is a regression and not a gap.
		fail "both nodes answer proxy-ARP for $POOL_NAT_ADDR after ${phase} (fw0=$fw0_proxy fw1=$fw1_proxy); the upstream sees one IP at two RETH virtual MACs, which is the #8297 defect returning"
	elif [[ "$fw0_proxy" -ge 1 && "$fw1_proxy" -eq 0 ]]; then
		# PROMOTED from known_gap by #8646, which moved proxy-ARP ownership off
		# VRRP events and onto the cluster. Measured before promoting: ten probes
		# 6s apart on a settled cluster, fw0=1 fw1=0 on all ten. One sample was
		# not enough — it cannot distinguish "the gate selected the owner" from
		# "both answered and the owner's reply landed last", which is the error
		# #8640 made on this same address.
		pass "only the RG owner answers proxy-ARP for $POOL_NAT_ADDR (${phase})"
	else
		# THIS BRANCH IS NOT LEFTOVER SCAFFOLDING, and it is the reason this
		# cell has three states rather than two. Do not collapse it.
		#
		# Reading the two branches above as "known_gap became pass/fail" invites
		# simplifying the whole block to `if fw1 == 0: pass` — which would delete
		# this arm, and this arm is the only thing that distinguishes "the owner
		# answers and the standby does not" from "NOBODY answers". Those look
		# identical to any assertion phrased about the standby alone.
		#
		# It is a state that actually happened: #8314 gated proxy-ARP on RG
		# ownership, was merged, and was REVERTED by #8342 because
		# `ip neigh show proxy` came back EMPTY ON BOTH NODES — the failure moved
		# from two answerers to zero, which breaks pool-mode NAT outright rather
		# than merely duplicating an answer. The cause was borrowing
		# `isRethMasterState`, whose own doc says it returns false when no
		# instances exist for the RG: safe for the DHCP relay it came from, an
		# outage here.
		#
		# So the assertion above is deliberately two-sided — the owner MUST
		# answer (fw0 >= 1), not merely "the standby must not" — and this arm
		# catches the half that a one-sided phrasing would pass.
		fail "the RG OWNER does not answer proxy-ARP for $POOL_NAT_ADDR after ${phase} (fw0=$fw0_proxy fw1=$fw1_proxy). Gating the owner is the OPPOSITE failure and breaks pool-mode NAT outright — this is the #8314 over-correction, not the #8297 defect"
	fi
}

# rg_ownership_diagnosis renders WHY a redundancy group did not move, not merely
# that it did not (#9452).
#
# THREE channels, because no one of them is sufficient and the issue's own
# acceptance named only the first:
#
#   - the per-RG readiness lines from BOTH nodes. `Transfer ready: no (<reason>)`
#     names a refusal on the node GIVING the RG up — a pending outbound bulk
#     (#3912) or the #2082 peer-priority gate. `Takeover ready: no (<reason>)`
#     names the readiness gate on the node TAKING it. Which one is false matters:
#     measured on #9452, `Transfer ready` was `yes` on both nodes for all three
#     RGs and `Takeover ready` was the false one, so a message carrying only the
#     transfer-readiness reason would still have said nothing.
#
#   - the PEER's view of the same RG. A transfer-out the peer never observed and
#     one it observed and declined are the same picture from one side.
#
#   - the election's own journal lines. The status lines are a SNAPSHOT, and the
#     #7162 startup promotion hold that blocked #9452 expires on its own after
#     30s — so by the time a failing cell reads status the gate can already read
#     `yes` and the only surviving record of the refusal is the log. This is the
#     channel that actually named the #9452 cause:
#       cluster: election blocked by readiness gate rg=0 ready=false
#         reasons="[session sync startup hold: bulk sync not yet complete]"
rg_ownership_diagnosis() {
	local rg="$1" node
	printf '    ---- RG%s ownership diagnosis ----\n' "$rg"
	for node in "$FW0" "$FW1"; do
		printf '    [%s] show chassis cluster status, redundancy group %s:\n' "$node" "$rg"
		incus exec "$node" -- cli -c 'show chassis cluster status' 2>&1 |
			awk -v rg="$rg" '
				$0 ~ ("^Redundancy group: " rg "[ ,]") { p = 1; print "      " $0; next }
				p && /^Redundancy group: / { p = 0 }
				p { print "      " $0 }' || true
	done
	printf '    [%s] election / transfer / promotion-hold journal tail:\n' "$FW0"
	incus exec "$FW0" -- journalctl -u xpfd -n 5000 --no-pager 2>/dev/null |
		grep -E "readiness gate|transfer out|transfer-out|manual failover|promotion hold|primary transition|degraded" |
		tail -10 | sed 's/^/      /' || true
}

# ── Preflight ────────────────────────────────────────────────────────

info "Preflight checks"

for inst in "$FW0" "$FW1" "$CLUSTER_LAN_HOST"; do
	instance_running "$inst" || die "$inst is not running"
done

# Reset any stale manual failover flags from previous test runs.
# Without this, fw1 can't take over during the reboot test because
# ManualFailover blocks election even when the peer is lost.
for rg in 0 1 2; do
	incus exec "$FW0" -- cli -c "request chassis cluster failover reset redundancy-group $rg" 2>/dev/null || true
	incus exec "$FW1" -- cli -c "request chassis cluster failover reset redundancy-group $rg" 2>/dev/null || true
done
sleep 2

# Verify fw0 is primary for EVERY redundancy group.
#
# #7368: this was `grep -q "node0.*primary"` over the whole status output.
# `secondary` does not contain `primary`, so that part was sound — but the grep
# is not scoped to a redundancy group, so a cluster with node0 SECONDARY for
# RG0 and primary for RG1 satisfied it. The reassert makes node0 primary for
# all RGs, and the post-failover phase below already asserts all three, so the
# precondition should be the same shape. deploy_reassert_node0_primary_ok is
# the predicate #6591 added and `make test-deploy-lib` covers; reusing it keeps
# one definition of "node0 is primary" rather than a second grep that can drift.
fw0_status=$(incus exec "$FW0" -- cli -c 'show chassis cluster status' 2>/dev/null)
if printf '%s\n' "$fw0_status" | deploy_reassert_node0_primary_ok; then
	pass "fw0 is primary for every redundancy group"
else
	die_precondition "fw0 is not primary for every redundancy group — cannot run the failover test. This is a PRECONDITION failure, NOT a failover regression: the cluster was not in a testable state before the change under test ran. Check the post-deploy reassert (#6591) and re-read the state directly:
$fw0_status"
fi

# Verify iperf target reachable
if incus exec "$CLUSTER_LAN_HOST" -- ping -c 2 -W 2 "$IPERF_TARGET" &>/dev/null; then
	pass "iperf3 target reachable ($IPERF_TARGET)"
else
	die "Cannot reach iperf3 target $IPERF_TARGET from ${CLUSTER_LAN_HOST}"
fi

# #6934: the IPv6 baseline. Asserted BEFORE any failover so a later v6 failure
# is attributable to the transition rather than to a cluster that never had v6
# transit — without this the post-failover cells could red on a broken fixture.
check_v6_transit "at baseline (before any failover)"

# ── #8280: pool-mode source-NAT traffic, alongside the main stream ──
#
# WHY THIS EXISTS. Every source-nat rule on this cluster used to be
# `interface;` mode, which is ADDRESS-ONLY: it rewrites the source to the
# egress interface's own address and returns before any port allocation, so it
# never reaches PortAllocator / AddressOccupancy::claim. Measured on #7174 M13:
# a change to the NAT port allocator passed this smoke 17/17 while the smoke
# never executed a line of it — the run looked identical whether the change was
# correct, reverted or broken.
#
# THE STATE THIS ENTERS, stated because an assertion that never reaches it buys
# nothing:
#   fw0 (primary)  allocate_translation -> AddressOccupancy::claim  — the pool
#                  port is claimed from the fresh cursor, then from the recycle
#                  FIFO as ports free and are re-claimed.
#   fw1 (standby)  handle_upsert_synced -> reserve_flow ->
#                  occupancy.reserve() -> claim_offset  — the HA import side.
#   across the crash + failback the roles SWAP, so ports fw1 imported as
#   reservations become locally owned and released: the reserve/recycle
#   lifecycle across a role change, which is the interaction no unit test
#   reaches.
#
# The source address is the lever. 10.0.61.240/28 is matched by the config's
# `rule pool-snat` and is assigned to nothing (LAN host is .102, VIP .1, DHCP
# .100-.199), so adding it here is the ONLY way traffic takes the pool path and
# every other assertion in this script keeps measuring exactly what it did.
# POOL_NAT_SMOKE=0 disables this phase entirely, so the CONFIG change can be
# shown not to shift any existing path: the run must return exactly the same
# assertion count it did before the pool rule existed.
POOL_NAT_SMOKE="${POOL_NAT_SMOKE:-1}"
POOL_SRC="${POOL_SRC:-10.0.61.240}"
POOL_NAT_ADDR="${POOL_NAT_ADDR:-172.16.80.7}"
POOL_PORT="${POOL_PORT:-5210}"
POOL_LAN_IF="${POOL_LAN_IF:-$(incus exec "$CLUSTER_LAN_HOST" -- \
	bash -c "ip -4 -o route get ${LAN_GW:-10.0.61.1} 2>/dev/null | sed -n 's/.* dev \\([^ ]*\\).*/\\1/p'" 2>/dev/null | tr -d '\r')}"

# pool_session_count echoes the number of sessions on $1 whose translated tuple
# carries the pool address, or the literal string "VOID" when the query did not
# produce a session listing at all.
#
# The three states matter. `show security flow session` is an admission-gated
# session-scan surface sharing one 4-slot budget across REST and gRPC, so a
# refusal returns no listing — and a bare `grep -c` renders that as 0, which is
# indistinguishable from "the allocator handed out nothing". The assertions
# below would then report a confident NAT-allocator defect for an admission
# event. "Total sessions:" is the listing's own terminator, so its presence is
# what separates "ran and found none" from "did not run".
# POOL_QUERY_ERR carries the last query's stderr, so a VOID can say WHY.
POOL_QUERY_ERR=""
pool_session_count() {
	local node="$1" out
	# stderr is CAPTURED, not discarded. Verified on the path this actually
	# runs: cmd/cli/show_flow.go calls GetSessions and on error does
	# `return fmt.Errorf(...)` BEFORE printing "Total sessions:", and
	# cmd/cli/main.go writes `error: %v` to stderr. So the absence of the
	# terminator is a sound refusal signal — and the reason is on stderr, which
	# an earlier version threw away, leaving a VOID that could not be acted on.
	POOL_QUERY_ERR=$(incus exec "$node" -- cli -c \
		"show security flow session source-prefix ${POOL_SRC}" 2>&1 >/dev/null || true)
	out=$(incus exec "$node" -- cli -c \
		"show security flow session source-prefix ${POOL_SRC}" 2>/dev/null || true)
	if ! grep -q "Total sessions:" <<<"$out"; then
		echo VOID
		return
	fi
	grep -c "$POOL_NAT_ADDR" <<<"$out" || true
}

pool_src_teardown() {
	[[ -n "$POOL_LAN_IF" ]] || return 0
	incus exec "$CLUSTER_LAN_HOST" -- pkill -9 -f "iperf3.*-B ${POOL_SRC}" 2>/dev/null || true
	incus exec "$CLUSTER_LAN_HOST" -- \
		ip addr del "${POOL_SRC}/24" dev "$POOL_LAN_IF" 2>/dev/null || true
}
# The cluster is SHARED: the secondary address must not outlive this run
# whatever happens, including a die() in the middle of a phase.
trap pool_src_teardown EXIT

if [[ "$POOL_NAT_SMOKE" != 1 ]]; then
	POOL_LAN_IF=""
	info "#8280: pool-mode NAT phase DISABLED (POOL_NAT_SMOKE=0)"
elif [[ -z "$POOL_LAN_IF" ]]; then
	info "#8280: could not resolve the LAN interface on ${CLUSTER_LAN_HOST}; pool-mode NAT coverage will be reported as NOT MEASURED"
else
	incus exec "$CLUSTER_LAN_HOST" -- \
		ip addr add "${POOL_SRC}/24" dev "$POOL_LAN_IF" 2>/dev/null || true
fi

# Kill any stale iperf3
incus exec "$CLUSTER_LAN_HOST" -- pkill -9 iperf3 2>/dev/null || true
sleep 1

# ── Phase 1: Start iperf3 ───────────────────────────────────────────

info "Starting iperf3 -P${IPERF_STREAMS} -t${IPERF_DURATION} -p${IPERF_PORT} → ${IPERF_TARGET}"

# iperf3 server handles one client at a time. After a previous test
# disrupts connections (session clear / failover), the server may hold
# a stale session until TCP keepalive fires (~minutes). Retry startup
# with increasing back-off to wait for the server to become available.
iperf_started=false
for attempt in 1 2 3; do
	incus exec "$CLUSTER_LAN_HOST" -- pkill -9 iperf3 2>/dev/null || true
	sleep 1
	incus exec "$CLUSTER_LAN_HOST" -- bash -c \
		"iperf3 --forceflush --connect-timeout 5000 -t ${IPERF_DURATION} -c ${IPERF_TARGET} -p ${IPERF_PORT} -P ${IPERF_STREAMS} > /tmp/iperf3-failover.log 2>&1 &"

	sleep 8  # all parallel streams must be fully established

	if ! incus exec "$CLUSTER_LAN_HOST" -- pgrep iperf3 &>/dev/null; then
		info "iperf3 exited on attempt $attempt — server may be busy, retrying"
		sleep $((attempt * 5))
		continue
	fi

	fw0_sessions=$(incus exec "$FW0" -- cli -c \
		"show security flow session destination-prefix ${IPERF_TARGET}" 2>/dev/null | grep -c "Session State: Valid" || true)
	if [[ "$fw0_sessions" -ge "$IPERF_STREAMS" ]]; then
		iperf_started=true
		break
	fi

	# iperf3 is running but not enough sessions — streams may have timed out
	if incus exec "$CLUSTER_LAN_HOST" -- grep -q "unable to connect" /tmp/iperf3-failover.log 2>/dev/null; then
		info "iperf3 stream connect failed on attempt $attempt — server busy, retrying"
		incus exec "$CLUSTER_LAN_HOST" -- pkill -9 iperf3 2>/dev/null || true
		sleep $((attempt * 10))
		continue
	fi

	iperf_started=true
	break
done

if ! $iperf_started; then
	if ! incus exec "$CLUSTER_LAN_HOST" -- pgrep iperf3 &>/dev/null; then
		incus exec "$CLUSTER_LAN_HOST" -- cat /tmp/iperf3-failover.log 2>/dev/null || true
		die "iperf3 failed to start after 3 attempts"
	fi
fi

# Verify iperf3 is running
if incus exec "$CLUSTER_LAN_HOST" -- pgrep iperf3 &>/dev/null; then
	pass "iperf3 running on ${CLUSTER_LAN_HOST}"
else
	incus exec "$CLUSTER_LAN_HOST" -- cat /tmp/iperf3-failover.log 2>/dev/null || true
	die "iperf3 failed to start"
fi

# Verify sessions exist on fw0.
# iperf3 server is single-client — if a stale session from the previous
# test lingers, some data streams may not connect. Accept MIN_SESSIONS
# (control + some data) rather than requiring all IPERF_STREAMS.
#
# #4052: the 8 TCP streams take a sub-second to finish their 3-way
# handshakes, so a single immediate assert here can catch the
# establishment window with only 0-3 Valid sessions and FALSE-FAIL a
# healthy cluster (a settled cluster shows ~25 Valid sessions at
# 23.4 Gbps / 0 retr). Poll up to 10s (20 × 0.5s), breaking as soon as
# the count reaches MIN_SESSIONS; only fail if the streams genuinely
# never establish within the timeout — a real establishment failure.
fw0_sessions=0
for _ in $(seq 1 20); do
	fw0_sessions=$(incus exec "$FW0" -- cli -c \
		"show security flow session destination-prefix ${IPERF_TARGET}" 2>/dev/null | grep -c "Session State: Valid" || true)
	[[ "$fw0_sessions" -ge "$MIN_SESSIONS" ]] && break
	sleep 0.5
done
# #7368: cross-reference the two independent checks this script already
# performs before deciding WHICH failure this is.
#
# Primacy is read from `show chassis cluster status` — a field the node reports
# about itself, with no oracle. The session count is a real measurement. They
# were never compared, so #6656's divergence (node0 primary with 1 session,
# node1 carrying 33) surfaced here as "streams did not establish" — a shortfall
# attributed to whatever change was under test, when the actual failure was
# that ownership and forwarding disagreed.
#
# The peer count is read ONLY on the shortfall path, so the healthy run pays
# nothing. failover_ownership_verdict is pure and selftested.
if [[ "$fw0_sessions" -ge "$MIN_SESSIONS" ]]; then
	pass "fw0 has $fw0_sessions established sessions"
else
	fw1_probe=$(incus exec "$FW1" -- cli -c \
		"show security flow session destination-prefix ${IPERF_TARGET}" 2>/dev/null | grep -c "Session State: Valid" || true)
	case "$(failover_ownership_verdict "$fw0_sessions" "$fw1_probe" "$MIN_SESSIONS")" in
	diverged)
		die_divergence "OWNERSHIP AND FORWARDING DISAGREE. fw0 reports PRIMARY for every redundancy group but carries only $fw0_sessions session(s), while fw1 — reported secondary — carries $fw1_probe. The cluster-state field and the traffic disagree, so neither 'failover is broken' nor 'the streams did not establish' is the right reading; see #6656. Read both nodes directly before re-running:
  incus exec $FW0 -- cli -c 'show chassis cluster status'
  incus exec $FW1 -- cli -c 'show chassis cluster status'"
		;;
	*)
		fail "fw0 has only $fw0_sessions established sessions (expected >= $MIN_SESSIONS); fw1 carries $fw1_probe, so this is an establishment failure rather than an ownership/forwarding divergence"
		;;
	esac
fi

# ── Phase 1b: pool-mode NAT traffic (#8280) ─────────────────────────
#
# A SECOND iperf3, bound to the pool-matched source and aimed at a different
# CoS class port, so it cannot contend with the main stream on 5211 (the
# server handles one client per port).
if [[ -n "$POOL_LAN_IF" ]]; then
	incus exec "$CLUSTER_LAN_HOST" -- bash -c \
		"iperf3 --forceflush --connect-timeout 5000 -B ${POOL_SRC} -t ${IPERF_DURATION} -c ${IPERF_TARGET} -p ${POOL_PORT} -P 2 > /tmp/iperf3-pool-8280.log 2>&1 &"
	sleep 6
fi

# ── Phase 2: Wait for session sync ──────────────────────────────────

info "Waiting ${SYNC_WAIT}s for session sync to fw1"
sleep "$SYNC_WAIT"

fw1_sessions=$(incus exec "$FW1" -- cli -c \
	"show security flow session destination-prefix ${IPERF_TARGET}" 2>/dev/null | grep -c "Session State: Valid" || true)
if [[ "$fw1_sessions" -ge "$MIN_SESSIONS" ]]; then
	pass "fw1 has $fw1_sessions synced sessions"
else
	fail "fw1 has only $fw1_sessions synced sessions (expected >= $MIN_SESSIONS)"
fi

# ── #8280: the pool allocator actually ran, and the peer imported it ──
#
# The discriminator is the TRANSLATED address. An interface-mode session shows
# reth0.80's own 172.16.80.8 in its `Out:` line; a POOL-mode session shows the
# pool's 172.16.80.7, which only AddressOccupancy::claim can hand out. Asserting
# "a session exists" would pass on interface mode and measure nothing.
if [[ "$POOL_NAT_SMOKE" != 1 ]]; then
	: # phase deliberately disabled; no assertion is owed
elif [[ -z "$POOL_LAN_IF" ]]; then
	fail "#8280 pool-mode NAT was NOT MEASURED: the LAN interface on ${CLUSTER_LAN_HOST} could not be resolved, so no traffic took the pool path. This is a VOID for the allocator, not a pass — the rest of this run says nothing about PortAllocator"
else
	pool_fw0=$(pool_session_count "$FW0")
	if [[ "$pool_fw0" == VOID ]]; then
		fail "#8280: fw0's session query returned no listing, so pool-mode NAT was NOT MEASURED. This is most likely session-scan ADMISSION (the surface is gated on a 4-slot budget shared across REST and gRPC), not a NAT defect — re-run when nothing else is scanning rather than reading it as an allocator failure. Query stderr: ${POOL_QUERY_ERR:-<none>}"
	elif [[ "$pool_fw0" -ge 1 ]]; then
		pass "fw0 translated $pool_fw0 pool-mode session(s) to $POOL_NAT_ADDR (PortAllocator::claim ran)"
	else
		fail "fw0 has no session translated to the pool address $POOL_NAT_ADDR. Either the pool-mode rule did not match ${POOL_SRC}, or the allocator refused — either way this run does NOT exercise the NAT port allocator (#8280)"
	fi

	# ── #8297 acceptance: the STANDBY must not answer proxy-ARP ──────────
	#
	# The defect was TWO answerers, so this asserts the NEGATIVE. Asserting that
	# the primary has the entry passes on the broken code — both nodes had it —
	# and would be a green about nothing.
	#
	# Read from the kernel (`ip neigh show proxy`), not from config: the config
	# said the same thing on both nodes throughout, and it was the installed
	# NTF_PROXY entry that differed from what ownership required.
	check_proxy_arp_ownership "preflight, before any failover"

	pool_fw1=$(pool_session_count "$FW1")
	if [[ "$pool_fw1" == VOID ]]; then
		fail "#8280: fw1's session query returned no listing, so the standby import was NOT MEASURED — see the admission note on the fw0 assertion above. Query stderr: ${POOL_QUERY_ERR:-<none>}"
	elif [[ "$pool_fw1" -ge 1 ]]; then
		pass "fw1 imported $pool_fw1 pool-mode session(s) (reserve_flow -> occupancy.reserve)"
	else
		fail "fw1 imported no pool-mode session for ${POOL_SRC}. The standby's reserve_flow -> occupancy.reserve() path is what a NAT-allocator change most affects across a role change, and it did not run (#8280)"
	fi
fi

# ── Phase 3: Crash fw0 (sysrq reboot) ───────────────────────────────
#
# sysrq-b is the repo's proven unclean primitive (same as
# test-double-failover.sh): the guest resets instantly, with no unit
# stops, no priority-0 VRRP burst, and no shutdown-job queueing. The
# previous `reboot` here was a GRACEFUL systemd reboot despite the
# "unclean" claim — xpfd got a clean stop (emitting the planned-shutdown
# priority-0 burst, i.e. the ~1ms takeover path instead of the ~60ms
# worst-case detection this test exists to exercise) AND the whole
# shutdown queued behind any wedged stop job. The #1880 budget misses
# were exactly that: post-deploy `systemctl reload frr` poisons
# frr.service into a 2-minute stop-sigterm on FRR 10.6, and a graceful
# reboot inside that window waited out the timer.

info "Crashing fw0 (sysrq reboot — unclean shutdown, tests worst-case failover)"

# timeout is load-bearing AND needs -k: sysrq-b resets the guest
# INSTANTLY, killing the incus-agent serving this exec, so the exec
# never observes an exit status (measured: a 47-minute hang on the
# first live run). Worse, `incus exec` FORWARDS SIGTERM to the (dead)
# remote session instead of exiting (measured: `timeout 10` alone left
# the client alive for 38+ minutes), so only the -k SIGKILL follow-up
# reliably reaps the local client. `|| true` alone cannot save a
# command that never returns.
# Braces, not just 2>/dev/null on the command: bash prints its own
# "Killed" job notice for the SIGKILLed child, which would land in the
# test transcript as alarming noise.
{ timeout -k 5 10 incus exec "$FW0" -- bash -c 'echo b > /proc/sysrq-trigger' || true; } 2>/dev/null

# Wait for fw1 to detect failure and become primary
sleep 3

# Verify iperf3 survived the failover
if incus exec "$CLUSTER_LAN_HOST" -- pgrep iperf3 &>/dev/null; then
	pass "iperf3 survived fw0 reboot (failover to fw1)"
else
	fail "iperf3 DIED during fw0 reboot — failover broke TCP connections"
fi

# ── Phase 4: Wait for fw0 to come back as secondary (no auto-preempt) ─

info "Waiting for fw0 to reboot and rejoin as secondary (max ${REBOOT_WAIT}s)"

# Wall-clock budget (#1880): the old `seq 1 $REBOOT_WAIT` loop counted
# ITERATIONS as seconds, but each iteration costs ~1.2s (1s sleep +
# ~240ms incus exec), so "60s" silently meant ~74s and the PASS message
# under-reported by ~23%. Measured comebacks on the loss userspace
# cluster: ~22s clean (sysrq), so 60s wall keeps ~2.7x headroom.
fw0_back=false
wait_start=$SECONDS
while (( SECONDS - wait_start < REBOOT_WAIT )); do
	if wait_for_instance "$FW0" 1; then
		fw0_back=true
		info "fw0 xpfd active after $((SECONDS - wait_start))s"
		break
	fi
done

if $fw0_back; then
	pass "fw0 xpfd restarted after reboot"
else
	fail "fw0 xpfd did not come back within ${REBOOT_WAIT}s"
fi

# Wait for cluster to stabilize (gRPC takes ~15s after systemctl active)
sleep 20

# Verify fw0 is secondary for EVERY redundancy group (NOT primary — no auto-preempt)
#
# These two assertions were `grep -q "node0.*secondary"` / `grep -q "node1.*primary"`
# over the whole status output — the #7368 shape, which the precondition above
# already fixed but which survived here. Unscoped, it does not just admit a
# partial state: because the secondary branch is tried FIRST, a cluster that
# auto-preempted for RG1 while staying secondary for RG0 matched it and reported
# PASS, leaving the elif that names the auto-preempt regression unreachable in
# precisely the mixed case it exists to catch. The failback loop below is already
# per-RG (`grep -A1 "Redundancy group: $rg"`); this phase was the gap between it
# and the per-RG precondition.
fw0_status_after=$(incus exec "$FW0" -- cli -c 'show chassis cluster status' 2>/dev/null)
if printf '%s\n' "$fw0_status_after" | deploy_node_role_every_rg_ok node0 secondary; then
	pass "fw0 rejoined as secondary for every redundancy group (no auto-preempt)"
elif printf '%s\n' "$fw0_status_after" | deploy_node_role_every_rg_ok node0 primary; then
	fail "fw0 auto-preempted to primary for every redundancy group (should stay secondary)"
else
	fail "fw0 is neither secondary nor primary for EVERY redundancy group after rejoin — a MIXED or unreadable state. A mixed state is itself the auto-preempt regression, on a subset of RGs:
$fw0_status_after"
fi

# Verify fw1 is still primary for EVERY redundancy group
fw1_status_after=$(incus exec "$FW1" -- cli -c 'show chassis cluster status' 2>/dev/null)
if printf '%s\n' "$fw1_status_after" | deploy_node_role_every_rg_ok node1 primary; then
	pass "fw1 remains primary for every redundancy group after fw0 rejoin"
else
	fail "fw1 is not primary for every redundancy group after fw0 rejoin:
$fw1_status_after"
fi

# Verify iperf3 still running
if incus exec "$CLUSTER_LAN_HOST" -- pgrep iperf3 &>/dev/null; then
	pass "iperf3 survived fw0 rejoin"
else
	if incus exec "$CLUSTER_LAN_HOST" -- grep -q "iperf Done" /tmp/iperf3-failover.log 2>/dev/null; then
		pass "iperf3 completed successfully (finished before rejoin check)"
	else
		fail "iperf3 DIED during fw0 rejoin"
	fi
fi

# ── Phase 4b: Manual failover — fw0 becomes primary again ───────────

info "Manual failover: requesting fw1 to failover all RGs to fw0"

# Execute manual failover on fw1 for all RGs (current primary).
# Each RG must be explicitly failed over — RG0 alone doesn't move RG1/RG2
# because per-RG election is independent with non-preempt.
for rg in 0 1 2; do
	# stderr is CAPTURED, not discarded. `2>/dev/null` here hid every refusal
	# this command can return, so a run that printed "Manual failover triggered"
	# and a run that printed nothing at all were the same transcript (#9452).
	incus exec "$FW1" -- cli -c "request chassis cluster failover redundancy-group $rg" 2>&1 |
		sed 's/^/    /' || true
done

# Verify fw0 is now primary for ALL RGs.
#
# A BOUNDED POLL, not a fixed `sleep 5`. The fixed sleep could not tell "the
# transfer was refused" from "the transfer is still in flight", and #9452 was the
# second: all three RGs DID move, 19-30s later, when the rejoining node's bounded
# #7162 startup promotion hold expired. So the cell was reading a real outage —
# fw1 has already demoted, so for that whole window the RG is owned by NEITHER
# node — and reporting it as a refusal, while simply lengthening the sleep would
# have reported a 30s blackhole as a pass.
#
# Polling gives the cell the ELAPSED time, which is the number that separates the
# two, and the bound stays tight enough that the blackhole #9452 fixed still
# reds. Each RG is polled in turn, so the later RGs are not charged the earlier
# ones' wait.
MANUAL_FAILOVER_DEADLINE="${MANUAL_FAILOVER_DEADLINE:-10}"
all_primary=true
slowest=0
for rg in 0 1 2; do
	fo_start=$(date +%s)
	moved=0
	while :; do
		if incus exec "$FW0" -- cli -c 'show chassis cluster status' 2>/dev/null |
			grep -A1 "Redundancy group: $rg" | grep -q "node0.*primary"; then
			moved=1
			break
		fi
		if (($(date +%s) - fo_start >= MANUAL_FAILOVER_DEADLINE)); then
			break
		fi
		sleep 1
	done
	fo_elapsed=$(($(date +%s) - fo_start))
	if ((moved)); then
		if ((fo_elapsed > slowest)); then
			slowest=$fo_elapsed
		fi
		info "RG$rg moved to fw0 in ${fo_elapsed}s"
	else
		all_primary=false
		fail "fw0 is not primary for RG$rg ${MANUAL_FAILOVER_DEADLINE}s after manual failover. fw1 has ALREADY demoted, so for this whole window RG$rg is owned by NEITHER node: transit is blackholed and nothing answers proxy-ARP for the pool-NAT address. That is an outage, not a declined request — read the elapsed time and the readiness reasons below rather than assuming a refusal (#9452)
$(rg_ownership_diagnosis "$rg")"
	fi
done
if $all_primary; then
	pass "fw0 became primary for all RGs after manual failover (slowest ${slowest}s of ${MANUAL_FAILOVER_DEADLINE}s budget)"
fi

# Verify iperf3 survived manual failover
if incus exec "$CLUSTER_LAN_HOST" -- pgrep iperf3 &>/dev/null; then
	pass "iperf3 survived manual failover"
else
	if incus exec "$CLUSTER_LAN_HOST" -- grep -q "iperf Done" /tmp/iperf3-failover.log 2>/dev/null; then
		pass "iperf3 completed successfully (finished before manual failover check)"
	else
		fail "iperf3 DIED during manual failover"
	fi
fi

# #9087: re-read ownership AFTER the full crash-failover + manual-failback
# cycle. This is the state the NEXT run's preflight observes, and it is the one
# that was leaking: fw1 installs the entry while primary during the crash
# phase, steps back down at the failback, and used to keep it.
check_proxy_arp_ownership "after the crash failover AND the manual failback"

# ── #8280: the allocator still works AFTER a full role-change cycle ──
#
# THE STATE THIS ENTERS, which is the whole point of the phase. By this line
# fw0 has been primary -> secondary (crash) -> primary (manual failback). The
# pool ports it originally claimed were imported by fw1 as RESERVATIONS
# (reserve_flow -> occupancy.reserve -> claim_offset), then fw1 became primary
# and owned them, then primacy came back. A fresh claim now walks the recycle
# FIFO in exactly the post-churn state #7174 M13 is about: reserved-then-
# released tokens, and an `occupied` counter that must still agree with the
# bitmap. A leak leaves ports unclaimable; a drifted counter reports the address
# full when it is not. Either way this probe gets no translation.
#
# The sessions are CLEARED first. A surviving session from before the failover
# would satisfy "a pool-translated session exists" without a single new claim,
# which is a cell that passes without entering the state it names.
#
# The allocator and data path are both asserted below. #8297 fixed the
# proxy-ARP ownership needed for a pool-mode handshake; #10146 promotes the
# formerly known-gap #8341 data-path check to a real assertion.
if [[ "$POOL_NAT_SMOKE" == 1 && -n "$POOL_LAN_IF" ]]; then
	incus exec "$FW0" -- cli -c "clear security flow session source-prefix ${POOL_SRC}" &>/dev/null || true
	incus exec "$CLUSTER_LAN_HOST" -- bash -c \
		"timeout 6 iperf3 --connect-timeout 3000 -B ${POOL_SRC} -t 2 -c ${IPERF_TARGET} -p ${POOL_PORT} > /tmp/iperf3-pool-8280-post.log 2>&1 &" || true
	sleep 5
	post_pool=$(pool_session_count "$FW0")
	if [[ "$post_pool" == VOID ]]; then
		fail "#8280: the post-failback session query returned no listing, so the allocator's state after the role change was NOT MEASURED — see the admission note above. A VOID here is NOT evidence the allocator is healthy. Query stderr: ${POOL_QUERY_ERR:-<none>}"
	elif [[ "$post_pool" -ge 1 ]]; then
		pass "the pool allocator still hands out a translation after a full primary->secondary->primary cycle"
		# #8297 fixed the proxy-ARP ownership needed for a pool-mode handshake,
		# so the data-path half of this phase is now assertable. #8341 is a
		# separate regression: the allocator can hand out a translation while
		# TCP still fails before egress. The assertion below keeps those two
		# observations distinct.
		# #10146 promotes the formerly known-gap #8341 check to a real
		# assertion. A successful iperf3 run emits `iperf Done.`; matching
		# that positive result avoids treating an arbitrary error message as
		# proof that the pool-mode TCP flow connected.
		if incus exec "$CLUSTER_LAN_HOST" -- grep -q "iperf Done" /tmp/iperf3-pool-8280-post.log 2>/dev/null; then
			pass "a pool-mode TCP flow connects after the role change (data path, not just allocation)"
		else
			pool_log=$(incus exec "$CLUSTER_LAN_HOST" -- tail -5 /tmp/iperf3-pool-8280-post.log 2>&1 || echo "(pool probe log unreadable)")
			fail "a pool-mode TCP flow did not complete after the role change; the #8341 TCP-specific data-path defect may have returned. Pool probe log tail: ${pool_log}"
		fi
	else
		fail "after the crash failover AND the manual failback, a FRESH flow from ${POOL_SRC} got NO pool translation. The ports fw1 imported as reservations while it was standby are the ones a reserve/recycle lifecycle bug strands, and this is the only assertion in this suite that enters that state (#8280 / #7174 M13)"
	fi
fi

# #6934: the reported scenario. A manual RG failover moves the RETH virtual MAC,
# so every peer holding a neighbour entry for a VIP or for the stable RETH
# link-local must be corrected by the unsolicited-NA burst. The iperf3 check
# above cannot see a failure here: it is one long-lived IPv4 flow, so it
# survives on established state while a NEW IPv6 flow blackholes.
check_v6_transit "after manual failover"

# #6934: sample the window TWICE, not once. The reported symptom self-heals
# after ~60s with no intervention, and a single probe fired immediately after
# the failover reports a clean pass whether it landed before such a window
# opened or after it closed — a check that cannot distinguish "healthy" from
# "I sampled the wrong instant".
#
# Cost, counted rather than asserted: the 120s iperf3 starts at line ~207 and by
# the time control reaches here the script has already spent 8 + SYNC_WAIT + 3 +
# (reboot wait) + 20 + 5 seconds plus a 5-packet probe. With a typical reboot
# that leaves ~35-55s of iperf3 still to run, so the wait below overlaps it and
# Phase 5 just waits out the remainder — free. Only when the reboot consumes the
# full REBOOT_WAIT budget does any of it become extra wall clock, and then at
# most V6_RECHECK_DELAY of it.
sleep "$V6_RECHECK_DELAY"
check_v6_transit "${V6_RECHECK_DELAY}s after manual failover"

# ── Phase 5: Wait for iperf3 to complete and validate results ───────

info "Waiting for iperf3 to complete"

for i in $(seq 1 "$IPERF_DURATION"); do
	if ! incus exec "$CLUSTER_LAN_HOST" -- pgrep iperf3 &>/dev/null; then
		break
	fi
	sleep 1
done

# Check iperf3 completed successfully.
# iperf3's control socket may close during failover even though all data
# streams survived — this produces "control socket has closed unexpectedly"
# instead of "iperf Done". Accept either outcome as long as the sender
# [SUM] line shows adequate throughput.
# #6897: capture the whole [SUM] sender line and let the lib parse it. The
# previous inline parse matched only "Gbits", so a sub-Gbit run yielded the
# literal "0" and then matched NEITHER the pass branch nor the fail branch —
# there was no else, and the run emitted no throughput cell at all while still
# summarising as "0 failed". Sub-Gbit is exactly what a throughput regression
# or a CoS-shaped class looks like, so the gate went silent in the case it
# exists to catch.
sum_line=$(incus exec "$CLUSTER_LAN_HOST" -- grep '\[SUM\].*sender' /tmp/iperf3-failover.log 2>/dev/null \
	| tail -1 || true)
throughput=$(iperf_sum_rate_gbps "$sum_line")

if incus exec "$CLUSTER_LAN_HOST" -- grep -q "iperf Done" /tmp/iperf3-failover.log 2>/dev/null; then
	pass "iperf3 completed successfully"
elif [[ -n "$throughput" ]] && awk "BEGIN{exit !($throughput >= $MIN_THROUGHPUT)}"; then
	pass "iperf3 data transfer completed (${throughput} Gbps) — control socket disrupted during failover"
else
	iperf_log=$(incus exec "$CLUSTER_LAN_HOST" -- tail -5 /tmp/iperf3-failover.log 2>/dev/null || echo "(no log)")
	fail "iperf3 did not complete: $iperf_log"
fi

# The verdict is total: absent, unparseable, too-low and healthy each yield
# exactly one cell. The catch-all default keeps that true even if the lib ever
# grows a status this caller does not know about — a missing cell is the
# defect, so no path may end without emitting one.
throughput_verdict=$(iperf_throughput_verdict "$MIN_THROUGHPUT" "$sum_line")
case "$throughput_verdict" in
PASS\ *) pass "${throughput_verdict#PASS }" ;;
FAIL\ *) fail "${throughput_verdict#FAIL }" ;;
*)       fail "iperf3 throughput: unrecognised verdict from iperf_throughput_verdict: ${throughput_verdict}" ;;
esac

# The summary is the one line the harness ledger parses. Every measured cell
# is now an ordinary pass/fail assertion; there is no known-gap tally.
echo "  Failover test: $PASS passed, $FAIL failed"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [[ $FAIL -gt 0 ]]; then
	echo
	echo "Failures:"
	for err in "${ERRORS[@]}"; do
		echo "  - $err"
	done
	exit 1
fi
