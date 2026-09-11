#!/usr/bin/env bash
# Shared raw-deploy reconciliation + verification helpers for the xpf test
# Incus deploy paths (setup.sh and cluster-setup.sh).
#
# Both scripts push xpfd/cli/xpf-userspace-dp to a VM with `incus file push`
# and then (re)start the systemd unit. Two classes of stale-state on the
# target VM silently defeat that swap and make a deploy report success while
# the node keeps running OLD code — the #1 false-result hazard:
#
#   #2176 (a): a leftover #1917 in-place-upgrade drop-in
#     /etc/systemd/system/xpfd.service.d/10-xpf-version.conf pins ExecStart to
#     a CONCRETE versioned binary (versions/<ver>/xpfd). A raw `incus file push`
#     replaces /usr/local/sbin/xpfd, but systemd still launches the pinned
#     versioned path, so the freshly-pushed binary never runs.
#
#   #2176 (b): after that drop-in's versions/ dir is removed,
#     /usr/local/sbin/{xpfd,cli,xpf-userspace-dp} are left as DANGLING symlinks
#     into versions/current/<bin>. `incus file push` onto a dangling symlink
#     fails (no target to write through), breaking the deploy.
#
# These helpers run BEFORE the binary push to reconcile both, and AFTER the
# restart to ASSERT the running binary sha == the pushed sha (#2176 (c)) and
# that the effective ExecStart is the base-unit path (no surviving pin).
#
# #2162: deploy_verify_pushed_sha generalizes the helper-only sha readback
# (#1962/#1980) so xpfd and cli get the same HARD post-push verification.
#
# All functions take a FULLY-RESOLVED instance name (e.g. "loss:xpf-userspace-fw0"
# or "xpf-fw") because the two callers compute that differently (cluster-setup.sh
# r() remote prefix vs setup.sh INSTANCE_NAME). They depend on info()/warn()/die()
# being defined by the sourcing script (both define them identically).

# deploy_managed_bins is the set of binaries the deploy paths push into
# /usr/local/sbin and that the #1917 upgrade machinery links/pins. Keep in
# sync with pkg/upgrade manifest.Names() (xpfd, cli, xpf-userspace-dp).
deploy_managed_bins=(xpfd cli xpf-userspace-dp)

# The #1917 in-place-upgrade ExecStart pin drop-in (pkg/upgrade/flip.go
# unitDropinName). Removing it reverts the unit to the package/base-unit
# ExecStart=/usr/local/sbin/xpfd.
DEPLOY_VERSION_DROPIN="/etc/systemd/system/xpfd.service.d/10-xpf-version.conf"

# deploy_reconcile_stale_pin <rinst>
#
# Detect a stale xpfd ExecStart override drop-in on the target and remove it,
# reverting to the base-unit ExecStart=/usr/local/sbin/xpfd, then daemon-reload
# so the change is in effect before the unit is (re)started. Without this a raw
# deploy pushes a new /usr/local/sbin/xpfd that systemd never launches (#2176a).
#
# Only the xpf-managed pin file (10-xpf-version.conf) is removed automatically;
# any OTHER, operator-authored ExecStart override under xpfd.service.d is a HARD
# FAILURE (we will not silently delete a drop-in we did not write).
deploy_reconcile_stale_pin() {
	local rinst="$1"

	# Is the managed #1917 pin present?
	if incus exec "$rinst" -- test -f "$DEPLOY_VERSION_DROPIN" 2>/dev/null; then
		warn "Removing stale #1917 ExecStart pin ($DEPLOY_VERSION_DROPIN) on $rinst — it would pin systemd to an OLD versioned xpfd and silently defeat this deploy (#2176)."
		incus exec "$rinst" -- rm -f "$DEPLOY_VERSION_DROPIN" 2>/dev/null \
			|| die "failed to remove stale ExecStart pin $DEPLOY_VERSION_DROPIN on $rinst"
		# Drop an empty xpfd.service.d if nothing else remains, so the unit
		# is purely the base file again.
		incus exec "$rinst" -- bash -c 'd=/etc/systemd/system/xpfd.service.d; [ -d "$d" ] && [ -z "$(ls -A "$d" 2>/dev/null)" ] && rmdir "$d"; true' 2>/dev/null || true
		incus exec "$rinst" -- systemctl daemon-reload 2>/dev/null || true
	fi

	# Refuse to proceed if SOME OTHER ExecStart override survives in the
	# drop-in dir — a raw deploy must never leave an unknown pin in force.
	local other
	other=$(incus exec "$rinst" -- bash -c '
		d=/etc/systemd/system/xpfd.service.d
		[ -d "$d" ] || exit 0
		grep -lE "^[[:space:]]*ExecStart[[:space:]]*=" "$d"/*.conf 2>/dev/null || true
	' 2>/dev/null || true)
	if [[ -n "$other" ]]; then
		die "unexpected ExecStart override(s) under xpfd.service.d on $rinst — a raw deploy will not run the pushed binary while these pin a different path. Remove them or fix the drop-in, then re-deploy:
$other"
	fi
}

# deploy_reconcile_dangling_sbin <rinst>
#
# Detect dangling /usr/local/sbin/{xpfd,cli,xpf-userspace-dp} symlinks (left
# pointing into a removed versions/current/ after a #1917 dogfood was torn
# down) and remove them, so the subsequent `incus file push` lands a fresh
# REGULAR file instead of failing to write through a broken symlink (#2176b).
deploy_reconcile_dangling_sbin() {
	local rinst="$1"
	local b
	for b in "${deploy_managed_bins[@]}"; do
		local p="/usr/local/sbin/$b"
		# -L: is a symlink; -e: resolves to an existing target. A symlink
		# that is NOT -e is dangling.
		if incus exec "$rinst" -- bash -c "[ -L '$p' ] && [ ! -e '$p' ]" 2>/dev/null; then
			warn "Replacing dangling symlink $p on $rinst (points into a removed versions/ dir) with the freshly-pushed binary (#2176)."
			incus exec "$rinst" -- rm -f "$p" 2>/dev/null \
				|| die "failed to remove dangling symlink $p on $rinst"
		fi
	done
}

# deploy_verify_pushed_sha <rinst> <local_path> <remote_path> <label>
#
# Assert the on-VM sha256 of a just-pushed binary matches the local build.
# An `incus file push` can silently no-op and the local build can be stale;
# either leaves the VM running an old/absent binary. HARD FAIL on mismatch or
# empty readback (#2162 generalizes the #1962/#1980 helper-only check).
deploy_verify_pushed_sha() {
	local rinst="$1" local_path="$2" remote_path="$3" label="$4"
	local local_sum vm_sum
	local_sum=$(sha256sum "$local_path" | awk '{print $1}')
	# Readback may fail (binary absent) — || true so the explicit empty-check
	# below produces the clear diagnostic instead of set -e aborting here.
	vm_sum=$(incus exec "$rinst" -- sha256sum "$remote_path" 2>/dev/null | awk '{print $1}' || true)
	if [[ -z "$vm_sum" ]]; then
		die "$label not present on $rinst after push (sha256 readback empty: $remote_path)"
	fi
	if [[ "$local_sum" != "$vm_sum" ]]; then
		die "$label sha256 mismatch after push to $rinst (local=$local_sum vm=$vm_sum) — push silently no-op'd or the build is stale"
	fi
	info "Verified $label sha256 on $rinst ($local_sum)."
}

# deploy_running_xpfd_sha256 <rinst> [tries]
#
# Read back the sha256 of the LIVE xpfd process image on <rinst> and echo it on
# stdout; echo nothing (rc 1) if the unit has no live MainPID after <tries>
# one-second attempts (default 15). Never dies -- the caller decides whether an
# unreadable running-binary sha is fatal (a deploy: yes, #2176) or a recorded
# VOID (a ledger row: see test/incus/harness-result.sh).
#
# Extracted from deploy_verify_running_xpfd so there is exactly ONE running-exe
# readback in the tree. A second implementation would be free to disagree with
# this one about which process it read, and the whole point of the readback is
# that it is the authority on what is actually executing.
#
# Falsifiability: if the node is running something other than the pushed build
# this returns that other binary's sha, and every caller compares. If the
# measurement did not happen (no MainPID, incus unreachable, the unit dead) it
# returns EMPTY with rc 1 -- it never falls back to the on-disk path's sha,
# which would be a value indistinguishable from a healthy readback. On an empty
# instance name it returns empty rc 1 rather than reading the local host.
deploy_running_xpfd_sha256() {
	local rinst="${1:-}" tries_max="${2:-15}"
	[[ -n "$rinst" ]] || return 1
	local tries=0 run_raw="" run_sum=""
	while [[ $tries -lt $tries_max ]]; do
		# The remote emits the raw `sha256sum /proc/PID/exe` line; the first
		# field is split off locally to avoid nested single-quote awk fragility.
		# sha256sum on /proc/PID/exe reads the LIVE process image even if the
		# on-disk file was replaced after exec ("(deleted)").
		run_raw=$(incus exec "$rinst" -- bash -c '
			p=$(systemctl show -p MainPID --value xpfd 2>/dev/null)
			[ -n "$p" ] && [ "$p" != "0" ] || exit 1
			sha256sum "/proc/$p/exe" 2>/dev/null || exit 1
		' 2>/dev/null || true)
		run_sum=${run_raw%% *}
		[[ -n "$run_sum" ]] && break
		tries=$((tries + 1))
		# The wait exists so a unit that is still coming up is not read as
		# absent; it is a backstop on a WAIT, not a pass criterion.
		[[ $tries -lt $tries_max ]] && sleep 1
	done
	[[ -n "$run_sum" ]] || return 1
	printf '%s\n' "$run_sum"
}

# deploy_verify_running_xpfd <rinst> <local_xpfd_path>
#
# After (re)start, assert the LIVE xpfd process is the binary we just pushed
# (running-exe sha == local build) AND that the effective systemd ExecStart is
# the base-unit /usr/local/sbin/xpfd path — i.e. no version pin survived. This
# is the backstop that turns a silent stale-binary deploy into a HARD failure
# (#2176c). The whole point: a deploy MUST rc!=0 if the running binary != the
# pushed binary.
deploy_verify_running_xpfd() {
	local rinst="$1" local_xpfd="$2"
	local local_sum want_exec="/usr/local/sbin/xpfd"
	local_sum=$(sha256sum "$local_xpfd" | awk '{print $1}')

	# Effective ExecStart must resolve to the base-unit path. `systemctl show`
	# emits ExecStart={ path=/usr/local/sbin/xpfd ; ... }; extract the path=.
	local exec_path
	exec_path=$(incus exec "$rinst" -- bash -c "systemctl show -p ExecStart --value xpfd 2>/dev/null | sed -n 's/.*path=\([^ ;]*\).*/\1/p' | head -n1" 2>/dev/null || true)
	if [[ -z "$exec_path" ]]; then
		die "could not read effective xpfd ExecStart on $rinst — cannot confirm the deploy is in effect"
	fi
	if [[ "$exec_path" != "$want_exec" ]]; then
		die "xpfd ExecStart on $rinst is '$exec_path', not the base-unit '$want_exec' — a version pin survived this deploy (#2176); systemd is launching a different binary than was pushed"
	fi

	# Running-process exe sha must equal the local build.
	local run_sum=""
	run_sum=$(deploy_running_xpfd_sha256 "$rinst")
	if [[ -z "$run_sum" ]]; then
		die "xpfd is not running on $rinst after deploy (no live MainPID) — cannot verify the running binary"
	fi
	if [[ "$run_sum" != "$local_sum" ]]; then
		die "running xpfd on $rinst (sha256=$run_sum) does not match the pushed build (sha256=$local_sum) — the deploy did NOT take effect (#2176); the node is running STALE code"
	fi
	info "Verified running xpfd on $rinst matches the pushed build ($local_sum, ExecStart=$exec_path)."
}

# ── Rolling-deploy node ordering (#4009) ─────────────────────────────
# A rolling cluster deploy must restart the SECONDARY node first (traffic
# stays on the primary), then the primary. Getting the order wrong restarts
# the primary while the standby is not yet upgraded/ready → a spurious
# mid-deploy failover that masks real failover behavior in downstream smoke.
#
# These parsers are PURE (stdin → stdout, no incus, no info/warn/die) so the
# selftest can exercise them offline against captured `show chassis cluster
# status` samples.

# deploy_rolling_secondary_node reads `cli -c "show chassis cluster status"`
# output (run on node0) on stdin and echoes the node index (0 or 1) to upgrade
# FIRST — the RG0 SECONDARY. node0's own RG0 row reports node0's role directly:
#
#   Redundancy group: 0 , Failover count: 0
#   node0   200       primary        no       no       None
#   node1   100       secondary      no       no       None
#
# If node0's RG0 Status is "secondary" (or "secondary-hold"), node0 is the
# secondary and is upgraded first → echo 0. Otherwise node1 is the secondary
# → echo 1. Defaults to 1 (node0 primary / node1 secondary — the documented
# steady state) when RG0's node0 row is absent or unparseable.
#
# #4009: the legacy inline grep pattern "secondary:node0" never matched this
# space-separated, lowercase status output, so detection ALWAYS fell through to
# the default (node1 first). Whenever node0 was actually the RG0 secondary, the
# deploy then restarted node1 (the PRIMARY) first → a spurious mid-deploy
# failover. The RG number is read from the "Redundancy group: N" header so the
# decision is scoped to RG0 even in active-active (multi-RG) layouts.
deploy_rolling_secondary_node() {
	awk '
		/^Redundancy group:[[:space:]]/ { rg = $3; next }
		(rg == "0") && ($1 == "node0") {
			st = tolower($3)
			if (st ~ /^secondary/) { print 0 } else { print 1 }
			found = 1
			exit
		}
		END { if (found != 1) print 1 }
	'
}

# deploy_rolling_rg_ids reads `show chassis cluster status` on stdin and echoes
# the redundancy-group ids present (one per line, ascending, deduplicated).
# Used by the post-deploy node0-primary reassert to iterate every RG.
deploy_rolling_rg_ids() {
	awk '/^Redundancy group:[[:space:]]/ { print $3 }' | sort -n -u
}

# ── Post-deploy node0-primary reassert (#4009, fail-closed in #6591) ──
#
# deploy_reassert_node0_primary_ok reads `show chassis cluster status` on stdin
# and succeeds ONLY IF at least one redundancy group is present AND node0 reads
# exactly `primary` for EVERY one of them.
#
# The "at least one" clause is the #6591 fix, not a formality. The pre-fix
# reassert treated an unreadable status as "no redundancy groups to iterate",
# did nothing, warned, and returned SUCCESS — so a deploy that reasserted
# NOTHING was indistinguishable from one that succeeded, and the failure
# surfaced minutes later in an unrelated smoke target's preflight where the
# natural first hypothesis is that the change under test broke HA. An empty or
# unparseable status must therefore FAIL here.
#
# The comparison is `$3 == "primary"`, exact and scoped to the node0 row of the
# CURRENT group — not a `grep "node0.*primary"`. A grep cannot express "every
# RG", which is the property that matters: the reassert loops all groups, so a
# check satisfied by any single group would pass while the others stayed
# inverted.
deploy_reassert_node0_primary_ok() {
	deploy_node_role_every_rg_ok node0 primary
}

# deploy_node_role_every_rg_ok is the generalisation of the predicate above:
# it reads `show chassis cluster status` on stdin and succeeds ONLY IF at least
# one redundancy group is present AND <node> reads exactly <role> for EVERY one
# of them. deploy_reassert_node0_primary_ok is (node0, primary) and keeps its
# own name because it is the vocabulary the deploy path and #6591 use.
#
# #7368 fixed the DEPLOY precondition this way. The same unscoped shape survived
# in test-failover.sh's post-reboot rejoin assertions, and there it was worse
# than "can pass on a partial state": the rejoin check tried `node0.*secondary`
# FIRST and `node0.*primary` second, so a cluster that auto-preempted for RG1
# while staying secondary for RG0 matched the FIRST grep and reported PASS. The
# elif that exists to name the auto-preempt regression was unreachable in exactly
# the mixed case it was written for. A grep cannot express "every RG" in either
# direction, so both roles need the scoped form, not just the primary one.
deploy_node_role_every_rg_ok() {
	local node="${1:?deploy_node_role_every_rg_ok: node required}"
	local role="${2:?deploy_node_role_every_rg_ok: role required}"
	awk -v node="$node" -v role="$role" '
		/^Redundancy group:[[:space:]]/ { rg = $3; seen[rg] = 1; next }
		$1 == node { if (rg != "" && $3 == role) { ok[rg] = 1 } }
		END {
			n = 0
			for (g in seen) { n++; if (!(g in ok)) { exit 1 } }
			if (n == 0) { exit 1 }
			exit 0
		}
	'
}

# failover_ownership_verdict cross-references the two independent checks
# test-failover.sh already performs, and is the #7368 half of the #6591 fix.
#
# The smoke asserts primacy by reading `show chassis cluster status` — a field
# the node reports about ITSELF — and separately asserts that the same node
# carries established sessions, which is a real measurement. The two are never
# compared. #6656 showed what that costs: node0 reported primary for every RG
# with 1 session while node1 carried 33, and the smoke's session assertion
# caught it only INCIDENTALLY, reporting a session-count shortfall on a run
# whose actual failure was ownership/forwarding divergence.
#
# Arguments: sessions on the node REPORTED primary, sessions on its peer, and
# the minimum a healthy primary must carry. Echoes one of:
#
#   ok        the reported primary carries the traffic
#   diverged  the reported primary carries almost nothing while the PEER does
#             — ownership and forwarding disagree
#   nostream  neither node carries traffic — the iperf streams did not
#             establish, which is a different failure with a different fix
#
# Split out here so deploy-lib-selftest.sh can drive every combination without
# a cluster; the caller only formats the message.
failover_ownership_verdict() {
	local primary_sessions="$1" peer_sessions="$2" min_sessions="$3"
	if [[ "$primary_sessions" -ge "$min_sessions" ]]; then
		printf 'ok\n'
		return 0
	fi
	if [[ "$peer_sessions" -ge "$min_sessions" ]]; then
		printf 'diverged\n'
		return 0
	fi
	printf 'nostream\n'
}

# Bounded retries for the two reads. Overridable so the self-test does not
# sleep. The status read needs them because the daemon is still coming up right
# after a deploy: the measured failure was a reassert issued ~20s post-deploy
# that did not take, while the identical command issued later did.
DEPLOY_REASSERT_READ_TRIES="${DEPLOY_REASSERT_READ_TRIES:-30}"
DEPLOY_REASSERT_READ_DELAY="${DEPLOY_REASSERT_READ_DELAY:-2}"
DEPLOY_REASSERT_VERIFY_TRIES="${DEPLOY_REASSERT_VERIFY_TRIES:-15}"
DEPLOY_REASSERT_VERIFY_DELAY="${DEPLOY_REASSERT_VERIFY_DELAY:-2}"
# #7771: budget for the transfer to COMMIT before the pin that drove it is
# cleared. Defaults track the verify tunables so the self-test's DELAY=0 (which
# makes the retry COUNT the thing under test) applies here too without a second
# knob to remember.
DEPLOY_REASSERT_TRANSFER_TRIES="${DEPLOY_REASSERT_TRANSFER_TRIES:-$DEPLOY_REASSERT_VERIFY_TRIES}"
DEPLOY_REASSERT_TRANSFER_DELAY="${DEPLOY_REASSERT_TRANSFER_DELAY:-$DEPLOY_REASSERT_VERIFY_DELAY}"

# #7962: the verify budget when the degraded-promotion FALLBACK is the only path
# to convergence.
#
# On an idle cluster, XSK liveness cannot self-prove on the node this reassert
# checks. `shouldAutoProveIdleStandbyXSKLocked` requires `!hasActiveDataRGLocked()`
# and node0 holds RG1, so the auto-prove arm is unreachable there; with no traffic
# `currentRX` stays 0 and the RG waits out
# `cluster.DefaultDegradedPromoteTimeout` (120s). The old budget was
# TRIES*DELAY = 30s, so the gate could not pass on a restarted idle cluster
# unless traffic happened to flow inside its window — it failed BY CONSTRUCTION,
# and both its passes and its failures were timing artifacts (#7688, #7939, #7962).
#
# This number MUST exceed that fallback. It is not independently chosen and must
# not be tuned on its own: TestDeployReassertBudgetExceedsDegradedFallback7962
# (pkg/cluster) reads this default out of this file and fails if either side
# moves such that the budget no longer covers the fallback. Change one, that test
# tells you about the other.
DEPLOY_REASSERT_FALLBACK_BUDGET_S="${DEPLOY_REASSERT_FALLBACK_BUDGET_S:-150}"

# Whether to PRIME dataplane liveness with a little traffic before verifying.
#
# This is what an operator does by hand, and it is the difference between asking
# the system for proof it cannot produce and supplying the precondition. A
# handful of packets LAN->WAN makes the node log `XSK liveness proven` in
# seconds, so the common idle case converges immediately instead of waiting out
# the 120s fallback. Set to 0 to skip (the self-test does).
DEPLOY_REASSERT_PRIME_LIVENESS="${DEPLOY_REASSERT_PRIME_LIVENESS:-1}"
DEPLOY_REASSERT_PRIME_COUNT="${DEPLOY_REASSERT_PRIME_COUNT:-20}"

# deploy_reassert_prime_liveness drives a few packets through the data path so
# the helper can prove XSK liveness. Returns 0 if traffic was actually sent, 1 if
# it could not be (no LAN host, no target, unreachable).
#
# The RETURN VALUE is load-bearing and is not about success of the ping: it
# records whether the precondition was SUPPLIED, which is what lets the failure
# message below tell "the helper did not prove liveness despite forwarded
# traffic" apart from "nothing ever asked it to forward a packet". Those are the
# two states this gate used to crush into one, and the reason its failures cost
# lanes an afternoon.
deploy_reassert_prime_liveness() {
	local lan="${CLUSTER_LAN_HOST:-}" target="${IPERF_TARGET4:-${IPERF_TARGET:-}}"
	[[ "$DEPLOY_REASSERT_PRIME_LIVENESS" == "1" ]] || return 1
	[[ -n "$lan" && -n "$target" ]] || return 1
	incus exec "$lan" -- ping -c "$DEPLOY_REASSERT_PRIME_COUNT" -i 0.05 -W 1 "$target" \
		>/dev/null 2>&1 || true
	# Ping REPLIES are not required: a one-way packet still drives RX on the
	# firewall, which is all liveness needs. What matters is that we were able
	# to issue traffic at all.
	return 0
}

# deploy_reassert_primary_node0 leaves node0 the primary for EVERY redundancy
# group after a deploy, so downstream smoke (apply-cos-config, test-failover)
# starts from the documented node0-primary steady state regardless of preempt
# config.
#
# It is NO LONGER best-effort (#6591). It dies if it cannot establish that
# state, because the alternative — the pre-fix behaviour — is a preflight that
# fails OPEN, and a preflight that fails open is how a real HA regression gets
# laundered as an infrastructure hiccup. The deploy returning 0 while the
# cluster is left inverted relative to its configured priorities (node0 at
# priority 200 sitting secondary behind node1 at 100, because preempt=no means
# nothing corrects it) cost two misdiagnosed gate cycles.
#
# Sequence per RG, on node0: reset -> transfer -> reset.
#   - the leading reset clears a stale manual-failover flag that would
#     otherwise refuse the transfer;
#   - the transfer is what actually MOVES ownership (`failover reset` alone
#     never did — that was the original #6591 report);
#   - the trailing reset clears the flag the transfer itself sets, which
#     otherwise blocks the peer from electing during a later reboot leg.
#
# The trailing reset is safe to add precisely BECAUSE the verify below is
# fail-closed: if clearing the flag ever moved ownership back, this dies loudly
# instead of handing the next smoke an inverted cluster.
deploy_reassert_primary_node0() {
	local rinst="$1"
	# #7688: the PEER instance. ManualFailover is LOCAL, UNSYNCED node state --
	# there is no `manual` field in the proto and none in the heartbeat sync --
	# so a pin left on the peer cannot be observed or cleared from node0.
	local pinst="${2:-}"
	local status rgs rg try

	status=""
	rgs=""
	for (( try = 0; try < DEPLOY_REASSERT_READ_TRIES; try++ )); do
		status=$(incus exec "$rinst" -- cli -c "show chassis cluster status" 2>/dev/null || true)
		rgs=$(printf '%s\n' "$status" | deploy_rolling_rg_ids)
		[[ -n "$rgs" ]] && break
		sleep "$DEPLOY_REASSERT_READ_DELAY"
	done
	if [[ -z "$rgs" ]]; then
		die "post-deploy primary reassert: could not read cluster status from $rinst after ${DEPLOY_REASSERT_READ_TRIES} attempts. NOT continuing: the pre-#6591 code warned and returned success here, leaving the next HA smoke to discover an un-reasserted cluster in its own preflight."
	fi

	while read -r rg; do
		[[ -n "$rg" ]] || continue
		# Clear the PEER's manual pin FIRST. A pinned peer cannot participate
		# in the election this transfer depends on -- test-failover.sh says it
		# outright: "ManualFailover blocks election even when the peer is
		# lost." Because the flag is local and unsynced, resetting it on node0
		# (below) does nothing for a pin left on node1 by an earlier smoke:
		# every HA smoke resets BOTH nodes as a preamble but none as a
		# teardown, so the cluster is routinely left pinned on exit. The next
		# deploy is then what fails, and it fails as "node0 is not primary for
		# every redundancy group" -- indistinguishable from an HA regression in
		# whatever branch happened to deploy next (#7688).
		if [[ -n "$pinst" ]]; then
			incus exec "$pinst" -- cli -c "request chassis cluster failover reset redundancy-group $rg" >/dev/null 2>&1 || true
		fi
		incus exec "$rinst" -- cli -c "request chassis cluster failover reset redundancy-group $rg" >/dev/null 2>&1 || true
		incus exec "$rinst" -- cli -c "request chassis cluster failover redundancy-group $rg node 0" >/dev/null 2>&1 || true
	done <<<"$rgs"

	# #7771: WAIT for the transfers to commit before clearing the pins. The
	# `failover ... node 0` above IS a manual pin, and it is the only thing
	# driving the transfer; the pre-#7771 code cleared it on the very next line.
	# When the reset won that race the RG fell back to the natural election and
	# stayed on node1 -- correct behaviour for a non-preempting cluster
	# (`Preempt: no` on every row) and exactly the state the deploy must not
	# leave. Measured: the same commands by hand WITH a wait between them fixed
	# it on the first attempt.
	#
	# Once the transfer has actually committed, clearing the pin is safe for the
	# same reason the race was fatal: a non-preempting cluster leaves the new
	# primary in place. So the wait is not a settling heuristic -- it is the
	# precondition that makes the reset non-destructive.
	#
	# Bounded, and the pins are cleared BELOW whether or not this converges. A
	# left-behind pin is #7688's failure and is not traded away for this one:
	# the verify loop after it is still the verdict.
	for (( try = 0; try < DEPLOY_REASSERT_TRANSFER_TRIES; try++ )); do
		status=$(incus exec "$rinst" -- cli -c "show chassis cluster status" 2>/dev/null || true)
		if printf '%s\n' "$status" | deploy_reassert_node0_primary_ok; then
			break
		fi
		(( DEPLOY_REASSERT_TRANSFER_DELAY > 0 )) && sleep "$DEPLOY_REASSERT_TRANSFER_DELAY"
	done

	# Clear the pins. UNCONDITIONAL: see above -- an un-cleared pin blocks the
	# next election and is what #7688 was filed about.
	while read -r rg; do
		[[ -n "$rg" ]] || continue
		incus exec "$rinst" -- cli -c "request chassis cluster failover reset redundancy-group $rg" >/dev/null 2>&1 || true
	done <<<"$rgs"

	# Individual requests are tolerated (|| true) because the VERDICT is the
	# observed role, not the exit code of any one CLI call. A transfer that
	# returns non-zero but lands is fine; one that returns zero and does not
	# land is not — and only this read can tell them apart.
	# #7962: supply the precondition before demanding the proof. On an idle
	# cluster liveness cannot self-prove on this node, so without traffic the
	# only path to convergence is the 120s degraded fallback.
	local primed=0 tries="$DEPLOY_REASSERT_VERIFY_TRIES" regime="primed"
	if deploy_reassert_prime_liveness; then
		primed=1
	else
		# Priming was not possible, so the fallback IS the mechanism and the
		# budget must cover it. Derived, not independently chosen — see
		# DEPLOY_REASSERT_FALLBACK_BUDGET_S.
		regime="fallback"
		# Guard the divisor. The self-test runs with DELAY=0 so it never sleeps;
		# dividing by it aborts the function under `set -e` and turns every
		# should-succeed case into a failure — which is exactly what it did on
		# the first run of this change.
		if (( DEPLOY_REASSERT_VERIFY_DELAY > 0 )); then
			tries=$(( DEPLOY_REASSERT_FALLBACK_BUDGET_S / DEPLOY_REASSERT_VERIFY_DELAY ))
			(( tries > DEPLOY_REASSERT_VERIFY_TRIES )) || tries="$DEPLOY_REASSERT_VERIFY_TRIES"
		fi
	fi

	for (( try = 0; try < tries; try++ )); do
		status=$(incus exec "$rinst" -- cli -c "show chassis cluster status" 2>/dev/null || true)
		if printf '%s\n' "$status" | deploy_reassert_node0_primary_ok; then
			info "Re-asserted node0 primary for all redundancy groups (post-deploy, verified; ${regime} regime)."
			return 0
		fi
		sleep "$DEPLOY_REASSERT_VERIFY_DELAY"
	done

	# #7962: say WHICH failure this is. A gate that fails identically whether
	# the helper is broken or whether nothing asked it to forward a packet
	# carries no information, and its failures get read as HA regressions.
	local diagnosis
	if (( primed == 1 )); then
		diagnosis="Traffic WAS driven through the data path before this wait (${DEPLOY_REASSERT_PRIME_COUNT} packets to ${IPERF_TARGET4:-${IPERF_TARGET:-the smoke target}}), so the dataplane had the opportunity to prove XSK liveness and did not take it. Treat this as a REAL dataplane/HA signal."
	else
		diagnosis="Traffic could NOT be driven (no reachable LAN host/target), so liveness had no opportunity to be proven and this wait depended entirely on the ${DEPLOY_REASSERT_FALLBACK_BUDGET_S}s degraded-promotion fallback. If the status below says 'userspace XSK liveness not proven', the precondition was absent rather than the dataplane broken — that is NOT an HA regression (#7962)."
	fi
	die "post-deploy primary reassert FAILED: node0 is not primary for every redundancy group after ${tries} verification attempts (${regime} regime). ${diagnosis} The cluster is left in whatever state the transfer produced. Last status from $rinst:
${status}"
}

# ── #1864 verify-dataplane pre-flight (#6493) ────────────────────────
# The embedded AF_XDP shim object in a freshly built xpfd can be REJECTED by
# the target box's BPF verifier (a drifted `make generate` toolchain, or simply
# an older kernel on the VM than on the build host). Nothing else in a deploy
# notices: `incus file push` succeeds, deploy_verify_pushed_sha compares BYTES,
# and deploy_verify_running_xpfd only proves systemd launched the pushed image.
# All three pass while the node comes up in config-only mode with NO dataplane,
# and the failure surfaces later as a forwarding mystery. That is the
# 2026-06-10 #1864 incident mode exactly.
#
# So every path that swaps xpfd on a live box proves the new binary's shim
# LOADS on THAT box's kernel first. The cluster deploy has done this since
# #1869; the standalone test/incus deploy did not, which is the venue where
# shim iteration actually happens (#6493). This is the shared implementation
# both callers now use.

# Where the candidate binary is staged on the target for the probe. Deliberately
# NOT /usr/local/sbin/xpfd: the whole point is to decide BEFORE replacing
# anything the running daemon depends on.
DEPLOY_PREFLIGHT_PATH="/tmp/xpfd.preflight"

# deploy_verify_dataplane_preflight <rinst> <local_xpfd>
#
# ORDERING INVARIANT — the reason this function exists and the thing to protect
# in review: NO dataplane stop, `xpfd cleanup`, pkill, binary replacement, or
# legacy-name (bpfrxd) migration may run before this returns. On REJECT it
# die()s, so the caller aborts with the OLD daemon still running and forwarding.
# A preflight placed after `systemctl stop xpfd` proves the same fact but has
# already taken the box down to learn it, which is the bug.
#
# The probe LOADS anonymous maps only — no pin writes, no attach — so the live
# dataplane is untouched. Its spec validation does READ the live pins
# (validateUserspaceShimLivePins): a pinned-map ABI mismatch refuses with exit 1,
# which is not the #1864 verifier reject (exit 3), and the two print different
# remediation below (#9558).
#
# CPU contract: the verifier walk costs ~17s of one core on a REJECT. Running
# that on an AF_XDP worker core would stall forwarding on a box that is still
# in service, so it runs on the COMPLEMENT of the worker cores, derived from the
# live xpf-userspace-dp tasks' Cpus_allowed_list, at nice -19. If the complement
# is empty or cannot be derived (no helper running — the standalone case on a
# box whose daemon is down), it falls back to nice -19 across all CPUs.
deploy_verify_dataplane_preflight() {
	local rinst="$1" local_xpfd="$2"

	[[ -f "$local_xpfd" ]] \
		|| die "verify-dataplane pre-flight: local xpfd not found at $local_xpfd — nothing to verify (build first)"

	info "Pre-flight: verifying new xpfd dataplane object on $rinst..."
	incus file push "$local_xpfd" "${rinst}${DEPLOY_PREFLIGHT_PATH}" --mode 0755 \
		|| die "verify-dataplane pre-flight: failed to stage $local_xpfd at ${DEPLOY_PREFLIGHT_PATH} on $rinst — deploy aborted, old daemon untouched"

	local verify_rc=0
	incus exec "$rinst" -- bash -c '
		set -u
		free_cpus() {
			# Worker threads pin themselves to exactly one CPU each
			# (userspace-dp pin_current_thread); collect the
			# single-CPU Cpus_allowed_list values (unpinned control
			# threads report full ranges and are not workers) and
			# return the complement vs online CPUs.
			# pidof, not pgrep -x: the process name is 16 chars,
			# past the 15-char comm truncation pgrep -x matches on.
			local pid used t v
			pid=$(pidof -s xpf-userspace-dp 2>/dev/null)
			[ -n "$pid" ] || return 1
			used=""
			for t in /proc/"$pid"/task/*/status; do
				[ -r "$t" ] || continue
				v=$(awk -F"\t" "/^Cpus_allowed_list/ {print \$2}" "$t")
				[[ "$v" =~ ^[0-9]+$ ]] && used="$used $v"
			done
			[ -n "${used// /}" ] || return 1
			seq 0 $(( $(nproc --all) - 1 )) | \
				awk -v used="$used" "BEGIN{n=split(used,a,\" \"); for(i=1;i<=n;i++) u[a[i]]=1} !(\$0 in u)" | \
				paste -sd, -
		}
		MASK=$(free_cpus 2>/dev/null || true)
		# Probe the mask before trusting it: the complement is taken
		# against `nproc --all` (configured CPUs), which can include
		# offline CPUs — taskset then EINVALs and, because this exec
		# chain treats any non-zero exit as a verifier REJECT, a bad
		# mask would false-reject a good binary (observed live on
		# fw1 during the #1864 deploy smoke). An unusable mask falls
		# back to the un-pinned nice-only run.
		if [ -n "$MASK" ] && taskset -c "$MASK" true 2>/dev/null; then
			exec nice -n 19 taskset -c "$MASK" '"$DEPLOY_PREFLIGHT_PATH"' verify-dataplane
		fi
		exec nice -n 19 '"$DEPLOY_PREFLIGHT_PATH"' verify-dataplane
	' || verify_rc=$?
	if (( verify_rc != 0 )); then
		deploy_preflight_cleanup "$rinst"
		# #9558: verify-dataplane exits 3 ONLY for the #1864 kernel-verifier
		# reject (dataplane.ErrUserspaceShimVerifierReject). Every other refusal
		# exits 1, including a live pinned-map ABI mismatch, and rebuilding the
		# shim cannot fix those. Print the #1864 remediation for exit 3 only;
		# for anything else, point at verify-dataplane's own message.
		if (( verify_rc == 3 )); then
			die "verify-dataplane REJECTED the new binary's embedded shim on $rinst — deploy aborted, old daemon untouched.
  This is the #1864 failure mode. Rebuild with the pinned toolchain (make generate) or restore the tracked object:
    git checkout -- pkg/dataplane/userspace_xdp_bpfel.o && make build"
		fi
		die "verify-dataplane refused the new binary on $rinst (exit $verify_rc) — deploy aborted, old daemon untouched.
  This is NOT the #1864 kernel-verifier reject (that exits 3), so rebuilding the shim will not help.
  The cause and its remediation are in verify-dataplane's own message above (for example, a live
  pinned-map ABI mismatch needs the stale pin cleared)."
	fi
	deploy_preflight_cleanup "$rinst"
	info "Pre-flight PASS: the new xpfd's embedded shim loads on $rinst's kernel."
}

# deploy_preflight_cleanup <rinst>
#
# Remove the staged candidate. Runs on BOTH the PASS and the REJECT path — a
# REJECT that leaves a stale /tmp/xpfd.preflight behind seeds the next probe's
# diagnosis with a binary nobody asked about. Best-effort by design: a failure
# to unlink must not turn a passing pre-flight into a failed deploy.
deploy_preflight_cleanup() {
	local rinst="$1"
	incus exec "$rinst" -- rm -f "$DEPLOY_PREFLIGHT_PATH" 2>/dev/null || true
}
