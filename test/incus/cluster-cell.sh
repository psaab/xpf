# shellcheck shell=bash
#
# #1875 / #4020 — destructive-smoke lock preamble (sourced, never
# executed).
#
# The DESTRUCTIVE HA smoke scripts — test-failover, test-ha-crash,
# test-double-failover, test-stress-failover, test-chained-crash,
# test-active-active, test-restart-connectivity, test-private-rg —
# reboot / force-stop / fail over a node on the SHARED loss userspace
# cluster (loss:xpf-userspace-fw0/fw1). That is FAR more disruptive
# than a deploy, yet historically they took NO cluster lock: a reboot
# could collide with a concurrent agent's deploy or smoke (a deploy
# pushing binaries while a node reboots -> half-deployed node; a
# concurrent test-failover measuring loss while another reboots ->
# garbage results). #4020.
#
# This preamble serializes the destructive smoke under the canonical
# `XPF_CLUSTER_*` tuple. The default loss lock path is
# `/var/worktrees/.cache/tmpdir/xpf-cluster.lock`.
# TCP/UDP-specific callers must export their matching tuple to both
# this wrapper and any `cluster-setup.sh` command. Mutating verbs and
# apply-cos-config.sh already self-lock, so a test-failover QUEUES behind
# (or blocks on) a held lock instead of colliding. It never weakens the
# deploy/apply-cos lock — it is the identical re-exec-through-with-cluster.sh
# mechanism.
#
# Usage — source AFTER `set -euo pipefail`, BEFORE any incus/cluster
# work, passing the script's own path + args:
#
#   set -euo pipefail
#   _CELL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#   # shellcheck source=cluster-cell.sh
#   source "${_CELL_DIR}/cluster-cell.sh"
#   xpf_enter_destructive_cluster_cell "test-failover $*" "$0" "$@"
#
# xpf_enter_destructive_cluster_cell <purpose> <script-path> [args...]:
#   1. Re-execs under the incus-admin group if `incus` is not usable,
#      forwarding BPFRX_*/XPF_* explicitly. sg env preservation is not
#      guaranteed on every platform, and losing XPF_CLUSTER_LOCK_HELD
#      across the sg boundary would deadlock a run started inside a
#      with-cluster.sh cell (same reasoning as cluster-setup.sh's sg
#      re-exec — #1875 plan A3 / SMR r2 S1).
#   2. Serializes as a #1875 lock cell: inside a live with-cluster.sh
#      cell (valid marker from a live ancestor holder) it returns
#      immediately and the caller runs lock-free (cells nest); when
#      standalone it re-execs the WHOLE script through with-cluster.sh,
#      which blocks with a named-holder report until the cluster is
#      ours and re-runs the script with the marker set.
#
# The lock matches the deploy path: cluster-setup.sh's init/create/
# destroy/start/stop/restart use the canonical `XPF_CLUSTER_*` tuple for
# every cluster env, including legacy local xpf-fw0/1. Loss defaults to
# `/var/worktrees/.cache/tmpdir/xpf-cluster.lock`. TCP/UDP gates and ordinary
# commands must export the same suffixed tuple before both cluster-setup.sh
# and with-cluster.sh; default loss commands need no override.
#
# On return the caller holds (transitively) the cluster lock for the
# rest of its run; the kernel releases the flock when the cell's
# process tree exits (with-cluster.sh runs the cell with fd 9 closed).

_XPF_CELL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=cluster-lock.sh
source "${_XPF_CELL_DIR}/cluster-lock.sh"

xpf_enter_destructive_cluster_cell() { # <purpose> <script-path> [args...]
	local purpose="$1"; shift
	local script="$1"; shift

	# (1) incus-admin group re-exec. Forward BPFRX_*/XPF_* explicitly
	# so the #1875 lock marker (XPF_CLUSTER_LOCK_HELD) survives the sg
	# env boundary — otherwise a run started inside a with-cluster.sh
	# cell would lose the marker here and deadlock re-acquiring its own
	# ancestor's lock.
	if ! incus list &>/dev/null 2>&1; then
		if getent group incus-admin &>/dev/null && id -nG | grep -qw incus-admin; then
			local fwd="" _v
			for _v in "${!BPFRX_@}" "${!XPF_@}"; do
				fwd+="${_v}=$(printf '%q' "${!_v}") "
			done
			exec sg incus-admin -c "${fwd}$(printf '%q ' "$script" "$@")"
		fi
	fi

	# (2) #1875 lock cell. Inside a valid, live-ancestor cell -> run
	# lock-free; otherwise re-exec the whole script through
	# with-cluster.sh, which blocks on a held lock (queues behind a
	# concurrent deploy/smoke) instead of colliding with it.
	if xpf_cluster_lock_held; then
		return 0
	fi
	exec "${_XPF_CELL_DIR}/with-cluster.sh" "$purpose" -- "$script" "$@"
}
