# shellcheck shell=bash
#
# #1875 — shared-cluster lock helpers (sourced, never executed).
#
# The loss userspace cluster (loss:xpf-userspace-fw0/fw1) is shared by
# multiple cooperating agents on this dev box. Mutual exclusion is the
# advisory flock on /tmp/xpf-cluster.lock; ownership *visibility* is
# the metadata in /tmp/xpf-cluster.owner. Protocol (converged plan,
# docs/pr/1875-cluster-ownership/plan.md):
#
#   - test/incus/with-cluster.sh is the ONLY long-lived, self-locking,
#     marker-exporting holder. It exports
#         XPF_CLUSTER_LOCK_HELD="<lockpath>:<holderpid>"
#     while a lock cell is active.
#   - Scripts that self-lock (cluster-setup.sh mutating verbs,
#     apply-cos-config.sh) re-exec through with-cluster.sh when the
#     marker is absent and run lock-free when it is valid.
#   - Standalone per-command `flock /tmp/xpf-cluster.lock <cmd>`
#     holders (wg-interop.sh inc(), ad-hoc one-liners around commands
#     that do NOT self-lock) remain valid and never set the marker.
#   - Owner-epoch witness (#10126): with-cluster.sh publishes one
#     unique acquisition token to the persistent sidecar
#     ${XPF_CLUSTER_EPOCH} while holding the lock (acquires serialize,
#     so no token is lost). The read-only connectivity gate snapshots
#     the witness at its START probe and VOIDs at END when it moved —
#     closing the F-158 whole-window hole for cell holders.
#     Production's state directory is deliberately NON-STICKY: unlike
#     /tmp itself, it permits a different cooperating user to atomically
#     replace the mode-0666 epoch file. Legacy/raw-flock probes may
#     truncate the lock inode, but cannot erase this sidecar witness.
#     Per-command raw-flock holders publish no metadata and never bump:
#     edge overlap with them is still caught by the flock probe, while
#     a raw cycle that falls entirely mid-window remains polling-invisible.
#   - NEVER `rm` the lock, owner, or epoch files/state directory: flock
#     binds the lock inode, so deleting any persistence path can split
#     the mutex or erase the owner-epoch witness. Recovery from a stuck
#     holder is `kill <holder-pid>` (the kernel releases the lock when
#     its fd closes), never `rm`.
#
# Everything here must be safe under `set -euo pipefail` in consumers:
# no unguarded reads, no unguarded kill -0, no traps, no global state
# beyond the four XPF_CLUSTER_* path variables.

XPF_CLUSTER_LOCK="${XPF_CLUSTER_LOCK:-/tmp/xpf-cluster.lock}"
XPF_CLUSTER_OWNER="${XPF_CLUSTER_OWNER:-/tmp/xpf-cluster.owner}"
# The epoch witness is a persistent sidecar, not lock-inode content:
# legacy/read-only probes open the lock path with `>` and may truncate
# it, but must never erase an acquisition witness. Production uses a
# cooperatively writable, NON-STICKY state directory so a different
# user can atomically replace the 0666 epoch file; private hermetic
# callers override XPF_CLUSTER_EPOCH to a path under their temp tree.
XPF_CLUSTER_EPOCH_STATE_DIR="${XPF_CLUSTER_EPOCH_STATE_DIR:-/tmp/xpf-cluster-state}"
XPF_CLUSTER_EPOCH="${XPF_CLUSTER_EPOCH:-${XPF_CLUSTER_EPOCH_STATE_DIR}/epoch}"

# True (0) iff XPF_CLUSTER_LOCK_HELD names THIS lock path and a holder
# pid that is alive AND an ancestor of the current process. Any parse
# or validation failure returns 1: the caller then waits for the lock,
# which is always safe — the failure direction is never "skip the
# lock". The ancestry walk defeats the stale-marker leak (a cell's
# backgrounded daemon that outlives the cell inherits the env but is
# no longer a descendant of a live holder).
xpf_cluster_lock_held() {
	local marker="${XPF_CLUSTER_LOCK_HELD:-}"
	[[ -n "$marker" ]] || return 1
	local mpath="${marker%:*}" mpid="${marker##*:}"
	[[ "$mpath" == "$XPF_CLUSTER_LOCK" ]] || return 1
	[[ "$mpid" =~ ^[0-9]+$ ]] || return 1
	kill -0 "$mpid" 2>/dev/null || return 1
	# Ancestry: walk PPid from $$ up to init.
	local cur=$$ ppid
	while [[ "$cur" -gt 1 ]]; do
		if [[ "$cur" -eq "$mpid" ]]; then
			return 0
		fi
		ppid=$(awk '/^PPid:/ {print $2}' "/proc/${cur}/status" 2>/dev/null || true)
		[[ "$ppid" =~ ^[0-9]+$ ]] || return 1
		cur="$ppid"
	done
	return 1
}

# Print a one-line-per-fact ownership report to stdout. Diagnostics
# only — callers must not gate execution on this output (the single
# fail-closed exception lives in with-cluster.sh's split-mutex
# assertion, which re-derives state itself). Tolerates absent, empty,
# corrupt, and stale owner files.
xpf_cluster_owner_report() {
	local lock_ino
	lock_ino=$(stat -c %d:%i "$XPF_CLUSTER_LOCK" 2>/dev/null || echo "?")
	echo "cluster lock: ${XPF_CLUSTER_LOCK} (dev:ino ${lock_ino})"
	local owner
	owner=$(cat "$XPF_CLUSTER_OWNER" 2>/dev/null || true)
	if [[ -z "$owner" ]]; then
		echo "  no owner metadata (raw-flock holder, or holder predates the owner protocol)"
		fuser -v "$XPF_CLUSTER_LOCK" 2>&1 | sed 's/^/  fuser: /' || true
		return 0
	fi
	local opid otime ouser obranch oino opurpose
	read -r opid otime ouser obranch oino opurpose <<<"$owner" || true
	echo "  held by pid ${opid:-?} (${ouser:-?}) since ${otime:-?}"
	echo "  branch: ${obranch:-?}  lock dev:ino at acquire: ${oino:-?}"
	echo "  purpose: ${opurpose:-?}"
	if [[ "${opid:-}" =~ ^[0-9]+$ ]] && kill -0 "$opid" 2>/dev/null; then
		echo "  holder is ALIVE — wait for it or coordinate; NEVER kill another agent's holder, NEVER rm the lock file"
	else
		echo "  holder pid is DEAD — stale metadata (holder was SIGKILLed?); the flock itself is released on fd close."
		echo "  if the lock still appears held, a child inherited the fd; diagnose with:"
		fuser -v "$XPF_CLUSTER_LOCK" 2>&1 | sed 's/^/  fuser: /' || true
	fi
}

# xpf_cluster_epoch_read — print the #10126 owner-epoch witness from
# the persistent sidecar. The path is absent before the first lock
# cell, which is a valid empty snapshot; once present, a read failure
# is propagated so a gate cannot mistake an unreadable witness for a
# stable empty epoch.
xpf_cluster_epoch_read() {
	if [[ ! -e "$XPF_CLUSTER_EPOCH" ]]; then
		return 0
	fi
	cat "$XPF_CLUSTER_EPOCH" 2>/dev/null
}

# xpf_cluster_owner_identity — print the stable holder identity used
# by the #10126 endpoint comparison. The PID alone is insufficient
# because a later process may recycle it; acquisition timestamp and
# user are included. Invalid/stale/corrupt owner metadata is treated
# as absent — the flock probe remains the fail-fast edge check, while
# the epoch witness covers valid with-cluster cells that begin and end
# idle.
xpf_cluster_owner_identity() {
	local owner pid acquired user
	owner=$(cat "$XPF_CLUSTER_OWNER" 2>/dev/null || true)
	[[ -n "$owner" ]] || return 0
	read -r pid acquired user _ <<<"$owner" || true
	[[ "$pid" =~ ^[0-9]+$ && -n "$acquired" && -n "$user" ]] || return 0
	printf '%s %s %s\n' "$pid" "$acquired" "$user"
}

# xpf_cluster_epoch_bump — publish one unique #10126 owner-epoch
# token. Called by with-cluster.sh once per lock acquire, WHILE
# HOLDING the lock, so concurrent acquires serialize and no token is
# lost; reentrant nested cells perform no acquire and must not bump.
# Release never removes the token, which is what lets an endpoint
# START/END comparison see a full acquire+release cycle (owner CONTENT
# alone cannot: a cell publishes on acquire and removes on exit, so
# absent→absent is invisible without the epoch).
#
# Production's state directory is deliberately NON-STICKY. Atomic
# tmp+mv publication therefore works across cooperating users, unlike
# replacing a file directly in sticky /tmp. A private selftest may use
# a mode-0700 temp parent. Any state setup/publication failure is
# fatal to acquisition: the destructive command must not run without
# a witness, or the #10126 hole returns.
xpf_cluster_epoch_bump() {
	local epoch_dir epoch_dir_mode tmp token
	if [[ "$XPF_CLUSTER_EPOCH" == "$XPF_CLUSTER_LOCK" ]]; then
		echo "warning: xpf_cluster_epoch_bump: epoch sidecar must not replace the lock inode — refusing lock cell (#10126)" >&2
		return 1
	fi
	epoch_dir="${XPF_CLUSTER_EPOCH%/*}"
	[[ "$epoch_dir" == "$XPF_CLUSTER_EPOCH" ]] && epoch_dir="."
	if [[ ! -d "$epoch_dir" ]]; then
		if ! ( umask 000; mkdir -p "$epoch_dir" ) 2>/dev/null; then
			echo "warning: xpf_cluster_epoch_bump: cannot create state directory ${epoch_dir} — refusing lock cell (#10126)" >&2
			return 1
		fi
	fi
	# Only the shared production directory is normalized; never weaken
	# a caller's private temp-tree permissions. A cooperating user that
	# already finds mode 0777 must not chmod a directory it does not own:
	# stat first, chmod only when the mode differs, then verify 0777.
	if [[ "$epoch_dir" == "$XPF_CLUSTER_EPOCH_STATE_DIR" ]]; then
		epoch_dir_mode="$(stat -c %a "$epoch_dir" 2>/dev/null || true)"
		if [[ "$epoch_dir_mode" != 777 ]]; then
			if ! chmod 0777 "$epoch_dir" 2>/dev/null; then
				echo "warning: xpf_cluster_epoch_bump: cannot make production state directory ${epoch_dir} non-sticky and cross-user writable — refusing lock cell (#10126)" >&2
				return 1
			fi
		fi
		if [[ "$(stat -c %a "$epoch_dir" 2>/dev/null || true)" != 777 ]]; then
			echo "warning: xpf_cluster_epoch_bump: production state directory ${epoch_dir} is not mode 0777 — refusing lock cell (#10126)" >&2
			return 1
		fi
	fi
	if [[ ! -w "$epoch_dir" ]]; then
		echo "warning: xpf_cluster_epoch_bump: state directory ${epoch_dir} is not writable — refusing lock cell (#10126)" >&2
		return 1
	fi
	if [[ -d "$XPF_CLUSTER_EPOCH" ]]; then
		echo "warning: xpf_cluster_epoch_bump: epoch sidecar path ${XPF_CLUSTER_EPOCH} is a directory — refusing lock cell (#10126)" >&2
		return 1
	fi
	token="$(date +%s%N 2>/dev/null || date +%s)-$$-${RANDOM:-0}"
	tmp=$(mktemp "${XPF_CLUSTER_EPOCH}.XXXXXX" 2>/dev/null) || {
		echo "warning: xpf_cluster_epoch_bump: cannot create temporary epoch in ${epoch_dir} — refusing lock cell (#10126)" >&2
		return 1
	}
	if ! printf '%s\n' "$token" >"$tmp" 2>/dev/null; then
		echo "warning: xpf_cluster_epoch_bump: cannot write temporary epoch in ${epoch_dir} — refusing lock cell (#10126)" >&2
		rm -f "$tmp" 2>/dev/null || true
		return 1
	fi
	if ! chmod 0666 "$tmp" 2>/dev/null; then
		echo "warning: xpf_cluster_epoch_bump: cannot make temporary epoch cross-user readable in ${epoch_dir} — refusing lock cell (#10126)" >&2
		rm -f "$tmp" 2>/dev/null || true
		return 1
	fi
	if [[ "$(stat -c %a "$tmp" 2>/dev/null || true)" != 666 ]]; then
		echo "warning: xpf_cluster_epoch_bump: temporary epoch is not mode 0666 in ${epoch_dir} — refusing lock cell (#10126)" >&2
		rm -f "$tmp" 2>/dev/null || true
		return 1
	fi
	if ! mv -fT "$tmp" "$XPF_CLUSTER_EPOCH" 2>/dev/null; then
		echo "warning: xpf_cluster_epoch_bump: cannot publish ${XPF_CLUSTER_EPOCH} — refusing lock cell (#10126)" >&2
		rm -f "$tmp" 2>/dev/null || true
		return 1
	fi
	return 0
}
