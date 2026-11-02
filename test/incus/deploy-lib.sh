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
# #18544: deploy_reconcile_unit_shadows is the one DEB-path reconcile. It runs
# after the deb install and before the controlled cut. It removes the
# raw-deploy /etc copies of xpfd.service and the two boot-barrier units, which
# would otherwise shadow the packaged units.
#
# All functions take a FULLY-RESOLVED instance name (e.g. "loss:xpf-userspace-fw0"
# or "xpf-fw") because the two callers compute that differently (cluster-setup.sh
# r() remote prefix vs setup.sh INSTANCE_NAME). They depend on info()/warn()/die()
# being defined by the sourcing script (both define them identically).

# deploy_managed_bins is the push set: the binaries the raw deploy paths
# push into /usr/local/sbin. It is deliberately manifest.Names() minus
# xpf-day0-config, which raw deploy never pushes (it ships only inside
# the .deb) — this is an intentional subset, pinned by
# TestManagedBinaryDriftCanary (#17101), not a stale copy of the SSOT.
deploy_managed_bins=(xpfd cli xpf-userspace-dp)

# Resolve the LAN target for liveness priming using the same remote-qualified
# ref rules as cluster-env.sh. An explicit CLUSTER_LAN_HOST override wins;
# otherwise the cluster env's LAN_HOST supplies the name.
deploy_lan_host_ref() {
	local host="${CLUSTER_LAN_HOST:-${LAN_HOST:-}}"
	[[ -n "$host" ]] || return 1
	if [[ -n "${INCUS_REMOTE:-}" && "$host" != *:* ]]; then
		host="${INCUS_REMOTE}:${host}"
	fi
	printf '%s\n' "$host"
}

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

# ── Raw-deploy unit shadows on the deb path (#18544) ─────────────────
# The raw deploy paths (cluster-setup.sh deploy_vm, setup.sh cmd_deploy) push
# test/incus/xpfd.service and the two boot barriers
# (scripts/image/xpf-{transit,input}-closed.service) into /etc/systemd/system.
# The .deb ships its OWN copy of all three under /usr/lib/systemd/system
# (debian/rules stages the same sources; xpfd.service also gains an
# ExecStartPre verify-dataplane line). systemd prefers /etc, so on a node that
# was raw-deployed even once, those copies SHADOW the packaged units through
# every later deb deploy, however old they are. Measured 2026-10-30:
# - the loss and tcp nodes ran xpfd with KillMode=control-group under debs
#   that ship KillMode=mixed (#18213), so systemd SIGTERMed the helper
#   alongside xpfd, and xpfd's orderly shutdown could not clear rg_active
#   (#18540);
# - loss fw0's barrier copies were older than the packaged barriers.
# The #1917 drop-in still pins xpfd's ExecStart/ExecStartPre; every other
# setting came from the /etc copy.
#
# A production install has no /etc copies. The deb path therefore removes
# them, so the units shipped in the deb being deployed govern. It does not
# re-sync them from the worktree: that would pair one tree's units with
# binaries from a deb that may come from another tree (XPF_DEPLOY_DEB_PATH).
# A later raw deploy pushes them again, which is that path's contract.
deploy_shadowed_units=(xpfd.service xpf-transit-closed.service xpf-input-closed.service)
DEPLOY_UNIT_ETC_DIR="/etc/systemd/system"
# Where dh_installsystemd installs a packaged unit. On merged-/usr both
# directories hold the same file. The loaded unit must be in one of them.
deploy_packaged_unit_dirs=(/usr/lib/systemd/system /lib/systemd/system)
# A removed /etc copy is parked here until the loaded unit has been verified,
# so a failed verification can put it back. It is on persistent storage, so a
# reboot between the move and the check cannot lose it (a /run stash could),
# and it is outside every systemd unit search path.
DEPLOY_UNIT_SHADOW_STASH="/var/lib/xpf-deploy-unit-shadow"
# The units the deploy cannot do without. Their reconcile HARD FAILS when the
# deb ships no packaged copy. Every other unit in deploy_shadowed_units is
# skipped with a warning in that case: a deb pinned through
# XPF_DEPLOY_DEB_PATH may predate the boot barriers (#9852, #10751), and its
# raw-pushed /etc copies are then the only ones there are.
deploy_required_units=(xpfd.service)

# deploy_unit_path_is_packaged <unit> <path>: rc 0 iff <path> is the unit's
# file in one of deploy_packaged_unit_dirs.
deploy_unit_path_is_packaged() {
	local d
	for d in "${deploy_packaged_unit_dirs[@]}"; do
		[[ "$2" == "$d/$1" ]] && return 0
	done
	return 1
}

# deploy_reconcile_unit_shadow <rinst> <unit>
#
# Make the packaged <unit> the one systemd has LOADED. The steps:
# 0. With no packaged copy on disk, skip a unit that is not in
#    deploy_required_units (warn, return 0). The deployed deb predates it.
#    A copy parked by an interrupted earlier run is put back first, into a
#    free /etc path only, since it is then the unit's only copy.
# 1. Park a regular-file /etc/systemd/system/<unit> in the stash. Refuse
#    (HARD FAIL, file kept) when a REQUIRED unit has no packaged copy.
# 2. Run daemon-reload, also when the file is already gone but systemd still
#    has it loaded.
# 3. ASSERT the result positively: LoadState=loaded, and FragmentPath is the
#    unit's file in a packaged dir. A unit that the /etc copy used to outrank
#    (/run/systemd/system, /usr/local/lib/systemd/system, a runtime mask) or
#    one systemd rejects fails the check. Any parked copy then goes back,
#    whether this run parked it or an earlier interrupted run did, as long
#    as the /etc path is free. systemd reloads, and the deploy dies. The
#    error names the parked copy, and says whether the reload worked.
# 4. Only then drop the stash, and re-point every install link
#    (/etc/systemd/system/*/<unit>, i.e. the WantedBy=/RequiredBy= .wants and
#    .requires links) that still targets the removed file. systemd adds those
#    dependencies by link NAME, so enablement and RequiredBy= hold either way;
#    re-pointing makes the links match a package install.
#
# A symlink at the /etc path is never removed, because this deploy did not
# write it:
# - a link to /dev/null is a mask (xpf-deploy.py's #7559 daemon hold). It
#   governs deliberately, so the deploy leaves it alone, warns, and returns 0;
# - any other link is an alias. It is not removed, and step 3 decides: an
#   alias that systemd does not resolve to the packaged file fails the
#   deploy.
#
# The function never starts, stops or restarts a unit. daemon-reload only
# replaces what is loaded, and the new settings first apply at the unit's next
# stop/start (for xpfd, the controlled cut; for the boot barriers, the next
# boot). A second run changes nothing.
deploy_reconcile_unit_shadow() {
	local rinst="$1" unit="$2"
	local shadow="$DEPLOY_UNIT_ETC_DIR/$unit" stash="$DEPLOY_UNIT_SHADOW_STASH/$unit"
	local removed=0 have_packaged=0 required=0 d target frag state reason links l

	for d in "${deploy_packaged_unit_dirs[@]}"; do
		if incus exec "$rinst" -- test -f "$d/$unit" 2>/dev/null; then
			have_packaged=1
			break
		fi
	done
	for d in "${deploy_required_units[@]}"; do
		[[ "$d" == "$unit" ]] && required=1
	done
	if (( ! have_packaged && ! required )); then
		# The raw-pushed copy is then the only copy of this unit. If an
		# interrupted earlier run parked it, put it back (into a free /etc
		# path only), or this node boots without the unit while its install
		# links still name it.
		if incus exec "$rinst" -- test -f "$stash" 2>/dev/null; then
			if incus exec "$rinst" -- test -e "$shadow" 2>/dev/null ||
				incus exec "$rinst" -- test -L "$shadow" 2>/dev/null; then
				warn "No packaged $unit under ${deploy_packaged_unit_dirs[*]} on $rinst: the deployed deb predates it. A parked copy is at $stash, but $shadow is occupied, so it was NOT restored; inspect both by hand (#18544)."
				return 0
			fi
			incus exec "$rinst" -- mv -f "$stash" "$shadow" 2>/dev/null \
				|| die "no packaged $unit on $rinst and failed to put the parked $stash back at $shadow; restore it by hand, or the node boots without $unit"
			if incus exec "$rinst" -- systemctl daemon-reload 2>/dev/null; then
				warn "No packaged $unit under ${deploy_packaged_unit_dirs[*]} on $rinst: the deployed deb predates it. Put the parked $stash back at $shadow and reloaded (#18544)."
			else
				warn "No packaged $unit under ${deploy_packaged_unit_dirs[*]} on $rinst: the deployed deb predates it. Put the parked $stash back at $shadow, but daemon-reload FAILED; it loads at the next boot or reload (#18544)."
			fi
			return 0
		fi
		warn "No packaged $unit under ${deploy_packaged_unit_dirs[*]} on $rinst: the deployed deb predates it. Leaving $shadow as it is (#18544)."
		return 0
	fi

	if incus exec "$rinst" -- test -L "$shadow" 2>/dev/null; then
		target=$(incus exec "$rinst" -- readlink "$shadow" 2>/dev/null || true)
		if [[ "$target" == /dev/null ]]; then
			warn "$shadow on $rinst is masked (-> /dev/null): a deliberate hold, not a raw-deploy copy. Leaving it; the mask, not the packaged unit, governs $unit."
			return 0
		fi
		warn "$shadow on $rinst is a symlink to '${target:-?}', not a raw-deploy copy. Not removing it; checking that systemd resolves $unit to the packaged file."
	elif incus exec "$rinst" -- test -f "$shadow" 2>/dev/null; then
		if (( ! have_packaged )); then
			die "refusing to remove $shadow on $rinst: no packaged $unit under ${deploy_packaged_unit_dirs[*]} to fall back to; is the xpf deb installed?"
		fi
		warn "Removing stale raw-deploy unit $shadow on $rinst: it shadows the packaged $unit, so unit changes shipped in the deb never took effect here (#18544)."
		incus exec "$rinst" -- mkdir -p "$DEPLOY_UNIT_SHADOW_STASH" 2>/dev/null \
			|| die "failed to create $DEPLOY_UNIT_SHADOW_STASH on $rinst"
		incus exec "$rinst" -- mv -f "$shadow" "$stash" 2>/dev/null \
			|| die "failed to move $shadow aside on $rinst"
		removed=1
	fi

	# Reload after changing the disk, AND whenever systemd still has the /etc
	# copy LOADED: an earlier removal whose daemon-reload never ran leaves no
	# file to find, but the stale unit still governs the next stop.
	frag=$(incus exec "$rinst" -- systemctl show -p FragmentPath --value "$unit" 2>/dev/null || true)
	if (( removed )) || [[ "$frag" == "$shadow" ]]; then
		incus exec "$rinst" -- systemctl daemon-reload \
			|| die "systemctl daemon-reload failed on $rinst after reconciling $shadow"
		frag=$(incus exec "$rinst" -- systemctl show -p FragmentPath --value "$unit" 2>/dev/null || true)
	fi
	state=$(incus exec "$rinst" -- systemctl show -p LoadState --value "$unit" 2>/dev/null || true)

	# Verify the LOADED unit, positively. What governs the next stop is what
	# systemd loaded, and neither "the rm succeeded" nor "it is not the /etc
	# path" says that is the packaged file.
	reason=""
	if [[ "$state" != loaded ]]; then
		reason="$unit on $rinst has LoadState='${state:-unknown}' (FragmentPath='${frag}'), not loaded"
	elif ! deploy_unit_path_is_packaged "$unit" "$frag"; then
		reason="$unit on $rinst loads '${frag:-nothing}', not the packaged file under ${deploy_packaged_unit_dirs[*]} (#18544)"
	fi
	if [[ -n "$reason" ]]; then
		# Restore ANY parked copy, not only one this run made: an earlier run
		# interrupted after its move leaves one behind, and it is the last
		# unit that governed before the deploy. Restore it only into a free
		# /etc path; an occupied one (an alias, or a copy that never moved)
		# is never overwritten.
		if incus exec "$rinst" -- test -f "$stash" 2>/dev/null; then
			if incus exec "$rinst" -- test -e "$shadow" 2>/dev/null ||
				incus exec "$rinst" -- test -L "$shadow" 2>/dev/null; then
				die "$reason; a parked copy is at $stash on $rinst, but $shadow is occupied, so it was NOT restored. Inspect both by hand"
			fi
			incus exec "$rinst" -- mv -f "$stash" "$shadow" 2>/dev/null \
				|| die "$reason; ALSO failed to put $shadow back from $stash on $rinst; restore it by hand"
			if incus exec "$rinst" -- systemctl daemon-reload 2>/dev/null; then
				die "$reason; put the parked $stash back at $shadow and reloaded, so $rinst is as it was before the deploy"
			fi
			die "$reason; put the parked $stash back at $shadow, but daemon-reload FAILED, so systemd on $rinst may still have '$frag' loaded. Run systemctl daemon-reload there"
		fi
		die "$reason"
	fi

	# Verified. The parked copy is no longer needed (this also clears a stash
	# left by an interrupted earlier run).
	incus exec "$rinst" -- rm -rf "$stash" 2>/dev/null || true

	links=$(incus exec "$rinst" -- find "$DEPLOY_UNIT_ETC_DIR" -mindepth 2 -maxdepth 2 -type l -name "$unit" 2>/dev/null || true)
	for l in $links; do
		if [[ "$(incus exec "$rinst" -- readlink "$l" 2>/dev/null || true)" == "$shadow" ]]; then
			incus exec "$rinst" -- ln -sfn "$frag" "$l" \
				|| die "failed to re-point $l at $frag on $rinst"
		fi
	done
	info "$unit on $rinst loads the packaged unit ($frag)."
}

# deploy_reconcile_unit_shadows <rinst>: deploy_reconcile_unit_shadow for
# every unit the raw deploy pushes into /etc and the deb also ships.
deploy_reconcile_unit_shadows() {
	local rinst="$1" u
	for u in "${deploy_shadowed_units[@]}"; do
		deploy_reconcile_unit_shadow "$rinst" "$u"
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
# deploy_verify_pushed_uid <rinst> <remote_path> <label>
#
# Assert the on-VM binary is root-owned. xpfd's validated-binary trust
# check (#17881) refuses to execute a helper owned by a non-root uid,
# and a raw `incus file push` preserves the workstation owner's uid
# unless the push pins --uid 0 --gid 0 (#18029): the pushed file lands
# uid-1000-owned and the helper can never start. HARD FAIL on a
# non-root uid or an empty readback, same as deploy_verify_pushed_sha.
# `-L` matches sha256sum's target semantics: managed binaries may remain valid
# symlinks, and their link-owner metadata does not describe the executable.
deploy_verify_pushed_uid() {
	local rinst="$1" remote_path="$2" label="$3"
	local vm_uid
	vm_uid=$(incus exec "$rinst" -- stat -L -c %u "$remote_path" 2>/dev/null || true)
	if [[ -z "$vm_uid" ]]; then
		die "$label not present on $rinst after push (uid readback empty: $remote_path)"
	fi
	if [[ "$vm_uid" != "0" ]]; then
		die "$label owned by uid $vm_uid on $rinst after push, not root (0) — xpfd refuses a non-root-owned helper (#17881/#18029); push with --uid 0 --gid 0"
	fi
	info "Verified $label uid 0 (root) on $rinst."
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

# deploy_running_xpf_userspace_dp_sha256 <rinst> [tries]
#
# Read back the sha256 of the LIVE xpf-userspace-dp process image on <rinst>.
# The helper is a child of xpfd rather than its own systemd unit, so pidof
# selects the helper process and /proc/<pid>/exe remains the authority on what
# is executing. Exactly one helper PID is required: multiple matching helpers
# make the image identity ambiguous and therefore fail closed. Empty output
# with rc 1 means the helper was not running or the readback failed; callers
# must not substitute the on-disk path's hash.
deploy_running_xpf_userspace_dp_sha256() {
	local rinst="${1:-}" tries_max="${2:-15}"
	[[ -n "$rinst" ]] || return 1
	local tries=0 run_raw="" run_sum=""
	while [[ $tries -lt $tries_max ]]; do
		run_raw=$(incus exec "$rinst" -- bash -c '
			pids=$(pidof xpf-userspace-dp 2>/dev/null)
			set -- $pids
			[ "$#" -eq 1 ] || exit 1
			sha256sum "/proc/$1/exe" 2>/dev/null || exit 1
		' 2>/dev/null || true)
		run_sum=${run_raw%% *}
		[[ -n "$run_sum" ]] && break
		tries=$((tries + 1))
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

# deploy_verify_running_xpf_userspace_dp <rinst> <local_helper_path>
#
# After xpfd restarts, assert that the helper process image is the helper
# binary just pushed. Unlike xpfd, the helper is not a systemd unit; the
# process-image readback is the only authoritative identity check.
deploy_verify_running_xpf_userspace_dp() {
	local rinst="$1" local_helper="$2"
	local local_sum
	local_sum=$(sha256sum "$local_helper" | awk '{print $1}')
	local run_sum=""
	run_sum=$(deploy_running_xpf_userspace_dp_sha256 "$rinst" || true)
	if [[ -z "$run_sum" ]]; then
		die "xpf-userspace-dp is not running on $rinst after deploy — cannot verify the helper binary"
	fi
	if [[ "$run_sum" != "$local_sum" ]]; then
		die "running xpf-userspace-dp on $rinst (sha256=$run_sum) does not match the pushed build (sha256=$local_sum) — the node is running STALE helper code"
	fi
	info "Verified running xpf-userspace-dp on $rinst matches the pushed build ($local_sum)."
}
# ── Deploy attestation manifest (#11765, refused-deploy record #16290) ──
# The gate used to hash the worktree's CURRENT ./xpfd and compare it with
# the LIVE process image. Any rebuild between deploy and gate — even of the
# same commit — differs, because two stamped LDFLAGS are never stable:
# main.buildTime (Makefile date-now, second granularity) and main.version
# (the -dirty flag a clean-tree rebuild does not reproduce). Every HA gate
# therefore recorded VOID via exe_check=MISMATCH for a binary nobody
# rebuilt wrong; the comparison attested build REPRODUCIBILITY, which the
# toolchain cannot provide, instead of deployment IDENTITY, which the
# deploy path knows exactly.
#
# So the deploy path records what it SHIPPED, and the gate compares the
# running image against that record instead of against a fresh rebuild.
# The manifest is local, git-ignored, and bound to the checkout identity.
# A single-node deploy invalidates only its target slot before binary changes;
# an all-node deploy invalidates the whole manifest. Successful writes replace
# the affected slot(s) atomically and preserve a successfully deployed peer.
# Missing, invalid, or stale provenance fails closed.
#
# #16290: invalidation runs BEFORE the deploy body, but the new manifest is
# written only AFTER it succeeds. A refused cut (e.g. `xpfd upgrade
# --rolling` refuse-before-PREFLIGHT on a re-staged version tag) aborts
# under `set -e` before the write, leaving NO manifest at all. The nodes
# still run the previous build, yet every later gate recorded a bare
# VOID/exe_check=UNAVAILABLE with no pointer to the refusal. So a failed
# deploy now drops a sidecar marker next to the (absent) manifest naming
# the target and reason; the gate surfaces it in the VOID reason. The
# marker never attests binaries and never revives stale provenance: the
# manifest itself stays absent/invalidated (fail-closed), and a later
# successful deploy_write_manifest clears the marker atomically with
# the new record. A partially-cut rolling deploy likewise leaves the
# marker — completed nodes re-attest only on overall deploy success.
#
# Schema: schema=2, nodes {"0": <deploy record>, "1": <deploy record>}.
# Each record carries build_git_sha (HEAD + -dirty, ledger-excluded, cf.
# harness_build_git_sha), version, build_time, mode, deb, and binaries. Slots
# are independently replaced so a rolling rebuild cannot erase its peer.
# deploy_manifest_path [project_root]
# Echo the manifest path. XPF_DEPLOY_MANIFEST overrides (selftests point it
# at a fixture); otherwise <root>/dist-deb/xpf-deploy-manifest.json.
deploy_manifest_path() {
	if [[ -n "${XPF_DEPLOY_MANIFEST:-}" ]]; then
		printf '%s\n' "$XPF_DEPLOY_MANIFEST"
		return 0
	fi
	local root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
	printf '%s/dist-deb/xpf-deploy-manifest.json\n' "$root"
}

# deploy_manifest_invalidate <project_root> [0|1|all]
# A failed or partial deploy must not leave the previous successful artifact
# available to a later gate. A single-node attempt clears only that node's slot
# so a successfully deployed peer remains attestable.

# deploy_manifest_failure_path [project_root]
# Echo the refused/failed-deploy marker path: the manifest path with a
# .failed suffix, so XPF_DEPLOY_MANIFEST fixtures isolate it automatically.
deploy_manifest_failure_path() {
	local manifest
	manifest=$(deploy_manifest_path "${1:-}") || return 1
	printf '%s.failed\n' "$manifest"
}

# deploy_manifest_record_failure <project_root> <0|1|all> <reason>
# Record WHY the last deploy left no (or partial) attestation, so a later
# gate's VOID names the refused deploy instead of a bare
# exe_check=UNAVAILABLE (#16290). The reason is flattened to one line and
# bounded; the marker is a plain key=value file (no JSON parser needed on
# the read side). It is NOT provenance: it carries no binary identity and
# deploy_manifest_sha never reads it.
deploy_manifest_record_failure() {
	local root="$1" scope="${2:-all}" reason="${3:-deploy failed}"
	local marker flat
	[[ "$scope" == 0 || "$scope" == 1 || "$scope" == all ]] || return 1
	marker=$(deploy_manifest_failure_path "$root") || return 1
	flat=$(printf '%s' "$reason" | tr '\r\n\t' '   ' | tr -s ' ')
	flat="${flat:0:300}"
	[[ -n "$flat" ]] || flat="deploy failed"
	mkdir -p "$(dirname "$marker")" || return 1
	local tmp="$marker.tmp.$$"
	{
		printf 'target=%s\n' "$scope"
		printf 'failed_at=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
		printf 'reason=%s\n' "$flat"
	} >"$tmp" || { rm -f "$tmp"; return 1; }
	mv -f "$tmp" "$marker" || { rm -f "$tmp"; return 1; }
}

# deploy_manifest_failure_reason <project_root>
# Echo "deploy <target> failed: <reason>" from the marker, or nothing
# (rc 1) when no failed deploy is recorded. Gates append this to the
# exe_check=UNAVAILABLE VOID reason.
deploy_manifest_failure_reason() {
	local marker target="" reason=""
	marker=$(deploy_manifest_failure_path "$1") || return 1
	[[ -f "$marker" ]] || return 1
	local key value
	while IFS='=' read -r key value; do
		case "$key" in
			target) target="$value" ;;
			reason) reason="$value" ;;
		esac
	done <"$marker"
	[[ -n "$reason" ]] || return 1
	case "$target" in 0|1|all) ;; *) target="all" ;; esac
	printf 'deploy %s failed: %s\n' "$target" "$reason"
}

# deploy_manifest_clear_failure [project_root]
# Drop the failed-deploy marker. Called by deploy_write_manifest after a
# successful attestation write and by deploy_manifest_invalidate before a
# new attempt, so a stale refusal never outlives the state it described.
deploy_manifest_clear_failure() {
	local marker
	marker=$(deploy_manifest_failure_path "${1:-}") || return 1
	rm -f -- "$marker"
}

# deploy_exit_guard_on_exit <status>: restore a lab-downgrade floor before
# recording the failed deploy. The same handler serves direct deploy_vm_deb
# calls (floor-only) and cmd_deploy (floor + attestation), with state held in
# globals because EXIT runs after function locals are gone.
deploy_exit_guard_on_exit() {
	local rc="$1"
	if (( ${_deploy_floor_guard_pending:-0} )); then
		if ! deploy_binary_floor_guard_restore_on_exit; then
			warn "deploy floor guard: could not restore the saved binary floor; it remains at ${DEPLOY_BINARY_FLOOR_SAVED} on ${_deploy_floor_guard_rinst:-unknown}"
			((rc != 0)) || rc=1
		fi
	fi
	if (( ${_deploy_guard_pending:-0} )); then
		deploy_manifest_record_failure "$_deploy_guard_root" "$_deploy_guard_target" "attestation manifest absent because deploy ${_deploy_guard_step} failed (rc=${rc}); no new build was attested" || true
		warn "deploy attestation: manifest absent because deploy ${_deploy_guard_step} failed (rc=${rc}); later gates will VOID naming this deploy (#16290)"
	fi
	trap - EXIT
	exit "$rc"
}

deploy_exit_guard_install() {
	trap 'deploy_exit_guard_on_exit "$?"' EXIT
}

# deploy_manifest_arm_failure_guard <project_root> <0|1|all>
# Arm the EXIT-trap guard cmd_deploy installs right after invalidation
# (#16290). ALL guard state lives in globals: the EXIT trap fires after
# the arming function has returned and its locals are gone, so a trap
# referencing a function-local target/step would die unbound under
# `set -u` and record nothing (the Opus fold on PR #16338). The target
# in particular is captured into the global _deploy_guard_target here —
# a caller's `local target` is exactly what must not be trapped over.
# The hermetic selftest drives the REAL trap (arm, abort a subshell,
# observe the marker) instead of hand-calling the recorder.
deploy_manifest_arm_failure_guard() {
	local root="$1" scope="${2:-all}"
	[[ "$scope" == 0 || "$scope" == 1 || "$scope" == all ]] || return 1
	# Globals on purpose — do NOT declare these local (see above).
	_deploy_guard_root="$root"
	_deploy_guard_target="$scope"
	_deploy_guard_step="deploy dispatch"
	_deploy_guard_rc=0
	_deploy_guard_pending=1
	deploy_exit_guard_install
}

# deploy_manifest_guard_step <step label>
# Label the deploy step the guard will name if the shell aborts now.
deploy_manifest_guard_step() {
	_deploy_guard_step="$1"
}

# deploy_manifest_guard_disarm
# Explicit die paths record their own specific reason and then disarm,
# so the EXIT backstop cannot overwrite it with the generic step text.
# The success path disarms too, then the caller removes the trap.
deploy_manifest_guard_disarm() {
	_deploy_guard_pending=0
}

# deploy_manifest_invalidate <project_root> [0|1|all]
#


deploy_manifest_invalidate() {
	local manifest scope="${2:-all}"
	manifest=$(deploy_manifest_path "$1") || return 1
	# A new attempt supersedes any recorded failure of the previous one;
	# the attempt's own outcome re-records or (on success) stays clear.
	deploy_manifest_clear_failure "$1" || return 1
	case "$scope" in
	all)
		rm -f -- "$manifest" || return 1
		[[ ! -e "$manifest" ]]
		return
		;;
	0|1) ;;
	*) warn "deploy manifest: invalid node scope '$scope'"; return 1 ;;
	esac
	[[ -e "$manifest" ]] || return 0
	MANIFEST_PATH="$manifest" MANIFEST_NODE="$scope" python3 - <<'PY'
import json, os
path = os.environ["MANIFEST_PATH"]
try:
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
except (OSError, json.JSONDecodeError):
    os.unlink(path)
    raise SystemExit(0)
if not isinstance(doc, dict) or doc.get("schema") != 2 or not isinstance(doc.get("nodes"), dict):
    os.unlink(path)
    raise SystemExit(0)
doc["nodes"].pop(os.environ["MANIFEST_NODE"], None)
if not doc["nodes"]:
    os.unlink(path)
    raise SystemExit(0)
tmp = path + ".tmp." + str(os.getpid())
try:
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, separators=(",", ":"), ensure_ascii=False)
        f.write("\n")
    os.replace(tmp, path)
finally:
    if os.path.exists(tmp):
        os.unlink(tmp)
PY
}

# deploy_manifest_node_index <node> [fw0_instance] [fw1_instance]
# Map configured instances or conventional fw0/fw1 names (including remote
# prefixes) to stable slots. An unfamiliar identifier is not guessed.
deploy_manifest_node_index() {
	local node="${1:-}" fw0="${2:-}" fw1="${3:-}" short
	if [[ -n "$fw0" && "$node" == "$fw0" ]]; then
		printf '0\n'
	elif [[ -n "$fw1" && "$node" == "$fw1" ]]; then
		printf '1\n'
	else
		short="${node##*:}"
		if [[ "$short" =~ (fw|node)([01])$ ]]; then
			printf '%s\n' "${BASH_REMATCH[2]}"
		else
			return 2
		fi
	fi
}


# deploy_build_git_sha [root]
# Match harness_build_git_sha exactly: the ledger is excluded from the
# dirtiness test because previous rows are outputs, not build inputs.
deploy_build_git_sha() {
	local root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
	local sha dirt
	sha=$(git -C "$root" rev-parse HEAD 2>/dev/null) || return 1
	dirt=$(git -C "$root" status --porcelain -uall 2>/dev/null |
		grep -vE 'test/results/ledger\.(d/.*\.json|jsonl)$' || true)
	if [[ -n "$dirt" ]]; then
		printf '%s-dirty\n' "$sha"
	else
		printf '%s\n' "$sha"
	fi
}

# deploy_gate_wave <project_root> <gate> <make_command> <deploy_command...>
# Fence the deploy/gate interval against checkout changes. The cluster lock
# serializes cluster mutations, but does not lock Git operations.
deploy_gate_wave() {
	local root="$1" gate="$2" make_cmd="$3"
	local deployed_sha current_sha
	shift 3
	local -a deploy_command=("$@")
	[[ -n "$gate" && ${#deploy_command[@]} -gt 0 ]] || return 2
	deployed_sha=$(deploy_build_git_sha "$root") || return 1
	"${deploy_command[@]}" || return $?
	current_sha=$(deploy_build_git_sha "$root") || return 1
	if [[ "$current_sha" != "$deployed_sha" ]]; then
		printf 'deploy/gate wave: checkout changed during deploy; refusing gate\n' >&2
		return 1
	fi
	"$make_cmd" "$gate" || return $?
}

# deploy_manifest_sha_from_deb <deb> <binary>
# Echo the sha256 of usr/local/share/xpf/staged/<binary> as packed in the
# .deb (the exact bits deploy_install_deb pushes), or nothing (rc 1) when
# the member is absent or unreadable. Never substitutes a worktree hash.
deploy_manifest_sha_from_deb() {
	local deb="$1" bin="$2" sha=""
	[[ -f "$deb" ]] || return 1
	if ! sha=$(set -o pipefail
		dpkg-deb --fsys-tarfile "$deb" 2>/dev/null |
			tar -xO "./usr/local/share/xpf/staged/$bin" 2>/dev/null |
			sha256sum 2>/dev/null | awk '{print $1}'); then
		return 1
	fi
	[[ "$sha" =~ ^[0-9a-f]{64}$ ]] || return 1
	printf '%s\n' "$sha"
}

# deploy_write_manifest <project_root> [deb_path] [build_git_sha] <0|1|all>
# Record the shas this deploy SHIPPED. With a .deb path (the default dogfood
# path) the shas come from the staged members inside the .deb itself, so a
# worktree rebuild between `make deb` and cut-over cannot record the wrong
# bytes; without one (XPF_DEPLOY_FAST raw path) they come from the worktree
# binaries the raw path just pushed and verified. build_git_sha is captured
# before deployment so a checkout change during cut-over cannot relabel it.
# A write failure is fatal to the deploy.
deploy_write_manifest() {
	local root="$1" deb="${2:-}" expected_git_sha="${3:-}" scope="${4:-}"
	local manifest xpfd_sha="" cli_sha="" helper_sha=""
	local build_git_sha version build_time mode deb_name="" deb_version=""
	[[ "$scope" == 0 || "$scope" == 1 || "$scope" == all ]] || {
		warn "deploy manifest: node scope must be 0, 1, or all"
		return 1
	}
	manifest=$(deploy_manifest_path "$root")
	if [[ -n "$deb" ]]; then
		mode="deb"
		deb_name=$(basename "$deb")
		# #18772: the deployed package version, from the deb itself. `version`
		# below describes the deploying checkout; in an A/B cell that deploys
		# another checkout's deb, or a deliberate downgrade, only this names
		# the build the nodes run.
		if ! deb_version=$(deploy_deb_version "$deb"); then
			warn "deploy manifest: refusing $deb because filename version and package metadata Version disagree or cannot be read"
			return 1
		fi
		xpfd_sha=$(deploy_manifest_sha_from_deb "$deb" xpfd || true)
		cli_sha=$(deploy_manifest_sha_from_deb "$deb" cli || true)
		helper_sha=$(deploy_manifest_sha_from_deb "$deb" xpf-userspace-dp || true)
		[[ -n "$xpfd_sha" ]] || {
			warn "deploy manifest: cannot read staged xpfd from $deb"
			return 1
		}
	else
		mode="raw"
		[[ -f "$root/xpfd" ]] && xpfd_sha=$(sha256sum "$root/xpfd" | awk '{print $1}')
		[[ -f "$root/cli" ]] && cli_sha=$(sha256sum "$root/cli" | awk '{print $1}')
		[[ -f "$root/xpf-userspace-dp" ]] &&
			helper_sha=$(sha256sum "$root/xpf-userspace-dp" | awk '{print $1}')
	fi
	if [[ ! "$xpfd_sha" =~ ^[0-9a-f]{64}$ ]]; then
		warn "deploy manifest: no xpfd sha available (mode=$mode)"
		return 1
	fi
	build_git_sha="$expected_git_sha"
	if [[ -z "$build_git_sha" ]]; then
		build_git_sha=$(deploy_build_git_sha "$root" 2>/dev/null) || {
			warn "deploy manifest: cannot determine build git identity for $root"
			return 1
		}
	fi
	version=$(git -C "$root" describe --tags --always --dirty 2>/dev/null || echo "dev")
	build_time=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
	command -v python3 >/dev/null 2>&1 || {
		warn "deploy manifest: python3 is not installed"
		return 1
	}
	mkdir -p "$(dirname "$manifest")" || return 1
	local tmp="$manifest.tmp.$$"
	if ! MANIFEST_PATH="$manifest" MANIFEST_TMP="$tmp" \
		MANIFEST_GITSHA="$build_git_sha" MANIFEST_VERSION="$version" \
		MANIFEST_TIME="$build_time" MANIFEST_MODE="$mode" \
		MANIFEST_DEB="$deb_name" MANIFEST_DEB_VERSION="$deb_version" MANIFEST_XPFD="$xpfd_sha" \
		MANIFEST_CLI="$cli_sha" MANIFEST_HELPER="$helper_sha" \
		MANIFEST_SCOPE="$scope" \
		python3 - <<'PY'
import json, os
def opt(name):
    v = os.environ.get(name, "")
    return v if v else None
entry = {
    "build_git_sha": os.environ["MANIFEST_GITSHA"],
    "version": os.environ["MANIFEST_VERSION"],
    "build_time": os.environ["MANIFEST_TIME"],
    "mode": os.environ["MANIFEST_MODE"],
    "deb": opt("MANIFEST_DEB"),
    "deb_version": opt("MANIFEST_DEB_VERSION"),
    "binaries": {
        "xpfd": os.environ["MANIFEST_XPFD"],
        "cli": opt("MANIFEST_CLI"),
        "xpf-userspace-dp": opt("MANIFEST_HELPER"),
    },
}
path = os.environ["MANIFEST_PATH"]
scope = os.environ["MANIFEST_SCOPE"]
nodes = {}
try:
    with open(path, encoding="utf-8") as f:
        old = json.load(f)
    if isinstance(old, dict) and old.get("schema") == 2 and isinstance(old.get("nodes"), dict):
        nodes = old["nodes"]
except (OSError, json.JSONDecodeError):
    pass
for node in ("0", "1") if scope == "all" else (scope,):
    nodes[node] = entry
doc = {"schema": 2, "nodes": nodes}
with open(os.environ["MANIFEST_TMP"], "w", encoding="utf-8") as f:
    json.dump(doc, f, separators=(",", ":"), ensure_ascii=False)
    f.write("\n")
os.replace(os.environ["MANIFEST_TMP"], path)
PY
	then
		rm -f "$tmp"
		warn "deploy manifest: failed to write $manifest"
		return 1
	fi
	# A successful attestation supersedes any recorded refusal (#16290).
	deploy_manifest_clear_failure "$root" || {
		warn "deploy manifest: cannot clear failed-deploy marker for $manifest"
		return 1
	}
	info "Deploy manifest recorded $manifest (nodes=$scope mode=$mode xpfd=$xpfd_sha)."
}

# deploy_manifest_sha <binary> <project_root> [expected_build_git_sha] <0|1>
# Return the selected node's recorded SHA. rc=1 means no manifest or node slot;
# rc=2 means invalid; rc=3 means the record belongs to another checkout.
# Every nonzero status fails closed for a cluster measurement.
# deploy_manifest_deb_version <root> <node>: the deployed package version the
# manifest records for node 0/1, or "" (older manifests have none). #18772.
deploy_manifest_deb_version() {
	local root="$1" node="$2" manifest
	manifest=$(deploy_manifest_path "$root")
	[[ -f "$manifest" ]] || return 1
	python3 -I -c 'import json,sys
d=json.load(open(sys.argv[1], encoding="utf-8"))
v=(d.get("nodes") or {}).get(sys.argv[2], {}).get("deb_version")
print(v if isinstance(v, str) else "")' "$manifest" "$node"
}

deploy_manifest_sha() {
	local bin="$1" root="${2:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
	local expected_git_sha="${3:-}" node="${4:-}" manifest
	[[ "$node" == 0 || "$node" == 1 ]] || return 2
	manifest=$(deploy_manifest_path "$root")
	[[ -f "$manifest" ]] || return 1
	MANIFEST_PATH="$manifest" MANIFEST_BIN="$bin" \
		MANIFEST_NODE="$node" MANIFEST_EXPECTED_GITSHA="$expected_git_sha" python3 - <<'PY'
import json, os, re
try:
    with open(os.environ["MANIFEST_PATH"], encoding="utf-8") as f:
        doc = json.load(f)
except (OSError, json.JSONDecodeError):
    raise SystemExit(2)
if not isinstance(doc, dict) or doc.get("schema") != 2:
    raise SystemExit(2)
nodes = doc.get("nodes")
if not isinstance(nodes, dict):
    raise SystemExit(2)
entry = nodes.get(os.environ["MANIFEST_NODE"])
if entry is None:
    raise SystemExit(1)
if not isinstance(entry, dict):
    raise SystemExit(2)
git_sha = entry.get("build_git_sha")
if not isinstance(git_sha, str) or not git_sha:
    raise SystemExit(2)
expected = os.environ.get("MANIFEST_EXPECTED_GITSHA", "")
if expected and git_sha != expected:
    raise SystemExit(3)
binaries = entry.get("binaries")
if not isinstance(binaries, dict):
    raise SystemExit(2)
sha = binaries.get(os.environ["MANIFEST_BIN"])
if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
    raise SystemExit(2)
print(sha)
PY
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

# deploy_node_rgs_not_role reads `show chassis cluster status` on stdin and
# prints, one per line in ascending order, every redundancy group in which
# <node> does NOT read exactly <role>. A group with no <node> row counts as
# "not". It is the per-RG complement of deploy_node_role_every_rg_ok, scoped
# the same way (the `Redundancy group: N` header, never a substring grep), and
# the post-deploy reassert uses it to re-send only the transfers that have not
# landed (#12658).
deploy_node_rgs_not_role() {
	local node="${1:?deploy_node_rgs_not_role: node required}"
	local role="${2:?deploy_node_rgs_not_role: role required}"
	awk -v node="$node" -v role="$role" '
		/^Redundancy group:[[:space:]]/ { rg = $3; seen[rg] = 1; next }
		$1 == node { if (rg != "" && $3 == role) { ok[rg] = 1 } }
		END { for (g in seen) { if (!(g in ok)) { print g } } }
	' | sort -n
}

# deploy_node_rg_role reads `show chassis cluster status` on stdin and prints
# the exact role ($3) of <node> for redundancy group <rg>. It succeeds ONLY IF
# exactly one <node> row exists inside the `Redundancy group: <rg>` block.
#
# The header match is exact ($3 == rg), never a substring: `grep -A2
# "Redundancy group: 1"` also matches `Redundancy group: 10`, so clusters with
# 10+ RGs miscounted RG1 (#12203 row 21). A grep cannot express "the role of
# THIS node in THIS group", so the dual-active checks in test-chained-crash.sh
# and test-ha-crash.sh read every (node, RG) through this helper and treat a
# missing row as VOID -> FAIL. Empty, whitespace-only, unconfigured
# ("Cluster not configured"), zero-block, missing-block, and duplicate-row
# statuses all fail here instead of passing vacuously.
deploy_node_rg_role() {
	local node="${1:?deploy_node_rg_role: node required}"
	local want="${2:?deploy_node_rg_role: rg required}"
	awk -v node="$node" -v want="$want" '
		/^Redundancy group:[[:space:]]/ { rg = $3; next }
		rg != "" && ("x" rg) == ("x" want) && $1 == node { role = $3; n++ }
		END { if (n != 1 || role == "") exit 1; print role }
	'
}

# deploy_rg_local_forwarding reads `show chassis cluster status` on stdin and
# prints the LOCAL node's `rg-active=` value (active / inactive) for
# redundancy group <rg> (#18523). Each node prints one
# `Forwarding: rg-active=<v> vrrp-master=<v>` line under its own row for every
# RG that has a state machine, in private-RG AND legacy VRRP-backed mode
# (pkg/cluster/status.go FormatStatus, pkg/daemon/rg_forwarding_status_7367.go).
# That line is the dataplane's view, not the node's ownership claim.
#
# When ownership and forwarding disagree, the daemon appends
# ` -- DIVERGENCE: ...` (pkg/cluster/rg_forwarding.go FormatRGForwarding).
#
# Exit status:
#   0  exactly one line in the exact `Redundancy group: <rg>` block, value
#      active or inactive, no suffix; prints the value.
#   2  the same, but the line carries a suffix (any token other than
#      rg-active= / vrrp-master=); prints `<value> -- <suffix>`, so a caller
#      comparing against a bare `active`/`inactive` FAILs and names it.
#   1  missing, duplicated, or not active/inactive; prints nothing.
deploy_rg_local_forwarding() {
	local want="${1:?deploy_rg_local_forwarding: rg required}"
	awk -v want="$want" '
		/^Redundancy group:[[:space:]]/ { rg = $3; next }
		rg != "" && ("x" rg) == ("x" want) && $1 == "Forwarding:" {
			n++
			v = ""
			extra = ""
			for (i = 2; i <= NF; i++) {
				if ($i ~ /^rg-active=/) { v = substr($i, 11) }
				else if ($i !~ /^vrrp-master=/) { extra = extra (extra == "" ? "" : " ") $i }
			}
		}
		END {
			if (n != 1 || (v != "active" && v != "inactive")) exit 1
			if (extra != "") {
				sub(/^--[[:space:]]*/, "", extra)
				print v " -- " extra
				exit 2
			}
			print v
		}
	'
}

# deploy_active_active_split_verdict <fw0-status> <fw1-status> scores the
# test-active-active.sh split: RG1 (WAN) moved to node1 and RG2 (LAN) stayed
# on node0 (#18523). Arguments are each node's own
# `show chassis cluster status`. The caller defines pass() and fail(); this
# records exactly four verdicts and never aborts under `set -euo pipefail`.
#
# Ownership is read from BOTH nodes' own views, the ha_rg_owner_verdict rule
# (#18503). The untargeted yield parks the old owner in `secondary-hold`, so
# a non-owner is `secondary` or `secondary-hold`. fw0's view alone would
# score a dual-primary RG as healthy.
#
# Forwarding is each node's own `Forwarding: rg-active=` line, in both
# election modes: the owner `active`, the peer `inactive`, and no
# DIVERGENCE suffix. A missing line is a FAIL, never a skip.
deploy_active_active_split_verdict() {
	local s0="$1" s1="$2"
	local rg1_n0 rg1_n1 rg1_fw1 rg2_n0 rg2_fw1
	local f1_fw0 f1_fw1 f2_fw0 f2_fw1
	rg1_n0=$(deploy_node_rg_role node0 1 <<<"$s0" || true)
	rg1_n1=$(deploy_node_rg_role node1 1 <<<"$s0" || true)
	rg1_fw1=$(deploy_node_rg_role node1 1 <<<"$s1" || true)
	rg2_n0=$(deploy_node_rg_role node0 2 <<<"$s0" || true)
	rg2_fw1=$(deploy_node_rg_role node1 2 <<<"$s1" || true)
	if [[ "$rg1_n0" =~ ^secondary(-hold)?$ && "$rg1_n1" == primary && "$rg1_fw1" == primary ]]; then
		pass "RG1 (WAN) moved to fw1"
	else
		fail "RG1 did not move to fw1 (fw0 view: node0=${rg1_n0:-missing} node1=${rg1_n1:-missing}; fw1 view: node1=${rg1_fw1:-missing})"
	fi
	if [[ "$rg2_n0" == primary && "$rg2_fw1" =~ ^secondary(-hold)?$ ]]; then
		pass "RG2 (LAN) stayed on fw0"
	else
		fail "RG2 not owned by fw0 alone (fw0 view: node0=${rg2_n0:-missing}; fw1 view: node1=${rg2_fw1:-missing})"
	fi
	f1_fw0=$(deploy_rg_local_forwarding 1 <<<"$s0" || true)
	f1_fw1=$(deploy_rg_local_forwarding 1 <<<"$s1" || true)
	f2_fw0=$(deploy_rg_local_forwarding 2 <<<"$s0" || true)
	f2_fw1=$(deploy_rg_local_forwarding 2 <<<"$s1" || true)
	if [[ "$f1_fw0" == inactive && "$f1_fw1" == active ]]; then
		pass "RG1 (WAN) forwarding moved to fw1 (fw0 rg-active=inactive, fw1 rg-active=active)"
	else
		fail "RG1 (WAN) forwarding not on fw1 alone (fw0 rg-active=${f1_fw0:-missing}, fw1 rg-active=${f1_fw1:-missing})"
	fi
	if [[ "$f2_fw0" == active && "$f2_fw1" == inactive ]]; then
		pass "RG2 (LAN) forwarding stayed on fw0 (fw0 rg-active=active, fw1 rg-active=inactive)"
	else
		fail "RG2 (LAN) forwarding not on fw0 alone (fw0 rg-active=${f2_fw0:-missing}, fw1 rg-active=${f2_fw1:-missing})"
	fi
	return 0
}

# ── #18523: put every RG back on fw0 between HA smoke phases ──────────
# test-ha-crash.sh and test-restart-connectivity.sh both run this restore,
# so the selftest drives the code they run. The caller defines FW0, FW1 and
# pass()/fail()/info(). `incus` and `sleep` are the only commands with side
# effects, which lets deploy-lib-selftest.sh drive the loop with both mocked.

# deploy_restore_rg_on_fw0 <rg>: fw0 owns <rg> only when BOTH nodes' own
# views agree: fw0's view has node0 primary, and fw1's view has node1
# secondary or secondary-hold. fw0's view alone would score a dual-primary
# split as restored (the ha_rg_owner_verdict rule, #18503). An unreadable
# view is "not restored".
deploy_restore_rg_on_fw0() {
	local rg="${1:?deploy_restore_rg_on_fw0: rg required}" s0 s1
	s0=$(incus exec "$FW0" -- cli -c 'show chassis cluster status' 2>/dev/null || true)
	[[ "$(deploy_node_rg_role node0 "$rg" <<<"$s0" || true)" == primary ]] || return 1
	s1=$(incus exec "$FW1" -- cli -c 'show chassis cluster status' 2>/dev/null || true)
	[[ "$(deploy_node_rg_role node1 "$rg" <<<"$s1" || true)" =~ ^secondary(-hold)?$ ]]
}

# deploy_restore_rg_on_fw1 <rg>: fw1 still claims <rg> in its own view. The
# restore re-requests a yield only then: re-requesting from a node that
# already yielded re-arms its hold and bumps its failover count.
deploy_restore_rg_on_fw1() {
	local rg="${1:?deploy_restore_rg_on_fw1: rg required}" s1
	s1=$(incus exec "$FW1" -- cli -c 'show chassis cluster status' 2>/dev/null || true)
	[[ "$(deploy_node_rg_role node1 "$rg" <<<"$s1" || true)" == primary ]]
}

# deploy_restore_fw0_owns_all: deploy_restore_rg_on_fw0 holds for RG0-2.
deploy_restore_fw0_owns_all() {
	local rg
	for rg in 0 1 2; do
		deploy_restore_rg_on_fw0 "$rg" || return 1
	done
	return 0
}

# deploy_restore_healthy <took-s> <budget-s> <refusals>: a COMPLETED restore
# is healthy only with no refused request and within the budget. Healthy
# restores took 9-16s with one request per RG and no refusal (integ5,
# 2026-10-29). A refusal or a slow restore is the #18521 class (a half-open
# sync, an undischarged fence), the deferral this restore waits out.
deploy_restore_healthy() {
	local took="$1" budget="$2" refusals="$3"
	((refusals == 0 && took <= budget))
}

# deploy_restore_fw0_primary <label> moves RG0-2 back to fw0 one RG at a
# time, polls, and re-requests the yield from fw1 until RESTORE_FW0_WAIT
# (default 60s) runs out. A single fixed sleep after three blind requests was
# shorter than one admission window plus a post-restart bulk (~50
# sessions/s), and swallowed the refusal that said why.
#
# Verdicts (exactly one per call):
#   PASS  fw0 already owned every RG, or the restore completed with no
#         refusal within RESTORE_FW0_BUDGET (default 30s). Returns 0.
#   FAIL  "restored only after": restored, but a request was refused or it
#         took longer than the budget. Returns 0, so the run continues on a
#         restored cluster, but the run is not healthy.
#   FAIL  "could not restore": RESTORE_FW0_WAIT ran out. Returns 1.
# Both FAILs name the last refusal.
deploy_restore_fw0_primary() {
	local label="$1" deadline rg out last_err="" started=$SECONDS requests=0 refusals=0
	local wait_s="${RESTORE_FW0_WAIT:-60}" budget="${RESTORE_FW0_BUDGET:-30}" took
	if deploy_restore_fw0_owns_all; then
		pass "$label: fw0 already primary"
		return 0
	fi
	if [[ ! "$wait_s" =~ ^[0-9]+$ ]]; then
		info "RESTORE_FW0_WAIT=$wait_s is not a whole number of seconds; using 60"
		wait_s=60
	fi
	if [[ ! "$budget" =~ ^[0-9]+$ ]]; then
		info "RESTORE_FW0_BUDGET=$budget is not a whole number of seconds; using 30"
		budget=30
	fi
	for rg in 0 1 2; do
		incus exec "$FW0" -- cli -c "request chassis cluster failover reset redundancy-group $rg" 2>/dev/null || true
		incus exec "$FW1" -- cli -c "request chassis cluster failover reset redundancy-group $rg" 2>/dev/null || true
	done
	sleep 1
	deadline=$((SECONDS + wait_s))
	for rg in 0 1 2; do
		while ! deploy_restore_rg_on_fw0 "$rg"; do
			if ((SECONDS >= deadline)); then
				break 2
			fi
			if deploy_restore_rg_on_fw1 "$rg"; then
				out=$(incus exec "$FW1" -- cli -c "request chassis cluster failover redundancy-group $rg" 2>&1 || true)
				requests=$((requests + 1))
				if grep -qiE "error|refus|not connected|failed" <<<"$out"; then
					refusals=$((refusals + 1))
					last_err="RG$rg: $(head -1 <<<"$out")"
				fi
			fi
			for _ in 1 2 3 4 5; do
				deploy_restore_rg_on_fw0 "$rg" && break
				sleep 1
			done
		done
	done
	if ! deploy_restore_fw0_owns_all; then
		fail "$label: could not restore fw0 as primary within ${wait_s}s${last_err:+ (last refusal: $last_err)}"
		return 1
	fi
	took=$((SECONDS - started))
	if ! deploy_restore_healthy "$took" "$budget" "$refusals"; then
		fail "$label: fw0 restored only after ${took}s (budget ${budget}s; ${requests} request(s), ${refusals} refused${last_err:+; last refusal: $last_err})"
		return 0
	fi
	pass "$label: fw0 restored as primary in ${took}s (${requests} request(s), ${refusals} refused)"
	return 0
}

# failover_ownership_verdict cross-references the two independent checks
# test-failover.sh already performs, and is the #7368 half of the #6591 fix.
#
# The smoke asserts primacy by reading `show chassis cluster status` — a field
# the node reports about ITSELF — and separately asserts that the same node
# carries session entries, a separate count-only observation. The two are never
# compared. #6656 showed what that costs: node0 reported primary for every RG
# with 1 session while node1 carried 33, and the smoke's session assertion
# caught it only INCIDENTALLY, reporting a session-count shortfall on a run
# whose actual failure was ownership/forwarding divergence.
#
# Arguments: sessions on the node REPORTED primary, sessions on its peer, and
# the minimum a healthy primary must carry. Echoes one of:
#
#   ok        the reported primary has enough session entries
#   diverged  the reported primary has almost none while the PEER does
#   nostream   neither node reports session entries — the flow table is empty,
#             which is a different failure with a different fix
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
#     never did — that was the original #6591 report). While the commit wait
#     runs it is re-sent for every RG node0 does not own yet, because node0
#     refuses a transfer for an RG that is transiently not takeover-ready
#     (#12658);
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
	local status rgs rg try pending

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

	# Every `incus exec` in a loop fed on stdin (`done <<<"$rgs"`) takes -n.
	# Without it the client forwards the loop's stdin to the remote command, so
	# the FIRST call drains the rest of $rgs and the body runs for RG0 only:
	# RG1 and RG2 were never transferred, and a deploy that needed them failed
	# this reassert as "node0 is not primary for every redundancy group" (#9683).
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
			incus exec -n "$pinst" -- cli -c "request chassis cluster failover reset redundancy-group $rg" >/dev/null 2>&1 || true
		fi
		incus exec -n "$rinst" -- cli -c "request chassis cluster failover reset redundancy-group $rg" >/dev/null 2>&1 || true
		incus exec -n "$rinst" -- cli -c "request chassis cluster failover redundancy-group $rg node 0" >/dev/null 2>&1 || true
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
		# #12658: re-send the transfer for every RG node0 does not own yet.
		# RequestPeerFailover REFUSES a transfer while the local RG is not
		# takeover-ready, and that window opens routinely in the middle of this
		# loop: the moment RG1 lands on a freshly cut node0 that has not yet
		# proven XSK liveness, node0 stops being an idle standby and RG2 reads
		# `userspace XSK liveness not proven` until WAN RX proves it ~2s later.
		# A transfer that was sent once and refused was never re-sent, so 3 of 4
		# rolling deploys on 2026-10-13 left RG2 on node1 -- split-RG, every
		# LAN->WAN flow across the generic-XDP fabric, capped at ~6 Gbps.
		#
		# Never on the LAST pass: every re-send must be followed by a status
		# read before the pins below are cleared, or this reintroduces #7771.
		if (( try + 1 < DEPLOY_REASSERT_TRANSFER_TRIES )); then
			pending=$(printf '%s\n' "$status" | deploy_node_rgs_not_role node0 primary)
			while read -r rg; do
				[[ -n "$rg" ]] || continue
				info "post-deploy reassert: node0 does not own redundancy group $rg yet; re-sending its transfer"
				incus exec -n "$rinst" -- cli -c "request chassis cluster failover redundancy-group $rg node 0" >/dev/null 2>&1 || true
			done <<<"$pending"
		fi
		(( DEPLOY_REASSERT_TRANSFER_DELAY > 0 )) && sleep "$DEPLOY_REASSERT_TRANSFER_DELAY"
	done

	# Clear the pins. UNCONDITIONAL: see above -- an un-cleared pin blocks the
	# next election and is what #7688 was filed about. -n for the same reason
	# as the transfer loop: without it only RG0's pin is cleared (#9683).
	while read -r rg; do
		[[ -n "$rg" ]] || continue
		incus exec -n "$rinst" -- cli -c "request chassis cluster failover reset redundancy-group $rg" >/dev/null 2>&1 || true
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
		# reject (dataplane.ErrUserspaceShimVerifierReject). The legacy other
		# refusal class exits 1, including a live pinned-map ABI mismatch.
		# Print the #1864 remediation for exit 3 only; for anything else,
		# point at verify-dataplane's own message.
		if (( verify_rc == 3 )); then
			die "verify-dataplane REJECTED the new binary's embedded shim on $rinst — deploy aborted, old daemon untouched.
  This is the #1864 failure mode. Rebuild with the pinned toolchain (make generate) or restore the tracked object:
    git checkout -- pkg/dataplane/userspace_xdp_bpfel.o && make build"
		fi
		# #17769: route both #16701 headroom refusal codes to remediation
		# matching their distinct meanings. Neither is a kernel REJECT or a
		# pinned-map ABI mismatch, and neither honors a guest-side override.
		if (( verify_rc == 4 )); then
			die "verify-dataplane refused the new binary on $rinst (exit 4) — deploy aborted, old daemon untouched.
  LOW-HEADROOM: the shim LOADS on this kernel but measured verifier headroom is below the 15% floor (see verify-dataplane's counts, kernel and floor above).
  Free verifier headroom by reducing the shim's verifier cost (for example, trim the hot parsing paths described in pkg/dataplane/README.md), then rebuild and rerun the pre-flight. Alternatively, use a kernel with sufficient measured headroom; retry deployment only after this check passes. No guest-side override is honored."
		fi
		if (( verify_rc == 5 )); then
			die "verify-dataplane refused the new binary on $rinst (exit 5) — deploy aborted, old daemon untouched.
  UNMEASURED-HEADROOM: the shim LOADS on this kernel, but its processed-instruction count was unavailable, so the 15% floor could not be applied (see verify-dataplane's message above).
  Do not treat this as measured headroom or clear live pins. Resolve the verifier-stat reporting incompatibility or use a kernel that reports processed-instruction counts, then rerun the pre-flight and deploy only after it passes. No guest-side override is honored."
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

# deploy_install_deb <rinst> <local_deb>
#
# Install a local .deb on a node through a freshly-created remote directory.
# The old fixed destination, /tmp/<basename>, made a same-name re-push hit the
# existing file before apt ran (and meant the versions-slot collision was never
# diagnosed). A mktemp-created directory gives every install a distinct slot;
# both the package and its temporary directory are removed after apt, including
# failed push/install paths.
deploy_install_deb() {
	local rinst="$1" deb="$2" allow_downgrade="${3:-}"
	local base tmpdir remote_deb rc
	local -a apt_flags=(-y --reinstall)
	base=$(basename "$deb")
	# #18772: a deliberate lab downgrade (deploy_deb_node_action said
	# install-downgrade, which needs XPF_DEPLOY_ALLOW_DOWNGRADE=<that version>) is the only
	# caller that passes --allow-downgrades. Without it apt refuses as before.
	[[ "$allow_downgrade" == allow-downgrade ]] && apt_flags+=(--allow-downgrades)

	# mktemp creates the directory atomically on the target, so even a same-name
	# re-push gets a distinct, absent destination. Validate the returned path
	# before interpolating it into subsequent remote commands.
	if ! tmpdir=$(incus exec "$rinst" -- mktemp -d /tmp/xpf-deb.XXXXXX); then
		die "could not allocate a unique remote .deb slot on $rinst"
	fi
	if [[ "$tmpdir" != /tmp/xpf-deb.* ]]; then
		die "remote mktemp returned an unsafe .deb slot on $rinst: $tmpdir"
	fi
	remote_deb="${tmpdir%/}/$base"

	info "Pushing $base to $rinst (slot $tmpdir)..."
	if incus file push "$deb" "${rinst}${remote_deb}"; then
		:
	else
		rc=$?
		incus exec "$rinst" -- rm -rf "$tmpdir" 2>/dev/null ||
			warn "could not clean failed .deb slot $tmpdir on $rinst"
		return "$rc"
	fi

	# apt install is STAGE-ONLY on a clustered node (node-id present): it
	# refreshes the staging path but does NOT cut the dataplane.
	if incus exec "$rinst" -- apt-get install "${apt_flags[@]}" "$remote_deb"; then
		:
	else
		rc=$?
		incus exec "$rinst" -- rm -rf "$tmpdir" 2>/dev/null ||
			warn "could not clean failed .deb slot $tmpdir on $rinst"
		return "$rc"
	fi

	if ! incus exec "$rinst" -- rm -rf "$tmpdir"; then
		die "installed $base on $rinst but could not remove temporary .deb slot $tmpdir"
	fi
}

# ── Deb deploy plan: upgrade, same version, deliberate downgrade (#18772, #18764) ──
#
# The deb path cuts a node with `apt-get install` (stage) plus `xpfd upgrade
# --rolling` (cut). Two shapes used to fail MID-CELL, after earlier steps had
# spent cluster time, and the failed deploy invalidated the attestation
# manifest so the next gate VOIDed:
#   - a DOWNGRADE (an A->B->A cell putting master back): apt refuses
#     without --allow-downgrades. Past apt, the product's anti-rollback floor
#     (/var/lib/xpf/binary-floor, #10848) refuses both the postinst publish
#     and the cut, by design: a validly-signed old build is a replay;
#   - the SAME version again: the re-stage mints a new source generation,
#     and the cut refuses to replace the live dir (#16219).
#
# Now the plan is decided up front, before anything is pushed or the
# manifest is touched:
#   upgrade / fresh     install and cut, as before;
#   same + identical    the node already runs this deb byte for byte: skip
#                       the install and the cut, and the manifest is written
#                       from the deb as usual, so the attestation is kept;
#   same + different    refuse (rebuild under a new version);
#   downgrade           refuse, naming both versions and the fix, UNLESS
#                       XPF_DEPLOY_ALLOW_DOWNGRADE equals that deb's exact
#                       version. That is a deliberate lab A/B step: apt gets
#                       --allow-downgrades and the node's binary anti-rollback
#                       floor is reset first (what `dpkg --purge` does to it,
#                       debian/xpf.postrm). The next COMMITTED cut re-enrolls
#                       the floor at the deployed version. The
#                       product code is unchanged. A downgrade across a
#                       config-envelope bump is still refused by the cut's
#                       envelope check (the older binary cannot read the DB).

# deploy_running_deb_state <rinst>: "<dpkg status abbrev> <version>" for xpf,
# or empty on a confirmed package-absent result. A transport/query failure is
# a nonzero status so it can never be mistaken for a fresh node.
deploy_running_deb_state() {
	local rinst="$1" output rc
	if output=$(incus exec -n "$rinst" -- env LC_ALL=C dpkg-query -W -f='${db:Status-Abbrev} ${Version}' xpf 2>&1); then
		[[ -n "$output" ]] || {
			warn "deb deploy preflight: could not query xpf dpkg state on $rinst (empty successful response)"
			return 1
		}
		printf '%s\n' "$output"
		return 0
	else
		rc=$?
	fi
	if [[ "$output" == *"dpkg-query: no packages found matching xpf"* ]]; then
		return 0
	fi
	warn "deb deploy preflight: could not query xpf dpkg state on $rinst (rc=$rc): ${output:-no response}"
	return 1
}

# deploy_running_deb_version <rinst>: the xpf version a node has fully
# INSTALLED ("ii"), or "" when it has none. A removed-but-not-purged ("rc")
# record counts as none. Any other state (half-installed, unpacked,
# failed-config) prints "!<abbrev>", which deploy_deb_node_action refuses:
# dpkg-query prints a Version for those too, and it is not a running build.
deploy_running_deb_version() {
	local rinst="$1" state abbrev ver
	state=$(deploy_running_deb_state "$rinst") || return 1
	# spaces before the version; read splits on any run of them.
	read -r abbrev ver <<<"$state"
	case "$abbrev" in
	ii) printf '%s\n' "$ver" ;;
	"" | rc | un | pn) printf '\n' ;;
	*) printf '!%s\n' "$abbrev" ;;
	esac
}

# deploy_deb_plan <deb_version> <running_version>: upgrade | same | downgrade
# | fresh (nothing running). Pure, so the ordering is a table cell.
deploy_deb_plan() {
	local deb_ver="$1" run_ver="$2"
	if [[ -z "$run_ver" ]]; then
		printf 'fresh\n'
	elif dpkg --compare-versions "$deb_ver" gt "$run_ver"; then
		printf 'upgrade\n'
	elif dpkg --compare-versions "$deb_ver" eq "$run_ver"; then
		printf 'same\n'
	else
		printf 'downgrade\n'
	fi
}

# deploy_allow_downgrade <deb_version>: the explicit lab opt-in, bound to the
# version being deployed. XPF_DEPLOY_ALLOW_DOWNGRADE must equal that deb's exact
# version, so an export left in a shell cannot authorize an unrelated later
# downgrade. "1", "true" and any other version are no.
deploy_allow_downgrade() {
	[[ -n "${1:-}" && "${XPF_DEPLOY_ALLOW_DOWNGRADE:-}" == "$1" ]]
}

# DEPLOY_DEB_MANAGED_BINARIES are the binaries a deb stages and a cut copies
# into the live version dir (the four the postinst publishes).
DEPLOY_DEB_MANAGED_BINARIES=(xpfd cli xpf-userspace-dp xpf-day0-config)

# deploy_live_version_bin_sha256 <rinst> <name>: sha256 of <name> in the node's
# live version dir (/var/lib/xpf/versions/current), the copy the cut made.
deploy_live_version_bin_sha256() {
	local rinst="$1" name="$2" raw
	raw=$(incus exec -n "$rinst" -- sha256sum "/var/lib/xpf/versions/current/$name" 2>/dev/null || true)
	raw=${raw%% *}
	[[ "$raw" =~ ^[0-9a-f]{64}$ ]] || return 1
	printf '%s\n' "$raw"
}

# deploy_node_runs_deb <rinst> <deb>: true when the node is byte-identical to
# the deb: the RUNNING xpfd and userspace helper processes, and every managed
# binary in the live version dir (xpfd, cli, helper, xpf-day0-config).
deploy_node_runs_deb() {
	local rinst="$1" deb="$2" want got bin
	want=$(deploy_manifest_sha_from_deb "$deb" xpfd) || return 1
	got=$(deploy_running_xpfd_sha256 "$rinst" 3) || return 1
	[[ "$want" == "$got" ]] || return 1
	want=$(deploy_manifest_sha_from_deb "$deb" xpf-userspace-dp) || return 1
	got=$(deploy_running_xpf_userspace_dp_sha256 "$rinst" 3) || return 1
	[[ "$want" == "$got" ]] || return 1
	for bin in "${DEPLOY_DEB_MANAGED_BINARIES[@]}"; do
		want=$(deploy_manifest_sha_from_deb "$deb" "$bin") || return 1
		got=$(deploy_live_version_bin_sha256 "$rinst" "$bin") || return 1
		[[ "$want" == "$got" ]] || return 1
	done
}

# deploy_deb_node_action <rinst> <deb>: what to do on one node. Prints one of
#   install            upgrade or fresh install
#   install-downgrade  deliberate downgrade (opt-in present)
#   skip-same          already running this deb byte for byte
# and returns 0, or prints the refusal and returns 1. Never mutates the node.
deploy_deb_node_action() {
	local rinst="$1" deb="$2" deb_ver run_ver plan
	deb_ver=$(deploy_deb_version "$deb") || {
		printf 'refusing: cannot validate the xpf package filename against its metadata Version: %s\n' "$deb" >&2
		return 1
	}
	run_ver=$(deploy_running_deb_version "$rinst") || {
		printf 'refusing: could not query xpf dpkg state on %s; not assuming a fresh install\n' "$rinst" >&2
		return 1
	}
	if [[ "$run_ver" == '!'* ]]; then
		printf 'refusing: xpf on %s is in dpkg state %s, not installed (ii); repair it (dpkg --configure -a, or reinstall) before deploying\n' \
			"$rinst" "${run_ver#!}" >&2
		return 1
	fi
	plan=$(deploy_deb_plan "$deb_ver" "$run_ver")
	case "$plan" in
	upgrade | fresh)
		printf 'install\n'
		;;
	same)
		if deploy_node_runs_deb "$rinst" "$deb"; then
			printf 'skip-same\n'
		else
			printf 'refusing: %s already runs xpf %s, but not these bytes (or they cannot be read); a re-staged same version cannot be cut (#16219) -- build a fresh DEB_VERSION with scripts/next-deb-version.sh\n' \
				"$rinst" "$run_ver" >&2
			return 1
		fi
		;;
	downgrade)
		if deploy_allow_downgrade "$deb_ver"; then
			printf 'install-downgrade\n'
		else
			printf 'refusing: xpf_%s is not newer than the running %s on %s; an A->B->A cell needs monotonically increasing versions -- build a fresh DEB_VERSION with scripts/next-deb-version.sh (e.g. rebuild A as a higher version), or set XPF_DEPLOY_ALLOW_DOWNGRADE=%s for this deliberate lab downgrade (it resets the node'"'"'s anti-rollback floor)\n' \
				"$deb_ver" "$run_ver" "$rinst" "$deb_ver" >&2
			return 1
		fi
		;;
	esac
}

# deploy_deb_preflight <deb> <rinst>...: decide every target node's action
# BEFORE the first push or manifest invalidation, so a refused cell costs
# nothing and the previous attestation survives. Prints "<rinst> <action>"
# per node.
deploy_deb_preflight() {
	local deb="$1" rinst action rc=0
	shift
	for rinst in "$@"; do
		if action=$(deploy_deb_node_action "$rinst" "$deb"); then
			printf '%s %s\n' "$rinst" "$action"
		else
			rc=1
		fi
	done
	return "$rc"
}

# deploy_reset_binary_floor <rinst>: the opted-in downgrade's floor reset,
# loudly. Only deploy_vm_deb's install-downgrade branch calls it. The floor is
# MOVED aside, not deleted, and armed with an EXIT guard before the move. Any
# exit before a committed cut—including install, publish, reconcile, and remote
# mktemp failures—tries to restore it; a committed cut re-enrolls a new one and
# deploy_drop_saved_binary_floor discards the old.
DEPLOY_BINARY_FLOOR=/var/lib/xpf/binary-floor
DEPLOY_BINARY_FLOOR_SAVED=/var/lib/xpf/binary-floor.lab-downgrade-saved

# A downgrade's moved-aside floor is guarded for the entire remaining deploy,
# including `die`, set -e, reconcile, and mktemp failures. The EXIT handler is
# shared with the attestation guard when cmd_deploy has already armed it.
deploy_binary_floor_guard_arm() {
	_deploy_floor_guard_rinst="$1"
	_deploy_floor_guard_pending=1
	deploy_exit_guard_install
}

deploy_binary_floor_guard_disarm() {
	_deploy_floor_guard_pending=0
}

deploy_binary_floor_guard_restore_on_exit() {
	(( ${_deploy_floor_guard_pending:-0} )) || return 0
	local rinst="${_deploy_floor_guard_rinst:-}"
	[[ -n "$rinst" ]] || return 1
	if deploy_restore_binary_floor "$rinst"; then
		_deploy_floor_guard_pending=0
		return 0
	fi
	return 1
}

deploy_reset_binary_floor() {
	local rinst="$1"
	warn "LAB DOWNGRADE (XPF_DEPLOY_ALLOW_DOWNGRADE=${XPF_DEPLOY_ALLOW_DOWNGRADE:-}): moving the binary anti-rollback floor $DEPLOY_BINARY_FLOOR aside on $rinst so the older build can publish and cut; a committed cut re-enrolls it at the deployed version, and any failure before that restores it"
	deploy_binary_floor_guard_arm "$rinst"
	incus exec -n "$rinst" -- bash -c "if [ -e $DEPLOY_BINARY_FLOOR ]; then mv -f $DEPLOY_BINARY_FLOOR $DEPLOY_BINARY_FLOOR_SAVED; fi"
}

# deploy_restore_binary_floor <rinst>: undo deploy_reset_binary_floor after a
# failure. A floor the failed attempt already re-enrolled is kept; a failed
# move preserves the saved copy and propagates its status.
deploy_restore_binary_floor() {
	local rinst="$1"
	warn "LAB DOWNGRADE did not commit on $rinst; restoring its anti-rollback floor"
	incus exec -n "$rinst" -- bash -c "if [ -e $DEPLOY_BINARY_FLOOR ]; then rm -f $DEPLOY_BINARY_FLOOR_SAVED; elif [ -e $DEPLOY_BINARY_FLOOR_SAVED ]; then mv -f $DEPLOY_BINARY_FLOOR_SAVED $DEPLOY_BINARY_FLOOR || exit \$?; fi"
}

# deploy_drop_saved_binary_floor <rinst>: the cut committed and re-enrolled
# the floor; discard the saved one.
deploy_drop_saved_binary_floor() {
	local rinst="$1"
	incus exec -n "$rinst" -- rm -f "$DEPLOY_BINARY_FLOOR_SAVED"
}

# ── Prebuilt-deb selection (#16308) ─────────────────────────────────
# `make cluster-deploy` used to unconditionally rebuild a stock deb via
# its .PHONY `deb` prerequisite, silently discarding a prebuilt
# high-version deb (e.g. `make deb DEB_VERSION=99.0.x+…`, the #16219
# downgrade-avoidance workflow) and then dying inside apt on the
# downgrade. Selection here is by Debian VERSION (dpkg --compare-versions),
# never mtime: mtime is what the just-rebuilt stock deb always wins.
#
# deploy_deb_filename_version <deb_path> -> echo the version in the filename
# xpf_<version>_<arch>.deb, or return 1 when the name does not parse. Used
# only for candidate selection; deployed plans and attestations use package
# metadata and verify it agrees with this name.
deploy_deb_filename_version() {
	local base ver
	base=$(basename "$1")
	case "$base" in
		xpf_*_*.deb) ;;
		*) return 1 ;;
	esac
	ver="${base#xpf_}"
	ver="${ver%_*}"
	[[ -n "$ver" ]] || return 1
	printf '%s\n' "$ver"
}

# deploy_deb_version <deb_path> -> echo dpkg-deb's Version field only when it
# matches the xpf_<version>_<arch>.deb filename. Plans and attestations must
# refuse a renamed or malformed package rather than naming its wrong build.
deploy_deb_version() {
	local filename_ver metadata_ver
	filename_ver=$(deploy_deb_filename_version "$1") || return 1
	metadata_ver=$(dpkg-deb -f "$1" Version 2>/dev/null) || {
		printf 'refusing: cannot read dpkg-deb Version metadata from %s\n' "$1" >&2
		return 1
	}
	if [[ -z "$metadata_ver" || "$filename_ver" != "$metadata_ver" ]]; then
		printf "refusing: filename version '%s' for %s does not match package metadata Version '%s'\n" \
			"$filename_ver" "$1" "$metadata_ver" >&2
		return 1
	fi
	printf '%s\n' "$metadata_ver"
}

# deploy_deb_newest <dir> -> echo the path of the highest-version
# xpf_*.deb in <dir> by dpkg version ordering, or nothing (rc 1) when the
# dir holds no parseable deb. Ties (same version, different arch/build)
# break by newest mtime so the result is deterministic, matching the old
# `ls -t` behaviour within a single version.
deploy_deb_newest() {
	local dir="$1" deb ver best="" best_ver=""
	[[ -d "$dir" ]] || return 1
	for deb in "$dir"/xpf_*.deb; do
		[[ -f "$deb" ]] || continue
		ver=$(deploy_deb_filename_version "$deb") || continue
		if [[ -z "$best" ]]; then
			best="$deb"; best_ver="$ver"; continue
		fi
		if dpkg --compare-versions "$ver" gt "$best_ver" 2>/dev/null; then
			best="$deb"; best_ver="$ver"
		elif [[ "$ver" == "$best_ver" && "$deb" -nt "$best" ]]; then
			best="$deb"
		fi
	done
	[[ -n "$best" ]] || return 1
	printf '%s\n' "$best"
}

# deploy_select_deb <dir> -> echo the deb to deploy in <dir>:
#   1. XPF_DEPLOY_DEB_PATH: that exact file (absolute, or relative to
#      <dir>), die if missing/unparseable. An explicit PATH is the most
#      specific pin and WINS over XPF_DEPLOY_DEB_VERSION when both are
#      set (per-invocation candidate pins, e.g. test-rolling-upgrade,
#      must not be overridden by a version pin from the environment).
#   2. XPF_DEPLOY_DEB_VERSION (exported by the Makefile deploy targets
#      when DEB_VERSION was explicit): the xpf_<version>_*.deb in <dir>,
#      die if absent — an explicitly built deb must deploy even if a
#      higher stale deb sits beside it.
#   3. Otherwise the highest Debian version present (deploy_deb_newest).
# Used by every deploy/attestation site so they can never disagree about
# which artifact shipped (#16308).
deploy_select_deb() {
	local dir="$1" pin="${XPF_DEPLOY_DEB_PATH:-}" want="${XPF_DEPLOY_DEB_VERSION:-}" cand
	if [[ -n "$pin" ]]; then
		cand="$pin"
		[[ "$cand" = /* ]] || cand="$dir/$cand"
		[[ -f "$cand" ]] ||
			die "XPF_DEPLOY_DEB_PATH=$pin does not name an existing .deb (looked for $cand)"
		deploy_deb_filename_version "$cand" >/dev/null ||
			die "XPF_DEPLOY_DEB_PATH=$pin is not a parseable xpf_<version>_<arch>.deb"
		printf '%s\n' "$cand"
		return 0
	fi
	if [[ -n "$want" ]]; then
		for cand in "$dir"/xpf_"$want"_*.deb; do
			if [[ -f "$cand" ]]; then
				printf '%s\n' "$cand"
				return 0
			fi
		done
		die "XPF_DEPLOY_DEB_VERSION=$want: no xpf_${want}_*.deb in $dir (was 'make deb DEB_VERSION=$want' run?)"
	fi
	deploy_deb_newest "$dir"
}

# ── Lab cluster control-channel key (#18724) ─────────────────────────────
#
# The HA lab configs (docs/ha-cluster-{userspace,tcp,udp}.conf) used to carry
# their `chassis cluster authentication-key` in the repository: loss the
# published `…-CHANGE-ME` placeholder, tcp and udp random keys that were just
# as public once committed. The raw deploy pushes $CLUSTER_CONF verbatim, so a
# re-setup restored the published key even after a live rotation.
#
# The configs now carry DEPLOY_CLUSTER_KEY_TOKEN in place of the key, and the
# raw push renders the file with the key from a host-side secret
# ($CLUSTER_AUTH_KEY_FILE, set per cluster in the env file). The token keeps
# the #6611 placeholder marker on purpose: a conf that reaches a node WITHOUT
# rendering still compiles, but it warns as a published placeholder instead of
# looking like a real key.
#
# Nothing here prints the key: the substitution is a bash expansion (never an
# argv), failures name files and lengths only, and the rendered file is
# written under umask 077 and removed by the caller after the push.
DEPLOY_CLUSTER_KEY_TOKEN="xpf-lab-cluster-key-substituted-at-deploy-CHANGE-ME"

# deploy_cluster_key_problem <key>: why <key> cannot be a lab cluster key, or
# "" when it can. A conf string cannot hold a double quote, a backslash or a
# newline; 16 is pkg/config's MinAdvisedControlLinkKeyLen; and a key that
# matches a #6611 placeholder marker would just reintroduce the problem.
deploy_cluster_key_problem() {
	local key="$1" lower
	lower="${1,,}"
	if [[ -z "$key" ]]; then
		printf 'is empty'
	elif [[ "$key" == *[[:space:]\"\\]* ]]; then
		printf 'contains whitespace, a double quote or a backslash'
	elif ((${#key} < 16)); then
		printf 'is %d characters, under the 16-character floor' "${#key}"
	elif [[ "$lower" == *change-me* || "$lower" == *example-only* ]]; then
		printf 'matches a published placeholder marker'
	fi
}

# deploy_cluster_key_mode_problem <file>: refuse a key file, or the directory
# holding it, that grants ANY group or other permission bit. The generator
# creates them 0600 and 0700, but an existing file is never rewritten, so a
# key someone copied in at 0644, or a directory left 0755, would otherwise be
# rendered and pushed as if it were private. Prints the fix; never the key.
deploy_cluster_key_mode_problem() {
	local file="$1" dir mode
	dir="$(dirname "$file")"
	mode="$(stat -c %a "$file" 2>/dev/null)" || {
		warn "cluster key: cannot stat $file"
		return 1
	}
	if (((8#$mode & 8#077) != 0)); then
		warn "cluster key: $file is mode $mode, readable or writable beyond its owner; run \`chmod 0600 $file\` (and rotate the key if anyone else could have read it)"
		return 1
	fi
	mode="$(stat -c %a "$dir" 2>/dev/null)" || {
		warn "cluster key: cannot stat $dir"
		return 1
	}
	if (((8#$mode & 8#077) != 0)); then
		warn "cluster key: $dir is mode $mode, open beyond its owner; run \`chmod 0700 $dir\`"
		return 1
	fi
	return 0
}

# deploy_ensure_cluster_key <file> [generate]: make sure <file> holds a
# usable key. An existing file is never rewritten: it is the key the live
# cluster runs. A MISSING file is a refusal, because minting a fresh key on a
# deploy to a live cluster splits the pair. It is generated (`openssl rand
# -base64 32`, directory 0700, file 0600) only on an explicit opt-in: the
# second argument `generate`, which `cluster-setup.sh create` passes for a
# newly created cluster, or XPF_CLUSTER_KEY_GENERATE=1. A symlink at the key
# path is refused outright, dangling or not.
deploy_ensure_cluster_key() {
	local file="$1" mode="${2:-}" dir key problem tmp
	[[ -n "$file" ]] || {
		warn "cluster key: no key file named (set CLUSTER_AUTH_KEY_FILE in the cluster env file)"
		return 1
	}
	if [[ -L "$file" ]]; then
		warn "cluster key: $file is a symlink; refusing it. Point CLUSTER_AUTH_KEY_FILE at the real file"
		return 1
	fi
	if [[ ! -e "$file" && "$mode" != generate && "${XPF_CLUSTER_KEY_GENERATE:-0}" != 1 ]]; then
		warn "cluster key: $file does not exist. It holds the key the running cluster signs with, so a deploy never mints one: restore the file, or re-key the cluster with the rolling additional-authentication-key rotation (pkg/cluster/README.md, \"Rotation\"). For a NEW cluster, \`cluster-setup.sh create\` generates it, or set XPF_CLUSTER_KEY_GENERATE=1"
		return 1
	fi
	if [[ ! -e "$file" ]]; then
		dir="$(dirname "$file")"
		(umask 077 && mkdir -p "$dir") || return 1
		if ! chmod 0700 "$dir"; then
			warn "cluster key: could not set $dir to mode 0700; refusing to generate a key there"
			return 1
		fi
		tmp="$(umask 077 && mktemp "${file}.XXXXXX")" || return 1
		if ! (umask 077 && openssl rand -base64 32 >"$tmp"); then
			rm -f "$tmp"
			warn "cluster key: could not generate $file (is openssl installed?)"
			return 1
		fi
		chmod 0600 "$tmp" && mv -f "$tmp" "$file" || { rm -f "$tmp"; return 1; }
		info "cluster key: generated a new key in $file (mode 0600)"
	fi
	[[ -f "$file" && -r "$file" ]] || {
		warn "cluster key: $file is not a readable regular file"
		return 1
	}
	deploy_cluster_key_mode_problem "$file" || return 1
	key="$(<"$file")"
	problem="$(deploy_cluster_key_problem "$key")"
	if [[ -n "$problem" ]]; then
		warn "cluster key: the key in $file $problem; regenerate it with \`openssl rand -base64 32\`"
		return 1
	fi
	return 0
}

# deploy_render_cluster_conf <src> <key_file> <out>: write <src> to <out>
# (mode 0600) with every DEPLOY_CLUSTER_KEY_TOKEN replaced by the key in
# <key_file>. Byte for byte otherwise: trailing newlines and NUL bytes are kept
# as they are. A conf without the token (an older or hand-keyed config) is
# copied unchanged and <key_file> is not consulted. Fails closed when the
# token is present but no usable key exists, or when the token survives.
#
# The substitution runs in python3, reading the key from <key_file> itself, so
# the key never reaches an argv or the environment; only paths do.
deploy_render_cluster_conf() {
	local src="$1" key_file="$2" out="$3" rc
	[[ -f "$src" ]] || {
		warn "cluster conf: $src not found"
		return 1
	}
	if ! grep -aqF -- "$DEPLOY_CLUSTER_KEY_TOKEN" "$src"; then
		install -m 0600 -- "$src" "$out"
		return
	fi
	deploy_ensure_cluster_key "$key_file" || {
		warn "cluster conf: $src carries the lab key token but no usable key is available; refusing to push it"
		return 1
	}
	rc=0
	CK_SRC="$src" CK_KEY_FILE="$key_file" CK_OUT="$out" CK_TOKEN="$DEPLOY_CLUSTER_KEY_TOKEN" \
		python3 -I - <<'PY' || rc=$?
import os, sys
src, key_file, out, token = (os.environ[k] for k in ("CK_SRC", "CK_KEY_FILE", "CK_OUT", "CK_TOKEN"))
token = token.encode()
# The bash check read the key with $(<), which drops trailing newlines; match it.
key = open(key_file, "rb").read().rstrip(b"\n")
# Defence in depth behind deploy_cluster_key_problem, which cannot see a NUL.
if not key or any(b < 0x21 or b > 0x7e or b in b'"\\' for b in key) or token in key:
    sys.exit(4)
data = open(src, "rb").read().replace(token, key)
if token in data:
    sys.exit(5)
old = os.umask(0o077)
try:
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
finally:
    os.umask(old)
with os.fdopen(fd, "wb") as f:
    f.write(data)
PY
	case "$rc" in
	0) return 0 ;;
	4) warn "cluster conf: the key in $key_file is not a printable, quote-free key; refusing to push $src" ;;
	5) warn "cluster conf: the lab key token survived rendering $src; refusing to push it" ;;
	*) warn "cluster conf: rendering $src failed (python3 exit $rc)" ;;
	esac
	rm -f "$out"
	return 1
}

# deploy_push_cluster_conf <src> <key_file> <instance> <dest>: render <src>
# into a private temp dir and push the result to <instance><dest> at mode
# 0600, root:root. The body is a subshell whose EXIT trap removes the temp
# dir. bash runs an EXIT trap when HUP, INT or TERM kills the shell too, so a
# render or push that is interrupted never leaves the rendered copy (it holds
# the key) in $TMPDIR; the signal cell pins that for all three.
# Exit status: 0 pushed, 2 refused to render (the message is already out),
# 1 or 3 the temp dir or the push failed.
deploy_push_cluster_conf() (
	src="$1" key_file="$2" instance="$3" dest="$4"
	conf_dir="$(umask 077 && mktemp -d)" || exit 1
	trap 'rm -rf "$conf_dir"' EXIT
	deploy_render_cluster_conf "$src" "$key_file" "$conf_dir/xpf.conf" || exit 2
	incus file push --mode 0600 --uid 0 --gid 0 "$conf_dir/xpf.conf" "${instance}${dest}" || exit 3
)
