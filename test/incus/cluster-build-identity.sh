# shellcheck shell=bash
#
# Shared-cluster BUILD IDENTITY — sourced, never executed.
#
# WHY THIS EXISTS. The #1875 lock serialises ACCESS to the shared loss
# userspace cluster. It says nothing about what is RUNNING on it. Those
# are different guarantees, and the gap between them silently invalidated
# two measurement runs:
#
#   a lane waited ~5 minutes for the lock, never touched the holder,
#   acquired cleanly, and then measured a binary another lane's deploy
#   had installed moments earlier — whose subject happened to be the very
#   code path under test. Every lock-level check said "clean". The only
#   tell was a CLI banner reading `uptime: 1m46s` for a daemon the lane
#   believed it had deployed hours before.
#
# A confound that survives a correct lock, produces plausible numbers, and
# is visible only in a stray banner line is not something to re-derive per
# lane. So the cell records WHICH BUILD it is measuring, and says so when
# that changes.
#
# WHAT IT DOES NOT DO. It does not prevent a concurrent deploy — the lock
# already does that for anyone who takes it. It answers a narrower and
# more useful question: "is the artifact I am measuring the one that was
# there when I acquired?"
#
# THREE SURFACES, deliberately different in severity:
#
#   xpf_cluster_build_record   — sample and record (called at acquire).
#   xpf_cluster_build_report   — compare and REPORT (called at release).
#                                Advisory by default; see below.
#   xpf_assert_cluster_build_unchanged
#                              — compare and FAIL. For a measurement to
#                                call immediately before it samples.
#
# WHY THE BOUNDARY CHECK IS ADVISORY AND THE ASSERT IS FATAL. A cell that
# deploys ON PURPOSE changes the sha, and that is not an error — the
# sanctioned deploy path re-baselines (`xpf_cluster_rebaseline_build`), but
# an image roll, an `xpfd upgrade`, or a future path that nobody thought to
# wire would trip a fatal boundary check and break working targets for a
# diagnostic. A measurement, by contrast, is exactly where a wrong answer
# is expensive and where the caller KNOWS it is not deploying — so that is
# where the hard failure belongs. `XPF_CLUSTER_BUILD_STRICT=1` promotes the
# boundary check to fatal for a run that wants it.
#
# Sampling is BEST-EFFORT and never fatal on its own: a node that is off,
# rebooting, or absent yields no sample, and "I could not tell" must not
# fail a cell that was going to succeed. An unknown is reported as unknown,
# never as unchanged — the failure-to-a-healthy-looking-value shape this
# whole file exists to close.

XPF_CLUSTER_BUILD_BIN="${XPF_CLUSTER_BUILD_BIN:-/usr/local/sbin/xpfd}"
# Per-node probe timeout. The probe runs at EVERY cell acquire and release,
# so a hung `incus exec` (unreachable remote, a node mid-reboot) must not
# stall a cell that would otherwise proceed — this check is a diagnostic
# and must never become a new way for the cluster to be unusable. A timeout
# yields `unknown`, which is reported as unknown and never as unchanged.
XPF_CLUSTER_BUILD_TIMEOUT="${XPF_CLUSTER_BUILD_TIMEOUT:-10}"
# Escape hatch: `0` disables sampling entirely (probe reports nothing, so
# every comparison degrades to "cannot tell"). Set by the hermetic
# self-tests, which must not reach a real cluster.
XPF_CLUSTER_BUILD_PROBE="${XPF_CLUSTER_BUILD_PROBE:-1}"

# Echo "<instance-ref> <sha256|unknown>" per cluster node, sorted.
# Never fails; a node it cannot reach reports `unknown`.
xpf_cluster_build_probe() {
	local dir refs ref sha
	[[ "${XPF_CLUSTER_BUILD_PROBE}" == "0" ]] && return 0
	dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
	# Resolve FW0/FW1 in a SUBSHELL so cluster-env.sh's exports cannot
	# leak into the caller's environment (with-cluster.sh runs the cell
	# with a deliberately minimal env contract).
	refs="$(
		# shellcheck source=cluster-env.sh
		source "${dir}/cluster-env.sh" >/dev/null 2>&1 || true
		printf '%s\n%s\n' "${FW0:-}" "${FW1:-}"
	)"
	# -n: without it `incus exec` forwards this loop's stdin to the remote
	# command, so the first node's call drains the node list and only FW0 is
	# ever probed. A binary swapped on FW1 then diffs clean (#9683).
	while read -r ref; do
		[[ -n "$ref" ]] || continue
		sha="$(timeout "$XPF_CLUSTER_BUILD_TIMEOUT" \
			incus exec -n "$ref" -- sha256sum "$XPF_CLUSTER_BUILD_BIN" 2>/dev/null \
			| awk '{print $1}')"
		printf '%s %s\n' "$ref" "${sha:-unknown}"
	done <<<"$refs" | sort
}

# Record the current build identity into $1 (default: the cell baseline).
xpf_cluster_build_record() {
	local out="${1:-${XPF_CLUSTER_BUILD_BASELINE:-}}"
	[[ -n "$out" ]] || return 0
	xpf_cluster_build_probe >"$out" 2>/dev/null || true
}

# Re-baseline after a DELIBERATE deploy, so the boundary check does not
# report a change the cell made itself. Safe to call when no cell is
# active (no baseline path exported) — it is then a no-op.
xpf_cluster_rebaseline_build() {
	[[ -n "${XPF_CLUSTER_BUILD_BASELINE:-}" ]] || return 0
	xpf_cluster_build_record "$XPF_CLUSTER_BUILD_BASELINE"
}

# Compare current identity against the baseline.
#   0 = unchanged, 1 = CHANGED, 2 = cannot tell (missing baseline / no sample)
# Prints a per-node report naming BOTH shas on a change: knowing WHICH
# build was measured is what makes the diagnostic actionable — that is how
# the originating run was traced to a specific sibling branch.
xpf_cluster_build_diff() {
	local base="${1:-${XPF_CLUSTER_BUILD_BASELINE:-}}"
	[[ -n "$base" && -s "$base" ]] || return 2
	local now ref was is rc=0 sampled=0
	now="$(xpf_cluster_build_probe)"
	while read -r ref was; do
		[[ -n "$ref" ]] || continue
		is="$(awk -v r="$ref" '$1==r {print $2}' <<<"$now")"
		[[ -n "$is" ]] || is="unknown"
		if [[ "$was" == "unknown" || "$is" == "unknown" ]]; then
			echo "  ${ref}: build identity UNKNOWN (was=${was} now=${is}) — not a clean bill" >&2
			continue
		fi
		sampled=1
		if [[ "$was" != "$is" ]]; then
			echo "  ${ref}: BUILD CHANGED  was=${was}  now=${is}" >&2
			rc=1
		fi
	done <"$base"
	[[ "$sampled" == 1 ]] || return 2
	return "$rc"
}

# Boundary report — advisory unless XPF_CLUSTER_BUILD_STRICT=1.
# $1 is a short label for the phase being reported on.
xpf_cluster_build_report() {
	local label="${1:-cell}"
	local rc=0
	xpf_cluster_build_diff || rc=$?
	case "$rc" in
		1)
			echo "[with-cluster] WARNING: the xpfd build CHANGED during this ${label}." >&2
			echo "  Any measurement taken in this cell describes a binary that was" >&2
			echo "  replaced under it. The #1875 lock serialises ACCESS, not the" >&2
			echo "  artifact — if you did not deploy, another lane did." >&2
			echo "  If this cell deployed on purpose, call xpf_cluster_rebaseline_build." >&2
			[[ "${XPF_CLUSTER_BUILD_STRICT:-}" == "1" ]] && return 1
			;;
		2)
			echo "[with-cluster] note: build identity could not be established for this ${label}." >&2
			;;
	esac
	return 0
}

# Fatal assert for a MEASUREMENT: call immediately before sampling.
# Fails on a change AND on "cannot tell" — a measurement that cannot name
# its subject is not evidence, which is the whole lesson here.
xpf_assert_cluster_build_unchanged() {
	local rc=0
	xpf_cluster_build_diff || rc=$?
	case "$rc" in
		0) return 0 ;;
		1)
			echo "[cluster] ABORT: the xpfd build changed under this cell (see above)." >&2
			echo "  Refusing to measure — the result would describe a different binary." >&2
			return 1
			;;
		*)
			echo "[cluster] ABORT: cannot establish which xpfd build is running." >&2
			echo "  Refusing to measure — an unattributable measurement is not evidence." >&2
			return 1
			;;
	esac
}
