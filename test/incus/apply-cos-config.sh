#!/usr/bin/env bash
#
# Re-apply a CoS iperf test config to a cluster VM after a deploy
# that wiped it. Usage:
#
#   ./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0
#   ./test/incus/apply-cos-config.sh --symmetric loss:xpf-userspace-fw0
#   ./test/incus/apply-cos-config.sh --surplus-sharing loss:xpf-userspace-fw0
#   COS_EQUAL_FLOW=1 ./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0
#   COS_EQUAL_FLOW=1 COS_EQUAL_FLOW_POLICY=mean \
#       ./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0
#   ./test/incus/apply-cos-config.sh                     # defaults to xpf-userspace-fw0
#
# COS_EQUAL_FLOW=1 (#1831, follow-up to #1766/#1745) opts every
# transmit-rate-exact scheduler in the selected fixture into
# `equal-flow-enforcement` (#1304) by appending the set lines to the
# candidate — same injection pattern as --surplus-sharing. Default
# (unset/0) leaves the fixture untouched. Mutually exclusive with
# --surplus-sharing: the compiler rejects a scheduler with both knobs.
#
# COS_EQUAL_FLOW_POLICY=<slowest|mean|ideal-share> (#1746) additionally
# sets `equal-flow-target-policy <value>` on every injected scheduler.
# Requires COS_EQUAL_FLOW=1 (the policy is inert without enforcement).
# Unset leaves the policy line out entirely — the byte-unchanged
# `slowest` default.
#
# Only the RG0 primary needs the config applied — it replicates to the
# secondary via config sync. Run against the primary.
#
# Atomic design (round-3 finding #3 HIGH):
#
# Earlier revisions ran the destructive `delete class-of-service` etc.
# in a SEPARATE commit transaction from the reapply `set` lines. If the
# second commit failed (syntax drift, validation error, daemon unhappy)
# the cluster was left in a post-delete "no-CoS" state with no rollback,
# which silently contaminated the subsequent capture cells.
#
# The fix: merge deletes and sets into ONE candidate config, run
# `commit check` first, and only if check passes do we `commit`. Either
# ALL changes apply (delete + set atomic) or NONE apply (candidate
# discarded on `rollback`, live config unchanged). Post-commit we run
# `show class-of-service interface` and verify that shaper output is
# present; if verification fails we fall back to `rollback 1 | commit`
# which restores the previous good config.
#
set -euo pipefail

# #1875: this script commits config on the SHARED loss userspace
# cluster — serialize against other agents. Inside a with-cluster.sh
# cell (valid marker from a live ancestor holder) it runs directly;
# standalone it re-execs through with-cluster.sh, which blocks with a
# named-holder report until the cluster is ours.
_LOCK_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=cluster-lock.sh
source "${_LOCK_SCRIPT_DIR}/cluster-lock.sh"
# #6440: CLI-transcript success-marker gate. The piped-stdin CLI is a REPL
# that prints "error: ..." for a failed command, continues, and still exits
# 0 — so every phase below must verify the CLI's own success markers rather
# than the session's exit status.
# shellcheck source=cos-apply-lib.sh
source "${_LOCK_SCRIPT_DIR}/cos-apply-lib.sh"
if ! xpf_cluster_lock_held; then
    exec "${_LOCK_SCRIPT_DIR}/with-cluster.sh" "apply-cos-config $*" \
        -- "${_LOCK_SCRIPT_DIR}/apply-cos-config.sh" "$@"
fi

# #929 compatibility: --same-class still selects
# cos-iperf-same-class.set for older callers. That fixture mirrors the
# default 520x/620x map and also preserves the legacy destination-port
# 7 -> iperf-1g same-class echo override. #1250: --symmetric selects
# cos-iperf-symmetric.set, which also shapes reverse iperf3 -R and
# echo replies on reth1 unit 0 using source-port terms (#15260:
# reth1, not the dash-form ge-0-0-1 member name). Flags must be
# parsed BEFORE the positional TARGET argument so they are not silently
# treated as hostnames.
SAME_CLASS=0
SYMMETRIC=0
SURPLUS_SHARING=0
while [[ "${1:-}" == --* ]]; do
    case "$1" in
        --same-class) SAME_CLASS=1; shift ;;
        --symmetric) SYMMETRIC=1; shift ;;
        --surplus-sharing) SURPLUS_SHARING=1; shift ;;
        --) shift; break ;;
        *) echo "unknown flag: $1" >&2; exit 2 ;;
    esac
done

if [[ "$SAME_CLASS" -eq 1 && "$SYMMETRIC" -eq 1 ]]; then
	echo "error: --same-class and --symmetric select different fixtures; use one at a time" >&2
	exit 2
fi

# #1831: opt-in equal-flow-enforcement injector. Env var (not a flag)
# so harness callers can layer it onto any fixture selection without
# touching positional args. Normalized to 0/1; anything other than
# literal "1" means off.
COS_EQUAL_FLOW="${COS_EQUAL_FLOW:-0}"
if [[ "$COS_EQUAL_FLOW" != "1" ]]; then
	COS_EQUAL_FLOW=0
fi
if [[ "$COS_EQUAL_FLOW" -eq 1 && "$SURPLUS_SHARING" -eq 1 ]]; then
	echo "error: COS_EQUAL_FLOW=1 and --surplus-sharing are mutually exclusive (the compiler rejects a scheduler with both equal-flow-enforcement and surplus-sharing)" >&2
	exit 2
fi
# #1746: optional equal-flow target policy, layered on the enforcement
# injector. Validated here so a typo fails fast instead of failing the
# remote commit check.
COS_EQUAL_FLOW_POLICY="${COS_EQUAL_FLOW_POLICY:-}"
case "$COS_EQUAL_FLOW_POLICY" in
	""|slowest|mean|ideal-share) ;;
	*)
		echo "error: COS_EQUAL_FLOW_POLICY must be one of slowest | mean | ideal-share (got '$COS_EQUAL_FLOW_POLICY')" >&2
		exit 2
		;;
esac
if [[ -n "$COS_EQUAL_FLOW_POLICY" && "$COS_EQUAL_FLOW" -ne 1 ]]; then
	echo "error: COS_EQUAL_FLOW_POLICY requires COS_EQUAL_FLOW=1 (the policy has no effect without equal-flow-enforcement)" >&2
	exit 2
fi

TARGET="${1:-loss:xpf-userspace-fw0}"
# Copilot D.2: shift past TARGET and reject extra positional
# arguments so a typo or duplicated argument fails loudly
# instead of being silently ignored.
[[ $# -le 1 ]] || {
    shift
    echo "unexpected extra arguments: $*" >&2
    exit 2
}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ "$SAME_CLASS" -eq 1 ]]; then
    CONFIG_FILE="${SCRIPT_DIR}/cos-iperf-same-class.set"
elif [[ "$SYMMETRIC" -eq 1 ]]; then
    CONFIG_FILE="${SCRIPT_DIR}/cos-iperf-symmetric.set"
else
    CONFIG_FILE="${SCRIPT_DIR}/cos-iperf-config.set"
fi
REMOTE_SETS="/tmp/cos-iperf-sets.set"

if [[ ! -f "$CONFIG_FILE" ]]; then
	echo "error: cannot find $CONFIG_FILE" >&2
	exit 1
fi

# Strip `delete` / blank / comment lines from the fixture: we inject
# our own curated delete list (below) so the candidate config is
# idempotent against both fresh-post-deploy and already-applied states.
SETS_TMP="$(mktemp)"
trap "rm -f '$SETS_TMP'" EXIT
grep -E '^set ' "$CONFIG_FILE" > "$SETS_TMP"
if [[ "$SURPLUS_SHARING" -eq 1 ]]; then
	awk '
		$1 == "set" &&
		$2 == "class-of-service" &&
		$3 == "schedulers" &&
		$5 == "transmit-rate" &&
		$NF == "exact" {
			exact[$4] = 1
		}
		END {
			for (sched in exact) {
				printf "set class-of-service schedulers %s surplus-sharing\n", sched
			}
		}
	' "$SETS_TMP" | sort >> "$SETS_TMP"
fi
# #1831: equal-flow-enforcement injection mirrors the surplus-sharing
# injector above — one presence-only flag line per transmit-rate-exact
# scheduler (#1304 scopes the knob to positive transmit-rate exact
# schedulers, which is every `transmit-rate ... exact` line in these
# fixtures). The atomic commit-check phase below still validates the
# combined candidate, so an unsupported combination fails before
# anything live changes.
if [[ "$COS_EQUAL_FLOW" -eq 1 ]]; then
	awk -v policy="$COS_EQUAL_FLOW_POLICY" '
		$1 == "set" &&
		$2 == "class-of-service" &&
		$3 == "schedulers" &&
		$5 == "transmit-rate" &&
		$NF == "exact" {
			exact[$4] = 1
		}
		END {
			for (sched in exact) {
				printf "set class-of-service schedulers %s equal-flow-enforcement\n", sched
				# #1746: optional target policy on the same schedulers.
				if (policy != "") {
					printf "set class-of-service schedulers %s equal-flow-target-policy %s\n", sched, policy
				}
			}
		}
	' "$SETS_TMP" | sort >> "$SETS_TMP"
fi

# Re-runs can leave a root-owned temp file behind on the VM. Remove it
# before pushing so repeated strict/surplus diagnostic applies do not
# fail with a stale permission error.
# #13070 (D10-15): shared wrapper (sg fallback for non-incus-admin
# operators), same command shapes as the previous bare `incus` calls.
incus_run exec "$TARGET" -- rm -f "$REMOTE_SETS" >/dev/null 2>&1 || true
incus_run file push --mode 0644 "$SETS_TMP" "${TARGET}/${REMOTE_SETS}" >/dev/null

# Deletes that may or may not exist depending on whether this is a
# fresh apply or a re-apply. Swallowed individually inside the single
# candidate session so "nothing to delete" is not a hard error, while
# a true commit failure still aborts the session.
#
# The `|| true` after each `delete` is bash-side — it suppresses the
# NON-zero exit heredocs leak when the CLI warns, not the commit itself.
# Because this whole block runs inside ONE `configure ... commit`
# session, the commit is still atomic: if `commit` fails, the
# candidate is discarded intact.
#
# IMPORTANT: this script speaks the Junos-style local CLI. `commit
# check` validates the candidate before apply; we invoke it first so a
# syntactically-bad candidate is caught before anything live changes.

# ---- Phase 0: daemon readiness ----
# This script normally runs immediately after a deploy, which restarts xpfd.
# #6440 recorded a run whose commit-check died with connection-refused because
# the gRPC listener was not up yet. Wait for it before touching config.
if ! cos_wait_daemon_ready "$TARGET" "${COS_READY_TIMEOUT:-60}"; then
	echo "error: xpfd on $TARGET did not become reachable within ${COS_READY_TIMEOUT:-60}s" >&2
	echo "no live state changed (nothing was committed)" >&2
	exit 3
fi

# ---- Phase 1: commit check (dry-run validate) ----
CHECK_OUT=$(mktemp)
trap "rm -f '$SETS_TMP' '$CHECK_OUT'" EXIT
if ! incus_run exec "$TARGET" -- /usr/local/sbin/cli > "$CHECK_OUT" 2>&1 <<EOF
configure
delete class-of-service
delete firewall family inet filter bandwidth-output
delete interfaces reth0 unit 80 family inet filter output
delete firewall family inet6 filter bandwidth-output
delete interfaces reth0 unit 80 family inet6 filter output
delete firewall family inet filter bandwidth-output-reverse
delete interfaces reth1 unit 0 family inet filter output
delete firewall family inet6 filter bandwidth-output-reverse
delete interfaces reth1 unit 0 family inet6 filter output
delete interfaces ge-0-0-1 unit 0 family inet filter output
delete interfaces ge-0-0-1 unit 0 family inet6 filter output
load merge ${REMOTE_SETS}
commit check
exit
quit
EOF
then
	echo "error: commit check failed on $TARGET (candidate config is invalid)" >&2
	echo "---- cli output ----" >&2
	cat "$CHECK_OUT" >&2
	echo "---- end cli output ----" >&2
	echo "no live state changed (commit check runs on the candidate only)" >&2
	exit 4
fi
# #6440: the exit status above is NOT sufficient — the piped-stdin CLI exits 0
# even when `load merge` or `commit check` failed. Require BOTH markers: a
# silently-failed load leaves a candidate holding only this script's deletes,
# which is a VALID candidate, so `commit check` would pass and phase 2 would
# commit a CoS wipe.
if ! cos_require_markers "commit check on $TARGET" "$CHECK_OUT" \
	"$COS_MARKER_LOAD_MERGE" "$COS_MARKER_COMMIT_CHECK"; then
	echo "no live state changed (commit check runs on the candidate only)" >&2
	exit 4
fi

# ---- Phase 2: atomic commit ----
# Delete + set are in ONE transaction. If `commit` fails, the
# candidate config is discarded and live state is unchanged —
# specifically the destructive deletes are NOT committed without the
# compensating sets.
APPLY_OUT=$(mktemp)
trap "rm -f '$SETS_TMP' '$CHECK_OUT' '$APPLY_OUT'" EXIT
if ! incus_run exec "$TARGET" -- /usr/local/sbin/cli > "$APPLY_OUT" 2>&1 <<EOF
configure
delete class-of-service
delete firewall family inet filter bandwidth-output
delete interfaces reth0 unit 80 family inet filter output
delete firewall family inet6 filter bandwidth-output
delete interfaces reth0 unit 80 family inet6 filter output
delete firewall family inet filter bandwidth-output-reverse
delete interfaces reth1 unit 0 family inet filter output
delete firewall family inet6 filter bandwidth-output-reverse
delete interfaces reth1 unit 0 family inet6 filter output
delete interfaces ge-0-0-1 unit 0 family inet filter output
delete interfaces ge-0-0-1 unit 0 family inet6 filter output
load merge ${REMOTE_SETS}
commit
exit
quit
EOF
then
	echo "error: commit failed on $TARGET AFTER commit-check passed" >&2
	echo "---- cli output ----" >&2
	cat "$APPLY_OUT" >&2
	echo "---- end cli output ----" >&2
	# commit-check passed but commit itself failed: this is rare
	# (usually a transient daemon / commit-hook issue). The candidate
	# is already discarded by the failed commit, so live state is
	# the pre-apply state. For extra safety try `rollback 1 | commit`
	# to roll forward onto the last good committed config — if the
	# pre-apply state itself was wedged, this will repair it.
	echo "attempting rollback 1 | commit to restore last-good state..." >&2
	cos_rollback_one "$TARGET" || true
	exit 5
fi
# #6440: as in phase 1, the exit status alone proves nothing. Require the
# markers for BOTH verbs that must have landed for CoS to be applied.
if ! cos_require_markers "commit on $TARGET" "$APPLY_OUT" \
	"$COS_MARKER_LOAD_MERGE" "$COS_MARKER_COMMIT"; then
	echo "the CoS apply did NOT land; rolling forward to the last good state..." >&2
	# `|| true` so a failed rollback does not let `set -e` pre-empt the
	# phase-specific exit code below; cos_rollback_one has already reported
	# MANUAL INTERVENTION REQUIRED on that path.
	cos_rollback_one "$TARGET" || true
	exit 5
fi

# ---- Phase 3: post-commit verification ----
# The atomic commit succeeded per the CLI. Now verify CoS is actually
# live via `show class-of-service interface`: we expect at least one
# interface block to show up (reth0 / reth0.80) with a shaper output
# setting. If the output is empty, the commit "succeeded" but CoS is
# not runtime-live — roll back to the previous good state.
VERIFY_OUT=$(mktemp)
trap "rm -f '$SETS_TMP' '$CHECK_OUT' '$APPLY_OUT' '$VERIFY_OUT'" EXIT
# NOTE (#6440): do NOT `|| true` this one. Unlike the piped-stdin heredocs
# above, `cli -c` DOES exit non-zero on a dispatch error or an unreachable
# xpfd, so its status is meaningful. Swallowing it made an unreachable daemon
# produce an error transcript that failed the shaper grep below and exited 6
# blaming a "missing shaper binding" — the misdiagnosis #6440 was filed on.
if ! incus_run exec "$TARGET" -- /usr/local/sbin/cli -c "show class-of-service interface" \
	> "$VERIFY_OUT" 2>&1; then
	echo "error: 'show class-of-service interface' FAILED on $TARGET (the CLI could not run it)" >&2
	echo "---- cli output ----" >&2
	cat "$VERIFY_OUT" >&2
	echo "---- end cli output ----" >&2
	echo "this is a CLI/daemon reachability failure, NOT a CoS binding failure" >&2
	cos_rollback_one "$TARGET" || true
	exit 6
fi
cat "$VERIFY_OUT"

# Look for ANY shaper/scheduler signal. If the show output does not
# mention a shaper/scheduler/output-traffic-control-profile, CoS is
# not effectively applied and we must roll back.
if ! grep -iqE 'shaper|scheduler|traffic-control-profile|output.*traffic' "$VERIFY_OUT"; then
	echo "error: post-commit verification FAILED — 'show class-of-service interface' output shows no shaper/scheduler binding" >&2
	echo "rolling forward with 'rollback 1 | commit' to restore the last good state..." >&2
	cos_rollback_one "$TARGET" || true
	exit 6
fi

# ---- Phase 3.5: oversubscription-policy round-trip verification ----
#
# #1626: PR #1618 shipped the #1614 step-1 wire surface (Junos
# `oversubscription-policy guarantee-rate <X>`) but the
# `cos-iperf-config.set` fixture forgot to enable the knob, so the
# simul-load smoke harness was measuring the default `proportional`
# mode the whole time. This phase guards against the same regression
# class for any future fixture: if the applied fixture contains
# `^set .*oversubscription-policy` lines, the running config tree
# MUST round-trip with EACH such line present after commit.
#
# The check is dynamically gated on fixture content (NOT on
# --same-class / --symmetric flags) so future fixtures that activate
# the knob get verified unchanged, and fixtures that don't are
# silently skipped.
#
# We use `show configuration class-of-service | display set` (the
# flat-set rendering of the config tree) so a literal `grep -Fxq`
# can match each fixture line verbatim. CRLF safety: strip trailing
# \r from the expected line in case the fixture file picks up
# Windows-style line endings on edit.
if grep -qE '^set .*oversubscription-policy' "$CONFIG_FILE"; then
	OVERSUB_OUT=$(mktemp)
	trap "rm -f '$SETS_TMP' '$CHECK_OUT' '$APPLY_OUT' '$VERIFY_OUT' '$OVERSUB_OUT'" EXIT
	if ! incus_run exec "$TARGET" -- /usr/local/sbin/cli -c \
		"show configuration class-of-service | display set" \
		> "$OVERSUB_OUT" 2>&1; then
		echo "error: 'show configuration class-of-service | display set' FAILED on $TARGET" >&2
		cat "$OVERSUB_OUT" >&2
		cos_rollback_one "$TARGET" || true
		exit 7
	fi

	MISSING=0
	while IFS= read -r want; do
		want="${want%$'\r'}"
		if ! grep -Fxq "$want" "$OVERSUB_OUT"; then
			echo "error: fixture line missing from running config:" >&2
			echo "  expected: $want" >&2
			MISSING=1
		fi
	done < <(grep -E '^set .*oversubscription-policy' "$CONFIG_FILE")

	if [[ "$MISSING" -ne 0 ]]; then
		echo "error: Phase-3.5 oversubscription-policy verification FAILED" >&2
		echo "---- show configuration class-of-service | display set ----" >&2
		cat "$OVERSUB_OUT" >&2
		echo "---- end show output ----" >&2
		echo "rolling forward with 'rollback 1 | commit' to restore the last good state..." >&2
		cos_rollback_one "$TARGET" || true
		exit 7
	fi
fi

echo "apply-cos-config: atomic commit + verification OK"
