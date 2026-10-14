#!/usr/bin/env bash
# Shared CLI-transcript verification helpers for the xpf CoS apply path
# (#6440).
#
# WHY THIS EXISTS
#
# `apply-cos-config.sh` drives the Junos-style CLI by piping a heredoc into
# `/usr/local/sbin/cli`:
#
#     if ! incus exec "$TARGET" -- /usr/local/sbin/cli <<EOF
#     configure
#     delete class-of-service
#     load merge /tmp/cos-iperf-sets.set
#     commit check
#     ...
#
# and gated each phase on that command's EXIT STATUS. That gate is
# structurally unable to detect a failure, because the stdin form of the CLI
# is a REPL, not a batch runner. Its read loop (cmd/cli/main.go) is:
#
#     err = c.dispatch(line)
#     if err != nil {
#         if err == errExit { break }
#         fmt.Fprintf(os.Stderr, "error: %v\n", err)   // print and CONTINUE
#     }
#
# A failed `load merge` / `commit check` / `commit` prints one `error: ...`
# line to stderr, the loop moves to the NEXT heredoc line, and `main` returns
# normally — process exit status 0. (`cli -c "<one command>"` is the opposite:
# that path DOES `os.Exit(1)` on a dispatch error. Only the piped-stdin form
# swallows.)
#
# The consequence #6440 reported: a `load merge` that failed left a candidate
# holding ONLY the script's `delete class-of-service ...` lines. Deleting is
# perfectly valid, so `commit check` passed and `commit` committed the deletes
# — wiping CoS instead of re-applying it. Neither the phase-1 nor the phase-2
# gate could fire, so the first thing that noticed anything was the phase-3
# output grep, which reported the MISLEADING "no shaper/scheduler binding"
# and exited 6. Every CoS-dependent measurement taken after such a run was
# silently taken against un-applied config.
#
# THE GATE
#
# Instead of trusting the exit status, assert the CLI's own SUCCESS MARKERS
# are present in the captured transcript. Each config verb prints a distinct
# line to stdout only on success (cmd/cli/main.go, cmd/cli/shared.go):
#
#     load merge      -> "load merge complete"
#     commit check    -> "configuration check succeeds"
#     commit          -> "commit complete" (or "commit complete: <summary>")
#     rollback N      -> "configuration rolled back"
#
# On failure the marker is NOT printed and an `error: ...` line appears
# instead. Asserting the positive marker is deliberately preferred over
# scanning for `error:`: the script's own delete list is idempotent by design
# and its `delete <path>` lines legitimately error with a path-not-found on a
# fresh post-deploy box (config.ConfigTree.DeletePath returns ErrPathNotFound;
# see pkg/config/event_options_4423_test.go). Those benign errors must not
# fail the apply, and they do not disturb the success markers.
#
# The Go-side contract these markers form is pinned by
# cmd/cli/cos_apply_markers_6440_test.go, so a reworded CLI cannot silently
# un-arm this gate.
#
# These helpers depend on nothing but bash + grep so the self-test
# (cos-apply-lib-selftest.sh, `make test-cos-apply-lib`) is hermetic.

# The CLI success markers this gate keys on. Each is matched ANCHORED to the
# start of a line, so a marker appearing inside an error/warning message body
# cannot satisfy the assertion. Keep in sync with
# cmd/cli/cos_apply_markers_6440_test.go.
# shellcheck disable=SC2034  # consumed by apply-cos-config.sh, which sources this file
COS_MARKER_LOAD_MERGE="load merge complete"
# shellcheck disable=SC2034  # consumed by apply-cos-config.sh, which sources this file
COS_MARKER_COMMIT_CHECK="configuration check succeeds"
COS_MARKER_COMMIT="commit complete"
COS_MARKER_ROLLBACK="configuration rolled back"

# cos_transcript_has_marker <transcript-file> <marker>
#
# True when <marker> appears at the START of some line of the transcript.
# Line-anchored on purpose: `commit complete` must match both the bare form
# and `commit complete: <summary>`, but must NOT match a line such as
# `error: commit failed: ... commit complete ...`.
cos_transcript_has_marker() {
	local transcript="$1" marker="$2"
	[[ -f "$transcript" ]] || return 1
	grep -q "^${marker}" "$transcript"
}

# cos_require_markers <label> <transcript-file> <marker>...
#
# Assert every supplied marker is present in the transcript. Returns 0 when
# all are found. On the first miss it reports WHICH marker was missing (that
# names the verb that actually failed, rather than blaming a downstream
# symptom) plus the CLI transcript, and returns 1.
#
# Callers turn that 1 into the phase-appropriate exit code + rollback.
cos_require_markers() {
	local label="$1" transcript="$2"
	shift 2
	local marker missing=0
	for marker in "$@"; do
		if ! cos_transcript_has_marker "$transcript" "$marker"; then
			echo "error: ${label}: the CLI never reported \"${marker}\"" >&2
			missing=1
		fi
	done
	if [[ "$missing" -ne 0 ]]; then
		echo "error: ${label}: a command inside the CLI session FAILED." >&2
		echo "  The piped-stdin CLI is a REPL: it prints 'error: ...' for a failed" >&2
		echo "  command, continues to the next line, and still exits 0 — so the" >&2
		echo "  session's exit status cannot be trusted (#6440)." >&2
		echo "---- cli transcript ----" >&2
		cat "$transcript" >&2
		echo "---- end cli transcript ----" >&2
		return 1
	fi
	return 0
}

# cos_wait_daemon_ready <target> [timeout-seconds]
#
# Block until xpfd's gRPC endpoint answers on <target>, or the timeout
# expires. Returns 0 when ready, 1 on timeout.
#
# `apply-cos-config.sh` is normally run right after `make cluster-deploy`,
# which restarts xpfd. #6440 recorded a run whose commit-check failed with
# connection-refused because the daemon's gRPC listener was not up yet —
# there was no readiness wait between deploy and the first CLI call.
#
# The probe uses `cli -c`, NOT the piped-stdin form: the `-c` path exits
# non-zero both when xpfd is unreachable (the GetStatus reachability probe)
# and when the command itself fails, so its exit status is meaningful.
cos_wait_daemon_ready() {
	local target="$1" timeout="${2:-60}"
	local waited=0
	while [[ "$waited" -lt "$timeout" ]]; do
		if incus_run exec "$target" -- /usr/local/sbin/cli -c "show system uptime" \
			>/dev/null 2>&1; then
			return 0
		fi
		sleep 2
		waited=$((waited + 2))
	done
	return 1
}

# cos_rollback_one <target>
#
# Run `rollback 1 | commit` on <target> and VERIFY it actually landed.
# Returns 0 only when the CLI reported BOTH "configuration rolled back" and
# "commit complete".
#
# Every rollback site in apply-cos-config.sh previously ran this as
# `... <<'EOF' || true` and then announced "live state reverted" from the
# `then` branch of an `if` on the session's exit status — which, being the
# piped-stdin REPL, is 0 whether or not the rollback worked. So the script
# could print a clean "live state reverted" over a rollback that never
# happened, leaving the cluster on the half-applied config the caller
# believed had been undone. #6440 observed exactly that reassurance.
cos_rollback_one() {
	local target="$1"
	local out
	out=$(mktemp)
	incus_run exec "$target" -- /usr/local/sbin/cli >"$out" 2>&1 <<'CLIEOF' || true
configure
rollback 1
commit
exit
quit
CLIEOF
	if cos_require_markers "rollback 1 | commit on $target" "$out" \
		"$COS_MARKER_ROLLBACK" "$COS_MARKER_COMMIT"; then
		echo "rollback 1 committed — live state reverted (verified)" >&2
		rm -f "$out"
		return 0
	fi
	echo "WARN: rollback commit did NOT land — MANUAL INTERVENTION REQUIRED" >&2
	rm -f "$out"
	return 1
}

# ===========================================================================
# #13070 (D10-15): the canonical 12-port CoS schedule, in ONE place.
#
# The port -> (queue, forwarding-class, filter-term, shaper-rate) grid below
# is the fixture test/incus/cos-iperf-config.set, spelled out for bash. It
# used to be copy-pasted into fairness-harness.sh, fairness-cos-class-sweep.sh,
# cos-simul-load-smoke.sh, cos-gate1-small-four-alone.sh, step1-capture.sh,
# step1-classify.sh, cos_be_contention_validate.py and the Python heredocs
# inside those scripts — eight independent tables that drifted apart
# (D10-08's retired 4-port tables in step1-*.sh are what drift looks like).
# Scripts now source these helpers instead of restating the grid.
#
# The binding to the fixture is ENFORCED, not assumed: test_cos_apply_lib.py
# parses cos-iperf-config.set and asserts every one of these helpers agrees
# with every term 0..11 on both port families, and cos_port_grid_test.py pins
# the consumers' wiring to this file. A change to the fixture without the
# matching change here reds `make test-incus-lib`.
#
# Semantics:
#   queue     the `forwarding-classes queue <n>` id (also the term id in the
#             canonical fixture, but they are distinct concepts — asserted
#             separately against the fixture).
#   rate_bps  the aggregate cap a sender on this port can ever reach: the
#             scheduler `transmit-rate` for exact classes, the interface
#             `shaping-rate` (25g) for the two non-exact root classes
#             (best-effort 5200/6200 and iperf-uncapped 5211/6211). Same
#             rule mouse_latency_orchestrate.parse_cos_class_caps applies.
#   unknown port -> exit 1 with no output: callers treat an unmapped port as
#             a misconfiguration, never as a default (#4241 V-11 doctrine).
#
# COS_SCHEDULE_PORTS is the declaration order of the grid (queue order).
# Consumers select subsets by slicing THIS array, never by re-listing ports:
#   shaped/priority classes 5201..5211 -> "${COS_SCHEDULE_PORTS[@]:1}"
#   gate1 small four         5201..5204 -> "${COS_SCHEDULE_PORTS[@]:1:4}"
# shellcheck disable=SC2034  # consumed by scripts that source this file
COS_SCHEDULE_PORTS=(5200 5201 5202 5203 5204 5205 5206 5207 5208 5209 5210 5211)

cos_port_to_class() {
	case "$1" in
		5200|6200) printf 'best-effort\n' ;;
		5201|6201) printf 'iperf-100m\n' ;;
		5202|6202) printf 'iperf-1g\n' ;;
		5203|6203) printf 'iperf-3g\n' ;;
		5204|6204) printf 'iperf-6g\n' ;;
		5205|6205) printf 'iperf-9g\n' ;;
		5206|6206) printf 'iperf-12g\n' ;;
		5207|6207) printf 'iperf-15g\n' ;;
		5208|6208) printf 'iperf-18g\n' ;;
		5209|6209) printf 'iperf-21g\n' ;;
		5210|6210) printf 'iperf-24g\n' ;;
		5211|6211) printf 'iperf-uncapped\n' ;;
		*) return 1 ;;
	esac
}

cos_port_to_queue() {
	case "$1" in
		5200|6200) printf '0\n' ;;
		5201|6201) printf '1\n' ;;
		5202|6202) printf '2\n' ;;
		5203|6203) printf '3\n' ;;
		5204|6204) printf '4\n' ;;
		5205|6205) printf '5\n' ;;
		5206|6206) printf '6\n' ;;
		5207|6207) printf '7\n' ;;
		5208|6208) printf '8\n' ;;
		5209|6209) printf '9\n' ;;
		5210|6210) printf '10\n' ;;
		5211|6211) printf '11\n' ;;
		*) return 1 ;;
	esac
}

# Filter term id in the `bandwidth-output` filter. Distinct from the queue id
# even though the canonical fixture numbers them identically — step1-capture's
# I10 counter check reads THIS id, and conflating the two is how D10-08's
# retired table silently mismatched term counters.
cos_port_to_term() {
	case "$1" in
		5200|6200) printf '0\n' ;;
		5201|6201) printf '1\n' ;;
		5202|6202) printf '2\n' ;;
		5203|6203) printf '3\n' ;;
		5204|6204) printf '4\n' ;;
		5205|6205) printf '5\n' ;;
		5206|6206) printf '6\n' ;;
		5207|6207) printf '7\n' ;;
		5208|6208) printf '8\n' ;;
		5209|6209) printf '9\n' ;;
		5210|6210) printf '10\n' ;;
		5211|6211) printf '11\n' ;;
		*) return 1 ;;
	esac
}

cos_port_to_rate_bps() {
	case "$1" in
		5200|6200) printf '25000000000\n' ;;
		5201|6201) printf '100000000\n' ;;
		5202|6202) printf '1000000000\n' ;;
		5203|6203) printf '3000000000\n' ;;
		5204|6204) printf '6000000000\n' ;;
		5205|6205) printf '9000000000\n' ;;
		5206|6206) printf '12000000000\n' ;;
		5207|6207) printf '15000000000\n' ;;
		5208|6208) printf '18000000000\n' ;;
		5209|6209) printf '21000000000\n' ;;
		5210|6210) printf '24000000000\n' ;;
		5211|6211) printf '25000000000\n' ;;
		*) return 1 ;;
	esac
}

# True (rc 0) when the port's class is scheduled `transmit-rate exact`.
# rc 1 = known non-exact root class; rc 2 = not a canonical port at all.
cos_port_is_exact() {
	case "$1" in
		5201|6201|5202|6202|5203|6203|5204|6204|5205|6205|5206|6206|5207|6207|5208|6208|5209|6209|5210|6210)
			return 0 ;;
		5200|6200|5211|6211)
			return 1 ;;
		*)
			return 2 ;;
	esac
}

# ===========================================================================
# #13070 (D10-15): the incus CLI wrappers, in ONE place.
#
# Every harness used to roll its own `sg incus-admin -c "incus ..."` with its
# own quoting (or none — `sg ... -c "incus $*"` collapses argv across word
# boundaries) and its own active-primary heuristic. These are the shared
# implementations; the group-membership decision and the %q-safe re-quoting
# come from test-mouse-latency.sh's R1 MED 1 fix, which is the battle-tested
# one. Both fall back to plain `incus` when the group/sg path is unavailable,
# preserving the direct-access behavior scripts without any sg handling had.
#
# INCUS_FORCE_SG=1 forces the sg path even for incus-admin members, for
# harnesses whose operator contract is "always through sg" (e.g.
# cos-be-contention-harness.sh's USE_SG_INCUS_ADMIN=1 default).

# Absolute directory of this file, for sibling lookups (cluster_status_parse.py
# beside it). Set at source time so consumers never depend on the caller's cwd.
COS_APPLY_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

incus_run() {
	if [[ "${INCUS_FORCE_SG:-0}" != "1" ]] \
		&& id -nG "$USER" 2>/dev/null | grep -qw incus-admin; then
		incus "$@"
		return
	fi
	if command -v sg >/dev/null && getent group incus-admin >/dev/null 2>&1; then
		local quoted
		quoted=$(printf '%q ' "$@")
		sg incus-admin -c "incus ${quoted}"
		return
	fi
	incus "$@"
}

# incus_exec <target> <argv...>: `incus exec <target> -- <argv>`.
#
# A bare <target> (no `remote:` prefix) is qualified with ${INCUS_REMOTE} when
# that variable is set, so rep scripts can address nodes by name the way
# test-mouse-latency.sh always did while remote-qualified callers are passed
# through untouched.
incus_exec() {
	local target="$1"
	shift
	if [[ "$target" != *:* && -n "${INCUS_REMOTE:-}" ]]; then
		target="${INCUS_REMOTE}:${target}"
	fi
	incus_run exec "$target" -- "$@"
}

# incus_exec_shell <target> <command-string>: the `bash -lc` form the
# run_incus() implementations in userspace-perf-compare.sh and
# cos-be-contention-harness.sh used, for call sites that carry pipes and
# redirections inside the guest command.
incus_exec_shell() {
	local target="$1"
	local cmd="$2"
	incus_exec "$target" bash -lc "$cmd"
}

# detect_active_primary <vm0> <vm1>
#
# Print whichever of the two nodes currently holds RG0 primary, querying
# <vm0>'s control plane (`cli -c "show chassis cluster status"`, parsed by
# cluster_status_parse.py — the same parser pkg/cluster's output format is
# pinned against). Prints <vm0> when the status cannot be fetched or parsed:
# a post-transition snapshot must FOLLOW primary (test-mouse-latency.sh's
# R1 MED 2 doctrine), and an unparseable status falls back to the configured
# primary exactly as that fix specified, rather than aborting the rep.
#
# This is the CONTROL-plane answer. cos-be-contention-harness.sh and
# userspace-perf-compare.sh deliberately keep their own data-plane
# `detect_active_fw` (statistics + `Forwarding armed` greps with hard-fail
# or fallback chains): they need "the node actually forwarding", which is a
# different question than "RG0 leader", and their fail doctrines differ on
# purpose. Do not merge them into this helper.
detect_active_primary() {
	local vm0="$1"
	local vm1="$2"
	local out
	out=$(incus_exec "$vm0" cli -c "show chassis cluster status" 2>/dev/null) || out=""
	local node
	node=$(printf '%s' "$out" | COS_VM0="$vm0" COS_VM1="$vm1" python3 -c '
import os
import sys
sys.path.insert(0, "'"${COS_APPLY_LIB_DIR}"'")
from cluster_status_parse import parse_cluster_status
vm = {"node0": os.environ["COS_VM0"], "node1": os.environ["COS_VM1"]}
for rg, n, st in parse_cluster_status(sys.stdin.read()):
    if rg == 0 and st == "primary":
        print(vm.get(f"node{n}", ""))
        break
') || node=""
	if [[ -z "$node" ]]; then
		node="$vm0"
	fi
	printf '%s\n' "$node"
}
