#!/usr/bin/env bash
#
# #8336 — a reusable crafted-frame screen probe for the shared cluster.
#
# WHY THIS EXISTS. #8298 was a live security bypass whose cluster reproduction
# was not achievable with the obvious tooling. Two attempts came back VOID, for
# reasons that had nothing to do with the fix and everything to do with the
# instrument. This script is those two attempts turned into a procedure so the
# next screen finding is demonstrable rather than argued.
#
# THE PROCEDURE, and every step is one of the traps:
#
#   1. ARM a screen profile. `stage_screen_check` is gated on
#      `has_screen_state()` and the loss userspace cluster carries no
#      `security screen` config, so without this the whole stage
#      short-circuits and the run is green for reasons unrelated to the change.
#   2. Send a WITNESS frame before the subject: something crafted to trip a
#      per-reason screen, whose counter moving proves the path is live.
#   3. Take the aggregate subject baseline after the witness, because the
#      aggregate includes its drop. Without a witness, a flat aggregate cannot
#      distinguish "arrived and was permitted" from "never arrived", and that
#      ambiguity is what made both earlier attempts unreadable.
#   4. DISARM, and verify on BOTH nodes. The cluster is shared and config syncs
#      to the peer, so a profile left bound changes the environment for every
#      other lane.
#
# The verdict layer is `screen-probe-lib.sh`, hermetically tested by
# `screen-probe-selftest.sh` (`make test-screen-probe-lib`). The decision --
# in particular that a flat witness is VOID rather than a pass -- lives there
# precisely so it can be tested without a cluster.
#
# USAGE
#   ./test/incus/screen-probe.sh <subject-send-cmd> <witness-send-cmd>
#
# Both commands are run on the LAN host and are expected to emit their frames.
# They are supplied by the caller because the crafted frame IS the experiment;
# this script owns the arming, sampling, witnessing and cleanup around it.
#
# EXIT STATUS: 0 only when the witness was live and the subject was DROPPED
# with both nodes left clean — rc0 is a green DROP gate and nothing else.
# 1 PASSED (subject not dropped; read the printed verdict), 2 VOID,
# 3 the shared cluster was left armed, 4 a broken decision layer (#12911).
#
# This script takes the shared-cluster lock via cluster-cell.sh, like every
# other destructive or config-mutating target. NEVER run it outside the lock:
# it commits config to both nodes.

set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=screen-probe-lib.sh
source ./screen-probe-lib.sh
# #12911: the header has always promised the shared-cluster lock, but the
# body never took it — a live probe commits screen config to BOTH nodes, so
# it can collide with another lane's deploy or smoke. Enter the #1875 cell
# like every other config-mutating target: a standalone run re-execs through
# with-cluster.sh and QUEUES behind a held lock; a run already inside a cell
# proceeds lock-free (cells nest).
# shellcheck source=cluster-cell.sh
source ./cluster-cell.sh
xpf_enter_destructive_cluster_cell "screen-probe $*" "$0" "$@"
# shellcheck source=cluster-env.sh
source ./cluster-env.sh
# shellcheck source=cos-apply-lib.sh
source ./cos-apply-lib.sh

SUBJECT_CMD="${1:?usage: screen-probe.sh <subject-send-cmd> <witness-send-cmd>}"
WITNESS_CMD="${2:?usage: screen-probe.sh <subject-send-cmd> <witness-send-cmd>}"
PROFILE="${SCREEN_PROBE_PROFILE:-probe8336}"

metrics() {
	# The extractor lives in the lib and is label-aware (#12910): the
	# per-reason family is exported ONLY as labeled series, which an exact
	# `$1 == m` awk match can never see — that shape made every witness
	# sample empty and every live verdict VOID. Prints the family value
	# (summed across label sets) or nothing. The subject stays the
	# aggregate, per trap 2.
	incus exec "$FW0" -- curl -sf --max-time 5 \
		http://127.0.0.1:8080/metrics 2>/dev/null \
		| screen_probe_extract_metric "$1"
}

# arm commits the screen profile and VERIFIES the commit from the CLI
# TRANSCRIPT, not from the exit status.
#
# #6440: the piped-stdin CLI is a REPL. It prints "error: ..." for a failed
# command and still exits 0, so `if ! incus exec ... <<EOF` cannot fire. The
# first version of this script gated on the exit status, which meant a failed
# arm set `armed_state="armed"` and the probe then measured an UNARMED box
# while reporting a verdict — trap 1 wearing this script's own clothes, since
# trap 1 is precisely "the screen stage short-circuits and the run is green for
# reasons unrelated to the change".
#
# Caught by `TestEveryConfigCommittingSmokeUsesTheMarkerGate_6936`, which scans
# every config-committing smoke script for this gate. The guard lives in
# cmd/cli and the script is shell, which is exactly why it was missed: a guard
# can live in a package the change never touched.
arm() {
	printf 'arming screen profile %s on %s\n' "$PROFILE" "$FW0" >&2
	local transcript
	transcript="$(mktemp)"
	incus exec "$FW0" -- /usr/local/bin/cli >"$transcript" 2>&1 <<-EOF || true
	configure
	set security screen ids-option $PROFILE ip tear-drop
	set security zones security-zone lan screen $PROFILE
	commit
	exit
	EOF
	if ! cos_require_markers "screen-probe arm" "$transcript" \
		"$COS_MARKER_COMMIT"; then
		rm -f "$transcript"
		return 1
	fi
	rm -f "$transcript"
}

# disarm is best-effort by design -- it runs from an EXIT trap, including after
# a failure -- but it still verifies the transcript, because a disarm that
# silently failed leaves the SHARED cluster armed for every other lane. The
# verdict goes to the cleanup check at the end rather than aborting here.
disarm() {
	printf 'disarming screen profile %s\n' "$PROFILE" >&2
	local transcript
	transcript="$(mktemp)"
	incus exec "$FW0" -- /usr/local/bin/cli >"$transcript" 2>&1 <<-EOF || true
	configure
	delete security zones security-zone lan screen
	delete security screen ids-option $PROFILE
	commit
	exit
	EOF
	if ! cos_require_markers "screen-probe disarm" "$transcript" \
		"$COS_MARKER_COMMIT"; then
		printf 'screen-probe: DISARM did not commit — the shared cluster may still be armed\n' >&2
	fi
	rm -f "$transcript"
}

count_profile_on() {
	local config
	config="$(incus exec "$1" -- /usr/local/bin/cli -c \
		"show configuration | display set" 2>/dev/null)" || return 1
	printf '%s\n' "$config" \
		| { grep -Fc -- "$PROFILE" || true; } | tr -dc '0-9' | head -c 8
}

# Disarm on ANY exit, including a failure mid-probe. A shared cluster left
# armed is the worst outcome here -- worse than a failed measurement, because
# it silently changes what every other lane measures.
trap disarm EXIT

armed_state="not-armed"
if arm; then
	armed_state="armed"
fi

witness_before="$(metrics xpf_screen_drops_by_reason_total || true)"

printf 'sending witness frame\n' >&2
eval "$WITNESS_CMD" || true

# Let the witness reach and update the dataplane counters before sampling.
sleep 2

witness_after="$(metrics xpf_screen_drops_by_reason_total || true)"
subject_before="$(metrics xpf_screen_drops_total || true)"

printf 'sending subject frame\n' >&2
eval "$SUBJECT_CMD" || true
sleep 2

subject_after="$(metrics xpf_screen_drops_total || true)"

verdict="$(screen_probe_verdict "$armed_state" \
	"$witness_before" "$witness_after" "$subject_before" "$subject_after")"
printf '\nSCREEN PROBE: %s\n' "$verdict"

disarm
trap - EXIT
cleanup="$(screen_probe_disarm_verdict \
	"$(count_profile_on "$FW0")" "$(count_profile_on "$FW1")")"
printf 'SCREEN PROBE CLEANUP: %s\n' "$cleanup"

# The process contract (#12911), decided by the lib so it is testable
# without a cluster — `screen_probe_exit_status`:
#   0   DROPPED and both nodes clean: the only green. rc0 means the witness
#       was live AND the subject was dropped, the sole reading an
#       exit-code-only caller may take as a passed DROP gate.
#   1   PASSED: the subject REACHED the screen and was NOT dropped — for an
#       instrument whose subject is a frame that should be screened, that is
#       the failed finding. Read the printed verdict for the diagnostic.
#   2   VOID: the measurement did not happen; nothing was learned.
#   3   cleanup FAIL: the shared cluster was left armed, which is worse than
#       any measurement outcome — so it outranks the verdict, and VOID's
#       exit no longer masks it.
#   4   an unrecognised verdict or cleanup: the decision layer is broken;
#       fail closed.
rc=0
screen_probe_exit_status "$verdict" "$cleanup" || rc=$?
exit "$rc"
