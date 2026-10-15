#!/usr/bin/env bash
#
# #8336 — self-test for test/incus/screen-probe-lib.sh.
#
# Hermetic: sources the lib and feeds it literal counter samples. No incus, no
# cluster, no network, no crafted frames.
#
# The load-bearing property is TOTALITY plus ORDERING.
#
# Totality, because the defect this class of harness produces is a MISSING
# CELL: two attempts at #8298 produced a flat aggregate that was reported as
# neither a pass nor a failure, and a flat number with no verdict reads as "we
# did not find anything" when the truth was "we did not measure anything".
#
# Ordering, because the VOID checks are not independent. An unarmed profile
# makes the witness meaningless and a flat witness makes the subject
# meaningless, so a layer that evaluated the subject first would report
# "PASSED" -- the frame was not dropped -- for a frame that never arrived.
# That is the exact false finding this issue exists to prevent, and it is why
# several cells below assert which VOID reason is chosen when more than one
# condition holds.

set -uo pipefail
cd "$(dirname "$0")"
# shellcheck source=screen-probe-lib.sh
source ./screen-probe-lib.sh

fails=0
check() {
	local name="$1" want="$2" got="$3"
	if [[ "$got" == "$want"* ]]; then
		printf 'ok   %s\n' "$name"
	else
		printf 'FAIL %s\n     want prefix: %s\n     got:         %s\n' "$name" "$want" "$got"
		fails=$((fails + 1))
	fi
}

# --- the three verdicts, each reachable -----------------------------------

check "a dropped subject with a live witness is DROPPED" DROPPED \
	"$(screen_probe_verdict armed 10 11 100 101)"

check "a flat subject with a live witness is PASSED, a RESULT" PASSED \
	"$(screen_probe_verdict armed 10 11 100 100)"

check "a flat witness is VOID, never PASSED" VOID \
	"$(screen_probe_verdict armed 10 10 100 100)"

# THE CELL THAT MATTERS MOST. Without the witness ordering this input reads
# as "the frame was not dropped" -- a finding -- when nothing arrived at all.
# Both earlier #8298 attempts produced exactly this shape.
got="$(screen_probe_verdict armed 10 10 100 100)"
check "a flat witness AND a flat subject is VOID, not PASSED" VOID "$got"
case "$got" in
	*PASSED*) printf 'FAIL the flat-witness case must not mention PASSED\n'; fails=$((fails + 1));;
esac

# --- trap 1: the unarmed profile ------------------------------------------

check "an unarmed profile is VOID before anything else is read" VOID \
	"$(screen_probe_verdict not-armed 10 11 100 101)"

# ORDERING: armed is checked FIRST. Here the witness is live and the subject
# moved -- every downstream signal says "dropped" -- and the verdict must
# still be VOID, because with no screen configured stage_screen_check never
# ran and whatever dropped the frame was not the code under test.
got="$(screen_probe_verdict "" 10 11 100 101)"
check "an unarmed profile beats a moving subject counter" VOID "$got"
case "$got" in
	*DROPPED*) printf 'FAIL an unarmed run must not report DROPPED\n'; fails=$((fails + 1));;
esac

# --- trap 3: unreadable samples are not zero ------------------------------

check "a missing witness sample is VOID" VOID \
	"$(screen_probe_verdict armed "" 11 100 101)"
check "a non-numeric witness sample is VOID" VOID \
	"$(screen_probe_verdict armed 10 '<html>error</html>' 100 101)"
check "a missing subject sample with a live witness is VOID" VOID \
	"$(screen_probe_verdict armed 10 11 100 "")"

# A counter that went BACKWARDS is a helper restart mid-probe: the two samples
# describe different processes, so the difference is not a drop count. Without
# this the subtraction underflows into a huge positive in some shells, or a
# negative that compares as "no drops" -- either way a fabricated result.
check "a witness counter that went backwards is VOID" VOID \
	"$(screen_probe_verdict armed 10 4 100 101)"
check "a subject counter that went backwards is VOID" VOID \
	"$(screen_probe_verdict armed 10 11 100 4)"

# --- delta helper, directly ------------------------------------------------

check_eq() {
	local name="$1" want="$2" got="$3"
	if [[ "$got" == "$want" ]]; then
		printf 'ok   %s\n' "$name"
	else
		printf 'FAIL %s: want %q got %q\n' "$name" "$want" "$got"
		fails=$((fails + 1))
	fi
}
check_eq "delta of two integers" 7 "$(screen_probe_delta 3 10)"
check_eq "delta of equal integers is 0, not empty" 0 "$(screen_probe_delta 5 5)"
check_eq "delta with a non-numeric before is empty" "" "$(screen_probe_delta x 10)"
check_eq "delta with a non-numeric after is empty" "" "$(screen_probe_delta 3 y)"
check_eq "delta of a backwards counter is empty" "" "$(screen_probe_delta 10 3)"

# The distinction the whole layer rests on: "did not move" and "cannot be
# read" are DIFFERENT, and only the first is a measurement.
if [[ "$(screen_probe_delta 5 5)" == "$(screen_probe_delta x 5)" ]]; then
	printf 'FAIL a flat counter and an unreadable one must not render alike\n'
	fails=$((fails + 1))
else
	printf 'ok   a flat counter and an unreadable one are distinguishable\n'
fi

# --- the disarm check, on a SHARED cluster --------------------------------

check "both nodes clean is PASS" PASS "$(screen_probe_disarm_verdict 0 0)"
check "a leftover on node0 is FAIL" FAIL "$(screen_probe_disarm_verdict 1 0)"
# The cell an aggregate count would fail: config syncs to the peer, so a
# profile can survive on node1 alone. A single summed check reading 0+1 as
# "mostly clean", or a check of node0 only, would pass here.
check "a leftover on node1 ALONE is FAIL" FAIL "$(screen_probe_disarm_verdict 0 1)"
check "an unreadable disarm count is FAIL, not PASS" FAIL "$(screen_probe_disarm_verdict 0 "")"

# --- #12910: the extractor must read labeled series ------------------------
#
# The exporter declares the per-reason witness family ONLY with a `reason`
# label, so every sample line's first field is the metric name WITH its
# label block attached. The live script fed that name to an exact `$1 == m`
# awk test, which can never match: every witness sample came back empty and
# every live verdict was VOID while the counter sat there counting. The
# extractor is label-aware and lives in the lib precisely so this cell can
# exist without a cluster.

PROM_BEFORE='# HELP xpf_screen_drops_total Total packets dropped by screen/IDS checks.
# TYPE xpf_screen_drops_total counter
xpf_screen_drops_total 7
# HELP xpf_screen_drops_by_reason_total Total packets dropped, by reason.
# TYPE xpf_screen_drops_by_reason_total counter
xpf_screen_drops_by_reason_total{reason="tear-drop"} 2
xpf_screen_drops_by_reason_total{reason="syn-flood"} 5
# A LONGER name sharing the prefix must not be summed into either family.
xpf_screen_drops_by_reason_total_bytes 99
'

check_eq "a labeled family is summed across its label sets" 7 \
	"$(printf '%s' "$PROM_BEFORE" | screen_probe_extract_metric xpf_screen_drops_by_reason_total)"
check_eq "an unlabeled family passes through unchanged" 7 \
	"$(printf '%s' "$PROM_BEFORE" | screen_probe_extract_metric xpf_screen_drops_total)"
check_eq "the longer prefix-sharing name is its own family, not part of ours" 99 \
	"$(printf '%s' "$PROM_BEFORE" | screen_probe_extract_metric xpf_screen_drops_by_reason_total_bytes)"
check_eq "an absent family is empty, not 0" "" \
	"$(printf 'xpf_other_total 1\n' | screen_probe_extract_metric xpf_screen_drops_by_reason_total)"
check_eq "a non-integer sample is empty, not a guess" "" \
	"$(printf 'xpf_screen_drops_total 4.2e+01\n' | screen_probe_extract_metric xpf_screen_drops_total)"
check_eq "an empty exposition is empty" "" \
	"$(printf '' | screen_probe_extract_metric xpf_screen_drops_total)"

# The decisive check from the issue: the witness moves both its per-reason
# counter and the aggregate. The live probe takes the aggregate subject
# baseline after the witness, so witness-only movement is a flat subject
# delta; one additional aggregate count means the subject was dropped.

PROM_DROPPED='xpf_screen_drops_total 9
xpf_screen_drops_by_reason_total{reason="tear-drop"} 3
xpf_screen_drops_by_reason_total{reason="syn-flood"} 5
'
PROM_PASSED='xpf_screen_drops_total 8
xpf_screen_drops_by_reason_total{reason="tear-drop"} 3
xpf_screen_drops_by_reason_total{reason="syn-flood"} 5
'

_wb="$(printf '%s' "$PROM_BEFORE" | screen_probe_extract_metric xpf_screen_drops_by_reason_total)"
_wa_d="$(printf '%s' "$PROM_DROPPED" | screen_probe_extract_metric xpf_screen_drops_by_reason_total)"
_wa_p="$(printf '%s' "$PROM_PASSED" | screen_probe_extract_metric xpf_screen_drops_by_reason_total)"
_sb="$(printf '%s' "$PROM_BEFORE" | screen_probe_extract_metric xpf_screen_drops_total)"
_sa_d="$(printf '%s' "$PROM_DROPPED" | screen_probe_extract_metric xpf_screen_drops_total)"
_sa_p="$(printf '%s' "$PROM_PASSED" | screen_probe_extract_metric xpf_screen_drops_total)"

check "a witness-only aggregate increment is PASSED" PASSED \
	"$(screen_probe_verdict armed "$_wb" "$_wa_p" 8 8)"
check "a subject increment after the witness is DROPPED" DROPPED \
	"$(screen_probe_verdict armed "$_wb" "$_wa_d" 8 9)"
check "a labeled witness family that vanishes mid-probe is VOID" VOID \
	"$(screen_probe_verdict armed "$_wb" "" "$_sb" "$_sa_d")"

# --- #12911: the process exit contract --------------------------------------
#
# rc0 belongs to DROPPED-with-clean-cleanup alone. A witnessed PASSED — the
# subject reached the screen and was NOT dropped — is the failed finding for
# an instrument whose subject should be screened, and it used to fall
# through to rc0, where an exit-code-only caller reads it as a green DROP
# gate. A leftover profile on the shared cluster is the worst outcome this
# file knows, so cleanup FAIL outranks every verdict, including VOID (whose
# rc2 used to mask it). Anything unrecognised fails closed.

probe_exit_status() {
	screen_probe_exit_status "$@"
	local rc=$?
	printf '%s' "$rc"
}

check_eq "DROPPED with a clean cleanup is rc0" 0 \
	"$(probe_exit_status "DROPPED moved +1" "PASS removed on both nodes")"
check_eq "a witnessed PASSED is rc1, never a green rc0" 1 \
	"$(probe_exit_status "PASSED not dropped" "PASS removed on both nodes")"
check_eq "VOID is rc2" 2 \
	"$(probe_exit_status "VOID witness unreadable" "PASS removed on both nodes")"
check_eq "a leftover profile is rc3" 3 \
	"$(probe_exit_status "DROPPED moved +1" "FAIL still present")"
check_eq "cleanup FAIL outranks VOID instead of being masked by rc2" 3 \
	"$(probe_exit_status "VOID witness unreadable" "FAIL still present")"
check_eq "cleanup FAIL outranks PASSED" 3 \
	"$(probe_exit_status "PASSED not dropped" "FAIL still present")"
check_eq "an unrecognised verdict fails closed at rc4" 4 \
	"$(probe_exit_status "garbage" "PASS clean")"
check_eq "an unrecognised cleanup fails closed at rc4" 4 \
	"$(probe_exit_status "DROPPED moved +1" "garbage")"
check_eq "an empty verdict fails closed at rc4" 4 "$(probe_exit_status "" "PASS clean")"

# --- #12911: the live script's own wiring, pinned by inspection -------------
#
# The live probe needs a cluster, so its two process-level promises are
# pinned statically, in the same file-level-predicate style as the #6936
# marker scan: the probe takes the shared-cluster lock its header claims,
# before any incus work; and its exit status is decided by the tested
# contract above rather than by hand-rolled code that can regress to a
# PASSED rc0 fall-through. Presence, not absence-of-an-idiom: a correct
# script may legitimately use other shapes elsewhere.

LIVE=./screen-probe.sh
live_body="$(cat "$LIVE")"
if grep -Eq '^[[:space:]]*(source|\.)[[:space:]][^#]*cluster-cell\.sh' <<<"$live_body"; then
	printf 'ok   the live probe sources cluster-cell.sh in its preamble\n'
else
	printf 'FAIL the live probe does not source cluster-cell.sh in its preamble — its header promises the shared-cluster lock (#12911)\n'
	fails=$((fails + 1))
fi
lock_line="$(grep -n 'xpf_enter_destructive_cluster_cell' "$LIVE" | head -1 | cut -d: -f1)"
first_incus="$(awk '!/^[[:space:]]*#/ && /incus exec/ { print NR; exit }' "$LIVE")"
if [[ -n "$lock_line" && -n "$first_incus" ]] && (( lock_line < first_incus )); then
	printf 'ok   the live probe takes the lock (line %s) before its first incus work (line %s)\n' "$lock_line" "$first_incus"
else
	printf 'FAIL the live probe must call xpf_enter_destructive_cluster_cell before any incus work (lock line=%s first incus line=%s) (#12911)\n' \
		"${lock_line:-none}" "${first_incus:-none}"
	fails=$((fails + 1))
fi
if grep -q 'screen_probe_exit_status' "$LIVE"; then
	printf 'ok   the live probe maps its exit status through screen_probe_exit_status\n'
else
	printf 'FAIL the live probe does not use screen_probe_exit_status — its rc contract is untested hand-rolled code (#12911)\n'
	fails=$((fails + 1))
fi
if grep -q 'screen_probe_extract_metric' "$LIVE"; then
	printf 'ok   the live probe extracts metrics through screen_probe_extract_metric\n'
else
	printf 'FAIL the live probe does not use screen_probe_extract_metric — a label-blind extractor made every witness sample empty (#12910)\n'
	fails=$((fails + 1))
fi

# #13128: the live aggregate subject sample must bracket only the subject
# command. The witness itself increments this aggregate, so sampling the
# baseline before the witness falsely calls every witness drop a subject drop.
witness_send_line="$(grep -n 'eval "\$WITNESS_CMD"' "$LIVE" | head -1 | cut -d: -f1)"
witness_sample_line="$(grep -n '^witness_after="$(metrics xpf_screen_drops_by_reason_total' "$LIVE" | head -1 | cut -d: -f1)"
subject_before_line="$(grep -n '^subject_before="$(metrics xpf_screen_drops_total' "$LIVE" | head -1 | cut -d: -f1)"
subject_send_line="$(grep -n 'eval "\$SUBJECT_CMD"' "$LIVE" | head -1 | cut -d: -f1)"
subject_after_line="$(grep -n '^subject_after="$(metrics xpf_screen_drops_total' "$LIVE" | head -1 | cut -d: -f1)"
if [[ -n "$witness_send_line" && -n "$witness_sample_line" &&
	-n "$subject_before_line" && -n "$subject_send_line" && -n "$subject_after_line" ]] &&
	(( witness_send_line < witness_sample_line &&
		witness_sample_line < subject_before_line &&
		subject_before_line < subject_send_line &&
		subject_send_line < subject_after_line )); then
	printf 'ok   the live probe samples aggregate drops after the witness and before the subject\n'
else
	printf 'FAIL the live probe must isolate subject aggregate drops from the witness (witness=%s witness-sample=%s baseline=%s subject=%s after=%s) (#13128)\n' \
		"${witness_send_line:-none}" "${witness_sample_line:-none}" \
		"${subject_before_line:-none}" "${subject_send_line:-none}" \
		"${subject_after_line:-none}"
	fails=$((fails + 1))
fi

# --- totality --------------------------------------------------------------
#
# Every verdict call must produce exactly one line beginning with one of the
# three tokens. A silent return is the failure mode that started this issue.
for args in \
	"armed 10 11 100 101" "armed 10 11 100 100" "armed 10 10 100 100" \
	"not-armed 0 0 0 0" "armed x y z w" "armed 10 11 100 x" \
	" 1 2 3 4" "armed 0 0 0 0" "armed 1 2 3" "armed" ""
do
	# shellcheck disable=SC2086
	out="$(screen_probe_verdict $args)"
	lines="$(printf '%s' "$out" | grep -c . || true)"
	if [[ "$lines" != "1" ]]; then
		printf 'FAIL totality: args=[%s] produced %s lines, want exactly 1\n' "$args" "$lines"
		fails=$((fails + 1))
		continue
	fi
	case "$out" in
		VOID\ *|DROPPED\ *|PASSED\ *) ;;
		*) printf 'FAIL totality: args=[%s] produced an unrecognised verdict: %s\n' "$args" "$out"
		   fails=$((fails + 1));;
	esac
done
if (( fails == 0 )); then
	printf 'ok   totality: every input class yields exactly one recognised verdict\n'
fi

if (( fails > 0 )); then
	printf '\n%d check(s) failed\n' "$fails"
	exit 1
fi
printf '\nall screen-probe-lib checks passed\n'
