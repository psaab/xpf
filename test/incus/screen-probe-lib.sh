#!/usr/bin/env bash
#
# #8336 — the crafted-frame screen probe's ANALYSIS layer.
#
# Extracted from the probe script so the decision is HERMETICALLY TESTABLE,
# exactly as iperf-throughput-lib.sh was extracted for the same reason.
#
# This exists because TWO measurement attempts against #8298 came back VOID,
# both for reusable reasons. Anyone crafting frames at the cluster to exercise
# a screen will hit the same traps and reach for the same wrong counter.
#
# THE THREE TRAPS, and what this layer does about each:
#
#  1. THE STANDARD SMOKE EXERCISES NO SCREEN CODE. `stage_screen_check` is
#     gated on `has_screen_state()` and the loss userspace cluster carries no
#     `security screen` configuration, so `extract_screen_info` is never
#     reached and the whole stage short-circuits. A cluster-deploy plus
#     test-failover against a screen change is green for reasons that have
#     nothing to do with the change. The probe script arms a profile first and
#     disarms after; this layer refuses to render a verdict from a run that
#     did not record the profile as armed.
#
#  2. THE PER-REASON COUNTER CANNOT SEE A PARSE-ERROR DROP. The obvious
#     instrument is `xpf_screen_drops_by_reason_total{reason="teardrop"}`, and
#     it is the wrong one for any drop originating in a parse failure:
#     `extract_screen_info` failing closed yields reason `ip-malformed`, and
#     `ip-malformed`, `syn-cookie` and `icmp-fragment` are surfaced ONLY
#     through the aggregate `xpf_screen_drops_total`. There is no
#     `ip-malformed` label in the per-reason series to sample, so a fail-closed
#     drop is invisible there BY CONSTRUCTION and the zero reads exactly like
#     "nothing happened". This layer takes the AGGREGATE as the subject.
#
#  3. WITHOUT AN ARRIVAL WITNESS A ZERO IS UNREADABLE. A flat aggregate has two
#     indistinguishable causes: the crafted frame never reached the firewall
#     (routing, L2, the host stack, or the NIC discarding a malformed header
#     before AF_XDP), or it arrived and was not dropped -- which is the actual
#     finding. Those are different results and collapsing them is how both
#     earlier attempts produced an unreadable zero.
#
# THE VERDICT IS THEREFORE THREE-VALUED, NOT TWO. The witness is a frame
# crafted to trip a per-reason screen and sent before the subject, so its
# counter moving proves the path is live. The aggregate baseline is sampled
# after that witness, preventing its drop from being attributed to the subject.
# A flat witness means THE MEASUREMENT DID NOT HAPPEN, and that is VOID --
# never a pass and never a failure. The same shape as the counter-witness
# technique in docs/engineering-style.md: pair measurement with proof the
# instrument is connected.
#
# And the verdict is TOTAL: every input class yields exactly one line. The
# defect that produced #6897's sibling lib was not a wrong number, it was NO
# CELL AT ALL for an input class nobody had enumerated.

# screen_probe_delta <before> <after>
#   Print the counter delta, or nothing when either sample is not an integer.
#   An unparseable sample is NOT zero: a scrape that returned an error page, a
#   metric that was absent, and a counter that genuinely did not move all
#   render as "no number here", and treating them alike is how a broken scrape
#   becomes a clean result.
screen_probe_delta() {
	local before="${1-}" after="${2-}"
	[[ "$before" =~ ^[0-9]+$ ]] || return 0
	[[ "$after" =~ ^[0-9]+$ ]] || return 0
	# A counter that went BACKWARDS means the helper restarted mid-probe (the
	# series is process-scoped). That is not a negative drop count; it is a
	# run whose two samples describe different processes.
	if (( after < before )); then
		return 0
	fi
	printf '%s\n' "$(( after - before ))"
}

# screen_probe_extract_metric <metric>  (Prometheus text exposition on stdin)
#   Print the family's value as one integer, summed across every label set,
#   or NOTHING when the family is absent from the exposition or any of its
#   samples is not an integer.
#
#   #12910: the per-reason witness family is exported ONLY as labeled series
#   — xpf_screen_drops_by_reason_total{reason="tear-drop"} 3 — so a sample
#   line's first field is the metric name WITH its label block attached, and
#   the exact `$1 == metric` test the live script used can never match it.
#   Every witness sample came back empty, so every live verdict was VOID
#   while the counter counted: a permanently unreadable instrument, wearing
#   the clothes of a fail-closed one.
#
#   Why SUM the label sets instead of selecting one label: the witness only
#   needs "some per-reason screen counter moved" to prove the path is live,
#   and forcing the caller to name the label would rebuild trap 2 one level
#   down — the wrong label reads exactly like a dead path. The boundary
#   match (exact name, or name immediately followed by `{`) keeps the
#   aggregate xpf_screen_drops_total, the per-reason family and any longer
#   name from standing in for one another.
#
#   Fail-closed on shape, in the same direction as screen_probe_delta: an
#   absent family and an unparseable one both print nothing. Neither is 0.
screen_probe_extract_metric() {
	local metric="${1-}"
	awk -v m="$metric" '
		$1 ~ /^#/ { next }
		index($1, m) == 1 && (length($1) == length(m) || substr($1, length(m) + 1, 1) == "{") {
			if ($2 !~ /^[0-9]+$/) { bad = 1; next }
			sum += $2
			found = 1
		}
		END { if (!bad && found) print sum }
	'
}

# screen_probe_verdict <armed> <witness_before> <witness_after> <subject_before> <subject_after>
#   Print exactly one verdict line:
#     "VOID <message>"    the measurement did not happen; nothing was learned
#     "DROPPED <message>" the subject frame was dropped by a screen
#     "PASSED <message>"  the subject frame arrived and was NOT dropped
#
#   VOID is checked FIRST and in dependency order: an unarmed profile makes the
#   witness meaningless, and a flat witness makes the subject meaningless. A
#   layer that checked the subject first would report "not dropped" for a frame
#   that never arrived -- which is precisely the reading that made both earlier
#   attempts look like findings.
screen_probe_verdict() {
	# Defaulted, not required. An unquoted empty variable at a call site
	# word-splits away and the call arrives with FEWER arguments than the
	# signature -- under `set -u` that aborts the function and it emits NOTHING.
	# A verdict layer that can emit nothing is the missing-cell defect this file
	# exists to prevent, wearing the file's own clothes. Found by this lib's own
	# totality check rather than by review.
	local armed="${1-}" wb="${2-}" wa="${3-}" sb="${4-}" sa="${5-}"

	if [[ "$armed" != "armed" ]]; then
		printf 'VOID %s\n' "no screen profile was armed (got '${armed}') — stage_screen_check is gated on has_screen_state(), so the screen stage short-circuits and NOTHING under test ran (#8336 trap 1)"
		return 0
	fi

	local wdelta
	wdelta="$(screen_probe_delta "$wb" "$wa")"
	if [[ -z "$wdelta" ]]; then
		printf 'VOID %s\n' "the witness counter is unreadable (before='${wb}' after='${wa}') — a missing metric, a failed scrape or a helper restart mid-probe. The subject sample cannot be interpreted without it (#8336 trap 3)"
		return 0
	fi
	if (( wdelta == 0 )); then
		printf 'VOID %s\n' "the witness frame did not move its counter — the crafted frames did not reach the screen stage at all (routing, L2, the host stack, or the NIC discarding the header before AF_XDP). A flat subject here means THE MEASUREMENT DID NOT HAPPEN, not that the frame was permitted (#8336 trap 3)"
		return 0
	fi

	local sdelta
	sdelta="$(screen_probe_delta "$sb" "$sa")"
	if [[ -z "$sdelta" ]]; then
		printf 'VOID %s\n' "the witness moved (+${wdelta}) but the subject counter is unreadable (before='${sb}' after='${sa}') — the path is live and the instrument is not"
		return 0
	fi

	if (( sdelta > 0 )); then
		printf 'DROPPED %s\n' "xpf_screen_drops_total +${sdelta} with the witness live (+${wdelta}) — the subject frame reached the screen stage and was dropped"
		return 0
	fi
	printf 'PASSED %s\n' "xpf_screen_drops_total did not move while the witness did (+${wdelta}) — the subject frame REACHED the screen stage and was NOT dropped. This is a result, not an absence of one"
}

# screen_probe_disarm_verdict <node0_count> <node1_count>
#   Print "PASS"/"FAIL" for the post-run cleanup check.
#
#   The cluster is SHARED. A screen profile left bound to a zone changes the
#   environment for every other lane, and config syncs to the peer -- so the
#   check is per-node and BOTH must be clean. A single aggregate count would
#   pass with 0 on one node and a leftover on the other.
screen_probe_disarm_verdict() {
	local n0="${1-}" n1="${2-}"
	for v in "$n0" "$n1"; do
		if [[ ! "$v" =~ ^[0-9]+$ ]]; then
			printf 'FAIL %s\n' "disarm check unreadable (node0='${n0}' node1='${n1}') — cannot confirm the shared cluster was left clean"
			return 0
		fi
	done
	if (( n0 == 0 && n1 == 0 )); then
		printf 'PASS %s\n' "screen profile removed on both nodes"
		return 0
	fi
	printf 'FAIL %s\n' "screen profile still present (node0=${n0} node1=${n1}) — the shared cluster was left armed; remove it before another lane deploys"
}

# screen_probe_exit_status <verdict> <cleanup>
#   Map the run's two result lines to the process exit status — #12911.
#
#     0  DROPPED with a clean cleanup. The ONLY green: rc0 means "the
#        witness was live AND the subject was dropped", which is the sole
#        outcome an exit-code-only caller may read as a passed DROP gate.
#     1  PASSED: the subject frame REACHED the screen stage and was NOT
#        dropped. For an instrument whose subject is a frame that should
#        be screened, that is the failed finding — it used to fall through
#        to rc0, where a status-only caller mistakes it for a green gate.
#     2  VOID: nothing was learned; the measurement did not happen.
#     3  cleanup FAIL: the shared cluster was left armed. Decided FIRST,
#        because a leaked profile changes what every other lane measures —
#        worse than any measurement outcome — and the old ordering let
#        VOID's rc2 mask it.
#     4  an unrecognised verdict or cleanup: the decision layer itself is
#        broken. Fail closed rather than guess at a reading.
#
#   Same discipline as screen_probe_verdict: defaulted, not required, so a
#   short argument list cannot abort the function into emitting a guess.
screen_probe_exit_status() {
	local verdict="${1-}" cleanup="${2-}"
	case "$cleanup" in
		PASS\ *) ;;
		FAIL\ *) return 3 ;;
		*) return 4 ;;
	esac
	case "$verdict" in
		DROPPED\ *) return 0 ;;
		PASSED\ *) return 1 ;;
		VOID\ *) return 2 ;;
		*) return 4 ;;
	esac
}
