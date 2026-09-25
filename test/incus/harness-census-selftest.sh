#!/usr/bin/env bash
# Self-test for scripts/harness-census.sh (#8302).
#
# Hermetic: fixture trees under a mktemp -d. No incus, no cluster, no network,
# no build. Runs in well under a second.
#
# WHY THIS EXISTS
#
# harness-census.sh is a gate about gates, and its failure mode is the one
# review cannot see: a census whose matcher is broken reports a CLEAN BOARD.
# Every green run of a broken census looks exactly like every green run of a
# healthy one. Only a mutation can tell them apart, so each defence below is
# asserted twice — once by a fixture that must score UNREACHED, and once by a
# MUTATION of the census that must make that same fixture flip to REACHED. A
# mutation that does not flip its cell is an ESCAPE and fails this self-test:
# it means the fixture was passing for some other reason and the defence it
# claims to cover is untested.
#
# The four false-registration shapes below are not invented. Each is a real
# instance in this tree at the time the census landed:
#
#   1. comment-only        Makefile:524 "Run it after touching test-mouse-latency.sh."
#   2. sibling target name `test-fbf-steering-lib` runs the SELFTEST, not the harness
#   3. lint-only           Makefile:672 `bash -n ./test/incus/newflow-ceiling-harness.sh`
#   4. bare list entry     run-selftests.sh SH_SCRIPTS holds `test/incus/test-fbf-steering.sh`
#                          with no `./`, fed only to `$interp -n`
#
# Plus the two cells that stop the census reporting a clean sweep of an
# inverted world: the EMPTY SWEEP (zero harnesses must FAIL, never pass) and
# the POSITIVE CONTROL (a known-reached harness must classify reached, so a
# matcher broken to reach nothing trips by name).
#
# And the control that fails on CORRECT input: TRANSITIVE reachability must
# actually work (cell G). Without it a matcher that reaches nothing would
# satisfy every UNREACHED cell above and this file would certify it.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CENSUS="${REPO_ROOT}/scripts/harness-census.sh"

PASS=0
FAIL=0
ok()  { echo "  ok   — $*"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL — $*" >&2; FAIL=$((FAIL + 1)); }

[[ -f "$CENSUS" ]] || { echo "FATAL: census not found at $CENSUS" >&2; exit 1; }

WORK="$(mktemp -d "${TMPDIR:-/var/tmp}/harness-census-selftest.XXXXXX")"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# ── fixture plumbing ──────────────────────────────────────────────────────
# A fixture is a miniature repo: <fx>/Makefile plus <fx>/test/incus/*.sh plus
# an optional <fx>/test/incus/HARNESSES.unreached.

new_fixture() { # new_fixture <name> -> echoes the fixture root
	local fx="$WORK/$1"
	mkdir -p "$fx/test/incus"
	: >"$fx/test/incus/HARNESSES.unreached"
	echo "$fx"
}

add_harness() { # add_harness <fx> <name.sh> [body...]
	local fx=$1 name=$2
	shift 2
	{
		echo '#!/bin/sh'
		printf '%s\n' "$@"
	} >"$fx/test/incus/$name"
	chmod +x "$fx/test/incus/$name"
}

# run_census <fx> [census-script] -> prints output, returns the census rc.
# The positive control is pointed at the fixture's own control harness, and
# the library list is emptied: these fixtures have no libraries, and a census
# that inherited the real tree's named list would fail on stale entries.
run_census() {
	local fx=$1 script=${2:-$CENSUS}
	CENSUS_ROOT="$fx" \
	CENSUS_HARNESS_GLOBS='test/incus/*.sh' \
	CENSUS_SCAN_GLOBS='test/incus/*.sh' \
	CENSUS_LIBRARIES='' \
	CENSUS_POSITIVE_CONTROL='test/incus/ctl.sh' \
		sh "$script" 2>&1
}

# mutant <name> <sed-expr>... -> echoes a path to a MUTATED copy of the census.
mutant() {
	local name=$1
	shift
	local out="$WORK/mutant-$name.sh"
	cp "$CENSUS" "$out"
	local e
	for e in "$@"; do
		sed -i "$e" "$out"
	done
	# A mutation that failed to change the file is a silent no-op that would
	# score as an ESCAPE for the wrong reason.
	if cmp -s "$CENSUS" "$out"; then
		bad "mutation '$name' changed NOTHING (its sed no longer matches the census -- the marker moved)"
	fi
	echo "$out"
}

# assert_unreached <fx> <path> <label>
assert_unreached() {
	local fx=$1 path=$2 label=$3 out rc
	out="$(run_census "$fx")" && rc=0 || rc=$?
	if [[ $rc -ne 0 && "$out" == *"$path"* && "$out" == *"UNREACHED and undeclared"* ]]; then
		ok "$label"
	else
		bad "$label (rc=$rc; census did not report $path as unreached)"
		printf '%s\n' "$out" | sed 's/^/         /' >&2
	fi
}

# assert_mutation_flips <fx> <path> <label> <mutant-path>
# The census under mutation must STOP reporting <path> as unreached. If it
# still reports it, the mutation ESCAPED and the cell above proves nothing.
assert_mutation_flips() {
	local fx=$1 path=$2 label=$3 mut=$4 out rc
	out="$(run_census "$fx" "$mut")" && rc=0 || rc=$?
	if [[ "$out" == *"UNREACHED and undeclared"* && "$out" == *"$path"* ]]; then
		bad "$label — mutation ESCAPED: the mutated census still scores $path unreached, so the cell has no power"
		printf '%s\n' "$out" | sed 's/^/         /' >&2
	else
		ok "$label"
	fi
}

# ── cell A1 — shape 1a: named only in a COMMENT inside a reached harness ──
# The real instance: with-cluster.sh (reached, via cluster-setup.sh) shows
#   #       ./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0 &&
# in its usage comment. That single line is the whole difference between
# apply-cos-config.sh being "reached transitively" and being unreached — and
# the design this census implements got it wrong in exactly that direction
# before the comment strip existed. This cell isolates the comment strip: the
# reference is inside a script body, where the recipe-line filter cannot help.
FX_A1="$(new_fixture comment-in-body)"
add_harness "$FX_A1" ctl.sh 'echo control'
add_harness "$FX_A1" hcomment.sh 'echo gate'
add_harness "$FX_A1" wrapper.sh \
	'# Usage:' \
	'#       ./test/incus/hcomment.sh --flag' \
	'echo wrapper'
cat >"$FX_A1/Makefile" <<'MK'
control:
	./test/incus/ctl.sh
	./test/incus/wrapper.sh
MK
assert_unreached "$FX_A1" "test/incus/hcomment.sh" \
	"shape 1a: a harness named only in a COMMENT inside a reached harness is UNREACHED"

M_COMMENT="$(mutant comment-strip '/census-guard: comment-strip/{n;s/.*/\tcat/;}')"
assert_mutation_flips "$FX_A1" "test/incus/hcomment.sh" \
	"shape 1a mutation: with the comment strip removed the cell flips to reached" "$M_COMMENT"

# ── cell A2 — shape 1b: named only in a full-line Makefile COMMENT ────────
# The real instance: Makefile:524 "Run it after touching test-mouse-latency.sh."
# beside a target that runs the hermetic selftest. Two independent guards stop
# it — a full-line comment is not a recipe line, AND the comment strip removes
# it — so the mutation has to remove BOTH before the cell flips. That is the
# property being asserted: defence in depth here, not a single point.
FX_A2="$(new_fixture comment-in-makefile)"
add_harness "$FX_A2" ctl.sh 'echo control'
add_harness "$FX_A2" test-mouse-latency.sh 'echo gate'
cat >"$FX_A2/Makefile" <<'MK'
control:
	./test/incus/ctl.sh

# Run it after touching ./test/incus/test-mouse-latency.sh
mouse-lib:
	@echo selftest
MK
assert_unreached "$FX_A2" "test/incus/test-mouse-latency.sh" \
	"shape 1b: a harness named only in a full-line Makefile COMMENT is UNREACHED"

M_MKCOMMENT="$(mutant makefile-comment \
	's|/\^\\t/ {   # census-guard: recipe-lines-only|{|' \
	'/census-guard: comment-strip/{n;s/.*/\tcat/;}')"
assert_mutation_flips "$FX_A2" "test/incus/test-mouse-latency.sh" \
	"shape 1b mutation: only with BOTH the recipe-line filter and the comment strip removed does the cell flip" "$M_MKCOMMENT"

# ── cell B — shape 2: matched only via a DIFFERENT TARGET's name ──────────
# The real instance: `make test-fbf-steering-lib` runs the hermetic selftest,
# not test-fbf-steering.sh. A naive census (`grep test-fbf-steering Makefile`)
# scores the harness registered.
FX_B="$(new_fixture sibling-target)"
add_harness "$FX_B" ctl.sh 'echo control'
add_harness "$FX_B" test-fbf-steering.sh 'echo gate'
add_harness "$FX_B" fbf-steering-selftest.sh 'echo selftest'
cat >"$FX_B/Makefile" <<'MK'
.PHONY: control test-fbf-steering-lib

control:
	./test/incus/ctl.sh

test-fbf-steering-lib:
	bash ./test/incus/fbf-steering-selftest.sh
MK
assert_unreached "$FX_B" "test/incus/test-fbf-steering.sh" \
	"shape 2: a harness matched only via a sibling TARGET's name is UNREACHED"

# The naive census this defends against, in two edits: scan every Makefile
# line (not just recipe lines, where a target name can never appear) and match
# the harness STEM anywhere in the caller's text instead of an exact basename.
M_NAIVE="$(mutant naive-stem-grep \
	's|/\^\\t/ {   # census-guard: recipe-lines-only|{|' \
	'/census-guard: invocation-policy/{n;s|.*|\t_b=${1##*/}; _s=${_b%.sh}; printf "%s\\n" "$3" \| grep -qF "$_s"|;}')"
assert_mutation_flips "$FX_B" "test/incus/test-fbf-steering.sh" \
	"shape 2 mutation: the naive stem grep scores the sibling target as registration" "$M_NAIVE"

# ── cell C — shape 3: named only under `bash -n` (lint-reachable) ─────────
FX_C="$(new_fixture lint-only)"
add_harness "$FX_C" ctl.sh 'echo control'
add_harness "$FX_C" lintonly.sh 'echo gate'
cat >"$FX_C/Makefile" <<'MK'
control:
	./test/incus/ctl.sh

lint:
	bash -n ./test/incus/lintonly.sh
MK
assert_unreached "$FX_C" "test/incus/lintonly.sh" \
	"shape 3: a harness named only under 'bash -n' is UNREACHED"

M_LINT="$(mutant lint-drop '/census-guard: lint-drop/{n;s/.*/\tcat/;}')"
assert_mutation_flips "$FX_C" "test/incus/lintonly.sh" \
	"shape 3 mutation: with the lint-line drop removed the cell flips to reached" "$M_LINT"

# ── cell D — shape 4: a BARE relative path in a lint list ─────────────────
# run-selftests.sh's SH_SCRIPTS holds `test/incus/test-fbf-steering.sh` with no
# `./`; every entry is fed to `$interp -n "$s"`, never run. The lint-drop
# cannot see it (the lint call is on a different line, in a loop), so the
# rooted-path rule is the only thing standing between it and a false REACHED.
FX_D="$(new_fixture bare-list)"
add_harness "$FX_D" ctl.sh 'echo control'
add_harness "$FX_D" barelist.sh 'echo gate'
add_harness "$FX_D" linter.sh \
	'SH_SCRIPTS="' \
	'test/incus/barelist.sh' \
	'"' \
	'for s in $SH_SCRIPTS; do sh -n "$s"; done'
cat >"$FX_D/Makefile" <<'MK'
control:
	./test/incus/ctl.sh
	./test/incus/linter.sh
MK
assert_unreached "$FX_D" "test/incus/barelist.sh" \
	"shape 4: a BARE relative path in a lint list is UNREACHED"

M_ROOTED="$(mutant rooted-path '/census-guard: rooted-path/s|if (t !~ /\^\[\.\\/\$~\]/) {|if (0) {|')"
assert_mutation_flips "$FX_D" "test/incus/barelist.sh" \
	"shape 4 mutation: without the rooted-path rule the bare list entry scores reached" "$M_ROOTED"

# ── cell D2 — the other half of shape 4: `sh <bare path>` IS an invocation ─
# The control that keeps the rooted-path rule from over-rejecting. The
# Makefile runs the self-test runner as `sh scripts/run-selftests.sh` with no
# `./`; scoring that a non-invocation would put a WRONG REASON into
# HARNESSES.unreached for anything it reaches. A bare path is a list entry
# only when nothing runs it.
FX_D2="$(new_fixture interp-bare)"
add_harness "$FX_D2" ctl.sh 'echo control'
add_harness "$FX_D2" interp.sh 'echo gate'
cat >"$FX_D2/Makefile" <<'MK'
control:
	./test/incus/ctl.sh
	sh test/incus/interp.sh
MK
out="$(run_census "$FX_D2")" && rc=0 || rc=$?
if [[ $rc -eq 0 ]]; then
	ok "shape 4 control: a bare path RUN BY an interpreter (\`sh test/incus/interp.sh\`) is REACHED"
else
	bad "an interpreter-run bare path was scored unreached (rc=$rc) -- the rooted-path rule over-rejects"
	printf '%s\n' "$out" | sed 's/^/         /' >&2
fi

# ── cell E — the EMPTY SWEEP must FAIL, never sweep clean ─────────────────
FX_E="$(new_fixture empty)"
cat >"$FX_E/Makefile" <<'MK'
control:
	@echo nothing
MK
out="$(CENSUS_ROOT="$FX_E" CENSUS_HARNESS_GLOBS='test/incus/nosuch-*.sh' \
	CENSUS_SCAN_GLOBS='test/incus/nosuch-*.sh' CENSUS_LIBRARIES='' \
	sh "$CENSUS" 2>&1)" && rc=0 || rc=$?
if [[ $rc -ne 0 && "$out" == *"ZERO harnesses"* ]]; then
	ok "empty sweep: a census that matches NO harnesses FAILS (it did not prove a clean board)"
else
	bad "empty sweep did not fail (rc=$rc)"
	printf '%s\n' "$out" | sed 's/^/         /' >&2
fi

# ── cell F — the POSITIVE CONTROL trips when the matcher reaches nothing ──
# The scenario: the matcher breaks, someone regenerates HARNESSES.unreached
# from its output, and the census is green over an inverted world -- every
# harness "declared unreached", nothing reported. The control is what makes
# that state loud, so the fixture declares EVERYTHING BUT the control.
FX_F="$(new_fixture positive-control)"
add_harness "$FX_F" ctl.sh 'echo control'
add_harness "$FX_F" other.sh 'echo other'
cat >"$FX_F/Makefile" <<'MK'
control:
	./test/incus/ctl.sh
MK
echo 'test/incus/other.sh  DIAGNOSTIC: fixture' >"$FX_F/test/incus/HARNESSES.unreached"
out="$(run_census "$FX_F")" && rc=0 || rc=$?
if [[ $rc -eq 0 && "$out" == *"positive control: test/incus/ctl.sh classifies REACHED"* ]]; then
	ok "positive control passes on a healthy census"
else
	bad "positive control did not pass on a healthy fixture (rc=$rc)"
	printf '%s\n' "$out" | sed 's/^/         /' >&2
fi

M_BLIND="$(mutant blind-matcher '/census-guard: invocation-policy/{n;s|.*|\treturn 1|;}')"
out="$(run_census "$FX_F" "$M_BLIND")" && rc=0 || rc=$?
if [[ $rc -ne 0 && "$out" == *"positive control FAILED"* ]]; then
	ok "positive control mutation: a matcher that reaches NOTHING trips the control by name"
else
	bad "positive control ESCAPED: a blind matcher did not trip it (rc=$rc)"
	printf '%s\n' "$out" | sed 's/^/         /' >&2
fi

# The control may never be declared away.
echo 'test/incus/ctl.sh  GATE: trying to suppress the control' >>"$FX_F/test/incus/HARNESSES.unreached"
out="$(run_census "$FX_F")" && rc=0 || rc=$?
if [[ $rc -ne 0 && "$out" == *"POSITIVE CONTROL and may never be declared unreached"* ]]; then
	ok "the positive control cannot be declared unreached"
else
	bad "declaring the positive control unreached was accepted (rc=$rc)"
fi

# ── cell G — the control that fails on CORRECT input: TRANSITIVITY works ──
# Without this, a matcher broken to reach nothing satisfies every UNREACHED
# cell above and this file certifies it.
FX_G="$(new_fixture transitive)"
add_harness "$FX_G" ctl.sh 'echo control'
add_harness "$FX_G" mid.sh \
	'SCRIPT_DIR=$(dirname "$0")' \
	'"${SCRIPT_DIR}/leaf.sh"'
add_harness "$FX_G" leaf.sh 'echo leaf'
cat >"$FX_G/Makefile" <<'MK'
control:
	./test/incus/ctl.sh
	./test/incus/mid.sh
MK
out="$(run_census "$FX_G")" && rc=0 || rc=$?
if [[ $rc -eq 0 ]]; then
	ok "transitivity: a harness invoked by an invoked harness is REACHED (nothing declared)"
else
	bad "transitivity broken: leaf.sh should be reached through mid.sh (rc=$rc)"
	printf '%s\n' "$out" | sed 's/^/         /' >&2
fi

# ── cell H — a mutually-calling cluster with no root stays UNREACHED ──────
# The real instances: cos-simul-load-smoke.sh <-> cos-gate1-small-four-alone.sh,
# and the step1/step2 capture chain. A census that only asked "does anything
# reference it" scores every one of them green. It must also TERMINATE.
FX_H="$(new_fixture cluster)"
add_harness "$FX_H" ctl.sh 'echo control'
add_harness "$FX_H" clusterx.sh 'SCRIPT_DIR=$(dirname "$0")' '"${SCRIPT_DIR}/clustery.sh"'
add_harness "$FX_H" clustery.sh 'SCRIPT_DIR=$(dirname "$0")' '"${SCRIPT_DIR}/clusterx.sh"'
cat >"$FX_H/Makefile" <<'MK'
control:
	./test/incus/ctl.sh
MK
out="$(timeout 60 sh -c "CENSUS_ROOT='$FX_H' CENSUS_HARNESS_GLOBS='test/incus/*.sh' \
	CENSUS_SCAN_GLOBS='test/incus/*.sh' CENSUS_LIBRARIES='' \
	CENSUS_POSITIVE_CONTROL='test/incus/ctl.sh' sh '$CENSUS'" 2>&1)" && rc=0 || rc=$?
if [[ $rc -eq 124 ]]; then
	bad "a mutually-calling cluster made the closure LOOP (timed out)"
elif [[ $rc -ne 0 && "$out" == *"test/incus/clusterx.sh"* && "$out" == *"test/incus/clustery.sh"* ]]; then
	ok "a cluster that only calls itself is UNREACHED, and the closure terminates"
else
	bad "mutually-calling cluster was not reported unreached (rc=$rc)"
	printf '%s\n' "$out" | sed 's/^/         /' >&2
fi

# ── cell I — a *-selftest.sh does not CONFER reachability ─────────────────
# mouse-elephant-selftest.sh invokes test-mouse-latency.sh against a fake
# iperf3. That exercises the script under mocks; it does not run the gate.
FX_I="$(new_fixture selftest-caller)"
add_harness "$FX_I" ctl.sh 'echo control'
add_harness "$FX_I" gate.sh 'echo gate'
add_harness "$FX_I" mock-selftest.sh 'SCRIPT_DIR=$(dirname "$0")' '"${SCRIPT_DIR}/gate.sh"'
cat >"$FX_I/Makefile" <<'MK'
control:
	./test/incus/ctl.sh

selftest:
	bash ./test/incus/mock-selftest.sh
MK
assert_unreached "$FX_I" "test/incus/gate.sh" \
	"a harness invoked only by a *-selftest.sh (under mocks) is UNREACHED"

# ── cell J — the declared list is a contract, and it only shrinks ─────────
FX_J="$(new_fixture declared)"
add_harness "$FX_J" ctl.sh 'echo control'
add_harness "$FX_J" idle.sh 'echo idle'
cat >"$FX_J/Makefile" <<'MK'
control:
	./test/incus/ctl.sh
MK

echo 'test/incus/idle.sh' >"$FX_J/test/incus/HARNESSES.unreached"
out="$(run_census "$FX_J")" && rc=0 || rc=$?
if [[ $rc -ne 0 && "$out" == *"declared with NO reason"* ]]; then
	ok "a declaration with no reason is a FAIL (a bare path is a suppression)"
else
	bad "a reasonless declaration was accepted (rc=$rc)"
fi

echo 'test/incus/idle.sh  DIAGNOSTIC: fixture' >"$FX_J/test/incus/HARNESSES.unreached"
out="$(run_census "$FX_J")" && rc=0 || rc=$?
[[ $rc -eq 0 ]] && ok "a declaration with a reason is accepted" \
	|| { bad "a well-formed declaration was rejected (rc=$rc)"; printf '%s\n' "$out" | sed 's/^/         /' >&2; }

echo 'test/incus/gone.sh  GATE: deleted last week' >>"$FX_J/test/incus/HARNESSES.unreached"
out="$(run_census "$FX_J")" && rc=0 || rc=$?
if [[ $rc -ne 0 && "$out" == *"stale declaration"* ]]; then
	ok "a declaration for a path that no longer exists is a FAIL (the list cannot rot)"
else
	bad "a stale declaration was accepted (rc=$rc)"
fi

# ...and the shrink-only rule: a declared harness that BECOMES reached is a FAIL.
cat >"$FX_J/Makefile" <<'MK'
control:
	./test/incus/ctl.sh
	./test/incus/idle.sh
MK
echo 'test/incus/idle.sh  DIAGNOSTIC: fixture' >"$FX_J/test/incus/HARNESSES.unreached"
out="$(run_census "$FX_J")" && rc=0 || rc=$?
if [[ $rc -ne 0 && "$out" == *"IS reached now"* ]]; then
	ok "a declared harness that becomes reached is a FAIL (the list is only allowed to shrink)"
else
	bad "a now-reached declaration was silently kept (rc=$rc)"
fi

# ── cell K — the library exemption is a NAMED LIST, not a wildcard ────────
FX_K="$(new_fixture libraries)"
add_harness "$FX_K" ctl.sh 'echo control'
add_harness "$FX_K" shiny-lib.sh 'shiny_fn() { :; }'
cat >"$FX_K/Makefile" <<'MK'
control:
	./test/incus/ctl.sh
MK
out="$(CENSUS_ROOT="$FX_K" CENSUS_HARNESS_GLOBS='test/incus/*.sh' \
	CENSUS_SCAN_GLOBS='test/incus/*.sh' CENSUS_LIBRARIES='' \
	CENSUS_POSITIVE_CONTROL='test/incus/ctl.sh' sh "$CENSUS" 2>&1)" && rc=0 || rc=$?
if [[ $rc -ne 0 && "$out" == *"undeclared library on disk: test/incus/shiny-lib.sh"* ]]; then
	ok "a new *-lib.sh must be DECLARED (a wildcard exemption would let a harness be renamed out of the census)"
else
	bad "an undeclared *-lib.sh was wildcard-exempted (rc=$rc)"
	printf '%s\n' "$out" | sed 's/^/         /' >&2
fi

out="$(CENSUS_ROOT="$FX_K" CENSUS_HARNESS_GLOBS='test/incus/*.sh' \
	CENSUS_SCAN_GLOBS='test/incus/*.sh' \
	CENSUS_LIBRARIES='test/incus/shiny-lib.sh test/incus/vanished-lib.sh' \
	CENSUS_POSITIVE_CONTROL='test/incus/ctl.sh' sh "$CENSUS" 2>&1)" && rc=0 || rc=$?
if [[ $rc -ne 0 && "$out" == *"declared library does not exist: test/incus/vanished-lib.sh"* ]]; then
	ok "a declared library that no longer exists is a FAIL (the named list cannot rot either)"
else
	bad "a stale library declaration was accepted (rc=$rc)"
fi

# ── #10716: the #9506 fixture and attestation harness are both reachable ──
#
# The fixture is sourced by the live T12/G2 harness, and both scripts must
# become reachable from its Makefile recipe. This positive control also
# reproduces the pre-fix state: dropping the recipe must make the census fail
# and name both scripts rather than pass with an undeclared pair.
FX_9506="$(new_fixture issue-9506)"
add_harness "$FX_9506" ctl.sh 'echo control'
add_harness "$FX_9506" ipsec-9506-fixture.sh 'echo fixture'
add_harness "$FX_9506" t12-g2-9506.sh \
	'SCRIPT_DIR=$(dirname "$0")' \
	'source "${SCRIPT_DIR}/ipsec-9506-fixture.sh"'
cat >"$FX_9506/Makefile" <<'MK'
control:
	./test/incus/ctl.sh
test-t12-g2-9506:
	./test/incus/t12-g2-9506.sh
MK
out="$(run_census "$FX_9506")" && rc=0 || rc=$?
if [[ $rc -eq 0 && "$out" == *"3 runnable harnesses -- 3 reached, 0 declared unreached"* ]]; then
	ok "#9506 live recipe reaches both T12/G2 and its sourced fixture"
else
	bad "#9506 recipe did not reach both harnesses (rc=$rc)"
	printf '%s\n' "$out" | sed 's/^/         /' >&2
fi

# Fail-on-revert RED cell: the census must reject the pre-fix recipe-less tree.
cat >"$FX_9506/Makefile" <<'MK'
control:
	./test/incus/ctl.sh
MK
out="$(run_census "$FX_9506")" && rc=0 || rc=$?
if [[ $rc -ne 0 &&
	"$out" == *"UNREACHED and undeclared"* &&
	"$out" == *"test/incus/ipsec-9506-fixture.sh"* &&
	"$out" == *"test/incus/t12-g2-9506.sh"* ]]; then
	ok "#9506 recipe removal reds the census with both missing paths"
else
	bad "#9506 recipe removal did not expose the undeclared pair (rc=$rc)"
	printf '%s\n' "$out" | sed 's/^/         /' >&2
fi

# ── cell L — the real tree must be GREEN ──────────────────────────────────
# This is what `make harness-census` runs. Kept here so the self-test and the
# gate cannot drift into testing different things.
out="$(sh "$CENSUS" 2>&1)" && rc=0 || rc=$?
if [[ $rc -eq 0 ]]; then
	ok "the real tree passes the census ($(printf '%s' "$out" | sed -n 's/^harness census: \(.*\)$/\1/p' | head -1))"
else
	bad "the real tree FAILS the census — a harness was added or a recipe removed"
	printf '%s\n' "$out" | sed 's/^/         /' >&2
fi

# ── #9006: the UNTRACKED branch, asserted in BOTH directions ──────────────
#
# The census scans the working tree, so an uncommitted harness fails it for one
# checkout only -- under a message asserting "a harness was added or a recipe
# removed", which points at recent commits, and offering a remedy (declare it
# in HARNESSES.unreached) that trips the separate stale-declaration FAIL. Two
# cells, because one direction alone does not bound it: the untracked case must
# produce the UNTRACKED text and NOT the generic text, and the tracked case
# must produce the generic text and NOT the UNTRACKED text. A branch that fired
# for both would look correct against either cell alone.
#
# GIT-GATED, NOT GIT-DEPENDENT. This file's contract is hermetic, and a hard
# git dependency is exactly what broke it once before (a `mktemp` added to the
# census died in the restricted-PATH leg). With no git these cells SKIP and the
# suite is unchanged; the census itself already falls back to the generic text
# in that case, which the existing cells cover.
if command -v git >/dev/null 2>&1; then
	FX_UT="$(new_fixture untracked-harness)"
	printf '#!/bin/sh\necho probe\n' >"$FX_UT/test/incus/scratch-probe.sh"
	chmod +x "$FX_UT/test/incus/scratch-probe.sh"
	(
		cd "$FX_UT" || exit 1
		git init -q . >/dev/null 2>&1
		git config user.email selftest@example.invalid
		git config user.name selftest
		git add -A ':!test/incus/scratch-probe.sh' >/dev/null 2>&1
		git commit -qm fixture >/dev/null 2>&1
	)

	out="$(run_census "$FX_UT")" && rc=0 || rc=$?
	if [[ $rc -ne 0 && "$out" == *"UNTRACKED harness"* && "$out" != *"UNREACHED and undeclared"* ]]; then
		ok "an UNTRACKED harness reports the untracked remedy, not the commit-hunting one"
	else
		bad "the untracked case did not take the #9006 branch (rc=$rc)"
		printf '%s\n' "$out" | sed 's/^/         /' >&2
	fi

	# The OTHER direction. Same file, now committed: it must fall back to the
	# generic text. Without this the branch could fire for every undeclared
	# harness and the cell above would still pass.
	( cd "$FX_UT" && git add -A >/dev/null 2>&1 && git commit -qm track >/dev/null 2>&1 )
	out="$(run_census "$FX_UT")" && rc=0 || rc=$?
	if [[ $rc -ne 0 && "$out" == *"UNREACHED and undeclared"* && "$out" != *"UNTRACKED harness"* ]]; then
		ok "a TRACKED undeclared harness still reports the original remedy"
	else
		bad "the tracked case took the wrong branch (rc=$rc)"
		printf '%s\n' "$out" | sed 's/^/         /' >&2
	fi
else
	echo "  skip — #9006 untracked-branch cells (git not on PATH; census falls back)"
fi

# ── summary ───────────────────────────────────────────────────────────────
echo ""
echo "harness-census-selftest: passed=$PASS failed=$FAIL"
[[ $FAIL -eq 0 ]] || exit 1
exit 0
