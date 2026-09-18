#!/usr/bin/env bash
# Self-test for test/incus/harness-result.sh. Hermetic: no incus, no cluster,
# no lock, no network. Every adapter is a pure function of (rc, log text), so
# the whole verdict matrix is drivable from fixtures.
#
# Usage: ./test/incus/harness-result-selftest.sh   (rc 0 = all pass)
#
# The load-bearing cell is the ADAPTER CENSUS. It does not invent a summary
# line; it EXTRACTS the real `echo` from each of the thirteen gates that carry the
# shape. Two consequences:
#
#   * an adapter anchored on a label prefix ("Failover test:") covers six of
#     eight and looks complete -- here it fails on the two that print a bare
#     "Results:";
#   * an adapter anchored at end of line drops test-connectivity.sh, whose
#     summary continues ", <n> skipped" after the pair;
#
# and if any of those thirteen gates changes its summary format, this reds instead
# of the ledger quietly filling with VOIDs.
#
# Falsifiability of this file: if the adapter table is wrong, the cell naming
# the affected source fails. If the census's own extraction breaks (a changed
# echo, a renamed file) the census fails rather than sweeping an empty set --
# it asserts the DISCOVERED set equals the declared set, so another gate added
# with the same shape and not declared is a red, and a declared gate that
# disappeared is also a red. On an empty glob it fails outright.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Overridable so the mutation runner can point this at a MUTATED copy of the
# library; defaults to the real one.
HARNESS_RESULT_LIB="${HARNESS_RESULT_LIB:-$SCRIPT_DIR/harness-result.sh}"

if ! command -v python3 >/dev/null 2>&1; then
	echo "SKIP: python3 not installed (the row emitter serialises with it)"
	exit 77
fi

# shellcheck source=harness-result.sh
source "$HARNESS_RESULT_LIB"

PASS=0
FAIL=0
ok() { echo "PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

WORK=$(mktemp -d "${TMPDIR:-/var/tmp}/xpf-harness-result-selftest.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
LOG="$WORK/gate.log"
LEDGER="$WORK/ledger.d"

# adapt_field <adapter> <rc> <n> -- nth TAB field of the adapter's line
adapt_field() {
	local adapter="$1" rc="$2" n="$3" out
	out=$(harness_adapt "$adapter" "$rc" "$LOG") || return 1
	cut -f"$n" <<<"$out"
}

expect_field() {
	local label="$1" adapter="$2" rc="$3" n="$4" want="$5" got
	got=$(adapt_field "$adapter" "$rc" "$n")
	if [[ "$got" == "$want" ]]; then
		ok "$label"
	else
		bad "$label (field $n: want '$want', got '$got')"
	fi
}

# ── 1. The adapter census: 5 iperf smokes + 8 cells smokes ──────────
#
# #9922 F-155: ONE adapter can no longer cover both classes. The five smokes
# that emit an iperf3 throughput cell keep ha-smoke (PASS headline FIXED to
# throughput_gbps, figure required); the eight smokes that emit cells only take
# smoke-cells (PASS/FAIL headline FIXED to cells_passed). The declared sets
# below are CLAIMs; the discovery in 1b and the Makefile cross-check in 1f
# test them.
DECLARED_IPERF_SMOKES=(
	test-failover
	test-double-failover
	test-stress-failover
	test-chained-crash
	test-active-active
)
DECLARED_CELLS_SMOKES=(
	test-ha-crash
	test-restart-connectivity
	test-private-rg
	test-connectivity
	test-wire-properties
	persistent-nat-failover
	dhcp-lease-failover
	wg-interop
)

# 1a. Every declared gate exists, carries its summary echo(s), and its OWN
#     adapter scores the rendered line. Iperf fixtures carry a synthetic
#     canonical cell line because ha-smoke PASS requires a measured figure;
#     cells fixtures are the bare summary because smoke-cells must ignore
#     everything but the pair.
IPERF_FIXTURE_LINE='  PASS  iperf3 throughput: 23.1 Gbps (>= 5 Gbps)'
census_covered=0
census_total=0
score_gate() {
	local g="$1" adapter="$2"
	census_total=$((census_total + 1))
	local f="$SCRIPT_DIR/$g.sh"
	if [[ ! -f "$f" ]]; then
		bad "census: declared gate $g.sh does not exist (renamed or removed?)"
		return 0
	fi
	# dhcp-lease-failover.sh carries TWO summary echoes: an early-exit echo
	# inside the no-promotion branch plus the canonical final echo. The
	# runtime reads the LAST summary, so the census renders the LAST echo;
	# any other count anywhere is a shape change, not coverage.
	local want_echoes=1
	[[ "$g" == "dhcp-lease-failover" || "$g" == "wg-interop" ]] && want_echoes=2
	local n
	n=$(grep -cE 'echo "[^"]*passed, [^"]*failed[^"]*"' "$f")
	if [[ "$n" != "$want_echoes" ]]; then
		bad "census: $g.sh has $n summary echo lines, expected exactly $want_echoes"
		return 0
	fi
	local line rendered
	line=$(grep -oE 'echo "[^"]*passed, [^"]*failed[^"]*"' "$f" | tail -1)
	rendered=$(PASS=7 FAIL=0 SKIP=2 eval "$line")
	# Positive control on the FIXTURE itself: if the render produced something
	# that does not contain the pair, the cell below would be testing an empty
	# string and passing for the wrong reason.
	if [[ "$rendered" != *"7 passed, 0 failed"* ]]; then
		bad "census: $g.sh summary did not render the pair (got '$rendered')"
		return 0
	fi
	if [[ "$adapter" == "ha-smoke" ]]; then
		printf '%s\n%s\n' "$IPERF_FIXTURE_LINE" "$rendered" >"$LOG"
	else
		printf '%s\n' "$rendered" >"$LOG"
	fi
	local v m h
	v=$(adapt_field "$adapter" 0 1)
	m=$(adapt_field "$adapter" 0 5)
	h=$(adapt_field "$adapter" 0 3)
	if [[ "$adapter" == "ha-smoke" ]]; then
		if [[ "$v" == "PASS" && "$m" == *"cells_passed=7"* && "$m" == *"throughput_gbps=23.1"* && "$h" == "throughput_gbps" ]]; then
			census_covered=$((census_covered + 1))
		else
			bad "census: ha-smoke did not score $g.sh's real summary line '$rendered' (verdict=$v headline=$h metrics=$m)"
		fi
	else
		if [[ "$v" == "PASS" && "$m" == *"cells_passed=7"* && "$m" == *"cells_failed=0"* && "$h" == "cells_passed" ]]; then
			census_covered=$((census_covered + 1))
		else
			bad "census: smoke-cells did not score $g.sh's real summary line '$rendered' (verdict=$v headline=$h metrics=$m)"
		fi
	fi
}
for g in "${DECLARED_IPERF_SMOKES[@]}"; do score_gate "$g" ha-smoke; done
for g in "${DECLARED_CELLS_SMOKES[@]}"; do score_gate "$g" smoke-cells; done
if ((census_covered == census_total)); then
	ok "adapter census: own adapter covers all $census_total declared gates (5 ha-smoke + 8 smoke-cells)"
else
	bad "adapter census: covered $census_covered of $census_total declared gates"
fi

# 1b. The declared set must EQUAL the discovered set. A per-member check plus a
#     count is satisfied by a NEW gate nobody declared -- the extra member a
#     lower bound cannot see. Three globs: test-*.sh, *-failover.sh, and the
#     unprefixed wg-interop.sh gate.
discovered=$(
	for f in "$SCRIPT_DIR"/test-*.sh "$SCRIPT_DIR"/*-failover.sh "$SCRIPT_DIR"/wg-interop.sh; do
		[[ -f "$f" ]] || continue
		b=$(basename "$f" .sh)
		case "$b" in *-selftest | *-lib) continue ;; esac
		grep -qE 'echo "[^"]*passed, [^"]*failed[^"]*"' "$f" && printf '%s\n' "$b"
	done | sort -u
)
if [[ -z "$discovered" ]]; then
	bad "census: the gate globs discovered ZERO gates with a summary line — the globs or the pattern are wrong (empty sweep)"
else
	want=$(printf '%s\n' "${DECLARED_IPERF_SMOKES[@]}" "${DECLARED_CELLS_SMOKES[@]}" | sort)
	if [[ "$discovered" == "$want" ]]; then
		ok "adapter census: the discovered gate set EQUALS the declared set ($(wc -l <<<"$discovered") gates)"
	else
		bad "adapter census: discovered set != declared set
  only discovered: $(comm -23 <(printf '%s\n' "$discovered") <(printf '%s\n' "$want") | tr '\n' ' ')
  only declared:   $(comm -13 <(printf '%s\n' "$discovered") <(printf '%s\n' "$want") | tr '\n' ' ')"
	fi
fi

# 1c. Every one of the 8 HA smokes named by CLAUDE.md is inside the declared
#     set. The brief's "assert all eight are covered", asserted by name.
missing8=""
for g in test-failover test-ha-crash test-double-failover test-stress-failover \
	test-chained-crash test-active-active test-restart-connectivity test-private-rg; do
	case " ${DECLARED_IPERF_SMOKES[*]} ${DECLARED_CELLS_SMOKES[*]} " in *" $g "*) ;; *) missing8="$missing8 $g" ;; esac
done
if [[ -z "$missing8" ]]; then
	ok "adapter census: all 8 destructive HA smokes are declared"
else
	bad "adapter census: HA smokes not declared:$missing8"
fi

# 1f. The Makefile mapping must match the scripts: a gate calls
#     iperf_throughput_verdict IFF it is wrapped with ha-smoke. A cells gate
map_bad=""
for g in "${DECLARED_IPERF_SMOKES[@]}" "${DECLARED_CELLS_SMOKES[@]}"; do
	# The unprefixed scripts run under test- gates (Makefile wraps
	# each source as --gate test-<script-name>).
	gate="$g"
	case "$g" in persistent-nat-failover | dhcp-lease-failover | wg-interop) gate="test-$g" ;; esac
	mkline=$(grep -E -- "--gate $gate " "$SCRIPT_DIR/../../Makefile" | head -1)
	case "$mkline" in
	*"--adapter ha-smoke"*) mk_adapter="ha-smoke" ;;
	*"--adapter smoke-cells"*) mk_adapter="smoke-cells" ;;
	*) map_bad="$map_bad $g(no-makefile-wrap)"; continue ;;
	esac
	if grep -q "iperf_throughput_verdict" "$SCRIPT_DIR/$g.sh"; then
		[[ "$mk_adapter" == "ha-smoke" ]] || map_bad="$map_bad $g(emits-iperf-but-wrapped-$mk_adapter)"
	else
		[[ "$mk_adapter" == "smoke-cells" ]] || map_bad="$map_bad $g(no-iperf-but-wrapped-$mk_adapter)"
	fi
done
if [[ -z "$map_bad" ]]; then
	ok "adapter census: Makefile --adapter matches iperf emission for all 13 smoke gates"
else
	bad "adapter census: Makefile/script adapter mismatch:$map_bad"
fi

# 1d. The label prefix must NOT be part of the match. Same numeric tail, every
#     real prefix, plus one nobody has written yet. Both adapters: the summary
#     parse is shared, and the property belongs to it.
prefix_ok=1
for adapter in ha-smoke smoke-cells; do
	for prefix in "  Failover test:" "  HA crash test:" "  Results:" "  Stress failover:" \
		"  Restart connectivity:" "  A prefix nobody has written yet:"; do
		if [[ "$adapter" == "ha-smoke" ]]; then
			printf '%s\n%s 3 passed, 0 failed\n' "$IPERF_FIXTURE_LINE" "$prefix" >"$LOG"
		else
			printf '%s 3 passed, 0 failed\n' "$prefix" >"$LOG"
		fi
		[[ "$(adapt_field "$adapter" 0 1)" == "PASS" ]] || prefix_ok=0
	done
done
((prefix_ok)) && ok "both smoke adapters match the numeric tail, not the label prefix" ||
	bad "a smoke adapter is prefix-sensitive — it would silently cover a subset of the gates"

# 1e. The trailing ", <n> skipped" must not defeat the match (test-connectivity).
printf '%s\n  Results: 7 passed, 0 failed, 2 skipped\n' "$IPERF_FIXTURE_LINE" >"$LOG"
expect_field "ha-smoke tolerates a trailing skipped count (not anchored at EOL)" ha-smoke 0 1 PASS
printf '  Results: 7 passed, 0 failed, 2 skipped\n' >"$LOG"
expect_field "smoke-cells tolerates a trailing skipped count (not anchored at EOL)" smoke-cells 0 1 PASS
expect_field "smoke-cells records the skipped count as an invariant" smoke-cells 0 5 \
	"cells_passed=7 cells_failed=0 cells_skipped=2"

# ── 2. ha-smoke: the three states ────────────────────────────────────
printf '  PASS  iperf3 throughput: 23.1 Gbps (>= 23 Gbps)\n  Failover test: 21 passed, 0 failed\n' >"$LOG"
expect_field "ha-smoke green -> PASS" ha-smoke 0 1 PASS
expect_field "ha-smoke green headline is the continuous metric" ha-smoke 0 3 throughput_gbps
expect_field "ha-smoke green carries cell counts as invariants" ha-smoke 0 5 \
	"cells_passed=21 cells_failed=0 throughput_gbps=23.1"

printf '  Failover test: 19 passed, 2 failed\n' >"$LOG"
expect_field "ha-smoke with failed cells -> FAIL" ha-smoke 1 1 FAIL
expect_field "ha-smoke FAIL without a figure keeps the cells headline (diagnostic-only)" ha-smoke 1 3 cells_passed
printf '  FAIL  iperf3 throughput too low: 12.0 Gbps (expected >= 23 Gbps)\n  Failover test: 19 passed, 2 failed\n' >"$LOG"
expect_field "ha-smoke FAIL with a figure keeps the throughput headline" ha-smoke 1 3 throughput_gbps

# The VOID that pays for itself: a smoke that died at `set -e` before its
# summary is indistinguishable from a clean run to anything reading only the
# tail.
printf 'FATAL: cluster lock held by another agent\n' >"$LOG"
expect_field "ha-smoke with NO summary line -> VOID" ha-smoke 2 1 VOID
if [[ "$(adapt_field ha-smoke 2 2)" == *"aborted before reaching its summary"* ]]; then
	ok "ha-smoke VOID carries a reason naming the abort"
else
	bad "ha-smoke VOID reason does not name the abort"
fi

printf '  Results: 0 passed, 0 failed\n' >"$LOG"
expect_field "ha-smoke with 0 passed and 0 failed -> VOID (ran no assertions)" ha-smoke 0 1 VOID

printf '  Failover test: 21 passed, 0 failed\n' >"$LOG"
expect_field "ha-smoke summary says 0 failed but rc!=0 -> VOID (they disagree)" ha-smoke 1 1 VOID
printf '  WireGuard interop: 8 passed, 0 failed\n' >"$LOG"
expect_field "wg-interop taint summary with rc=2 -> VOID" smoke-cells 2 1 VOID
if [[ "$(adapt_field smoke-cells 2 2)" == *"rc=2"* ]]; then
	ok "wg-interop taint VOID names rc=2"
else
	bad "wg-interop taint VOID does not name rc=2"
fi

# A LAST-match, so an intermediate tally cannot be read as the result. Both
# adapters: the summary parse is shared.
printf '  interim: 1 passed, 5 failed\n  Failover test: 21 passed, 0 failed\n' >"$LOG"
expect_field "smoke-cells reads the LAST summary, not an interim tally" smoke-cells 0 1 PASS
printf '%s\n  interim: 1 passed, 5 failed\n  Failover test: 21 passed, 0 failed\n' "$IPERF_FIXTURE_LINE" >"$LOG"
expect_field "ha-smoke reads the LAST summary, not an interim tally" ha-smoke 0 1 PASS

# ── 2b. #9922 F-155: the anchored iperf extraction ─────────────────────
# Floor/threshold prose used to become a banded measurement: "iperf3
# throughput floor 5 Gbps" anywhere in the log recorded throughput_gbps=5
# on a PASS row. Gbps now comes ONLY from a pass()/fail() cell line.
printf 'applying iperf3 throughput floor 5 Gbps for this lane\n  Failover test: 14 passed, 0 failed\n' >"$LOG"
expect_field "ha-smoke: bare FLOOR prose is not a measurement -> VOID" ha-smoke 0 1 VOID
printf '  PASS  iperf3 data transfer completed (2.5 Gbps) — control socket disrupted during failover\n  Failover test: 13 passed, 0 failed\n' >"$LOG"
expect_field "ha-smoke: data-transfer prose is not a throughput cell -> VOID" ha-smoke 0 1 VOID
expect_field "smoke-cells: the same log is a cells PASS (prose ignored)" smoke-cells 0 1 PASS
expect_field "smoke-cells: headline stays cells_passed under iperf-looking prose" smoke-cells 0 3 cells_passed
# LAST anchored cell wins; the figure is the FIRST <n> Gbps on that line.
printf '  PASS  iperf3 throughput: 9.9 Gbps (>= 5 Gbps)\n  PASS  iperf3 throughput: 23.1 Gbps (>= 5 Gbps)\n  Failover test: 21 passed, 0 failed\n' >"$LOG"
expect_field "ha-smoke reads the LAST throughput cell, not the first" ha-smoke 0 5 \
	"cells_passed=21 cells_failed=0 throughput_gbps=23.1"
# A FAIL cell without a figure (no measurement) keeps the cells headline.
printf '  FAIL  iperf3 throughput: no [SUM] sender line in the iperf3 log\n  Failover test: 20 passed, 1 failed\n' >"$LOG"
expect_field "ha-smoke: unmeasured FAIL keeps the cells headline" ha-smoke 1 3 cells_passed
# smoke-cells headline constancy even when a canonical cell line IS present
# (a mis-wrapped iperf log must not silently switch headline families).
printf '%s\n  HA crash test: 7 passed, 0 failed\n' "$IPERF_FIXTURE_LINE" >"$LOG"
expect_field "smoke-cells ignores even a canonical throughput cell line" smoke-cells 0 3 cells_passed
expect_field "smoke-cells carries no throughput metric" smoke-cells 0 5 "cells_passed=7 cells_failed=0"

# ── 3. iperf-throughput: recovering the void state the source lacks ──
#
# iperf-throughput-lib.sh has PASS/FAIL only. "no measurement at all" is
# emitted as a FAIL there, and mapping it straight through would file a
# non-measurement as a regression.
printf 'FAIL iperf3 throughput: no [SUM] sender line in the iperf3 log — the run produced no measurement at all\n' >"$LOG"
expect_field "iperf FAIL 'no measurement at all' -> VOID, not FAIL" iperf-throughput 1 1 VOID
printf "FAIL iperf3 throughput unparseable — no '<rate> <K|M|G>bits/sec' pair in the [SUM] sender line: x\n" >"$LOG"
expect_field "iperf FAIL 'unparseable' -> VOID, not FAIL" iperf-throughput 1 1 VOID
printf 'FAIL iperf3 throughput too low: 12.0 Gbps (expected >= 23 Gbps) — [SUM] line: x\n' >"$LOG"
expect_field "iperf FAIL 'too low' -> FAIL (a real measured regression)" iperf-throughput 1 1 FAIL
expect_field "iperf FAIL 'too low' records the measured rate" iperf-throughput 1 5 "throughput_gbps=12.0"
printf 'PASS iperf3 throughput: 23.1 Gbps (>= 23 Gbps)\n' >"$LOG"
expect_field "iperf PASS -> PASS" iperf-throughput 0 1 PASS
printf 'nothing here\n' >"$LOG"
expect_field "iperf with no verdict line -> VOID" iperf-throughput 1 1 VOID

# ── 4. newflow-ceiling: VALID/INVALID/INCONCLUSIVE ───────────────────
#
# exit 1 from this analyzer means "did not measure". Mapping it as a FAIL --
# which is what exit 1 means in mouse_latency_aggregate.py -- is the exact
# confusion the table exists to prevent.
printf '{"verdict":"VALID","reasons":[],"new_flows_per_sec":48000.0,"accept_ratio":0.98,"culprits":[],"elapsed_s":30.0,"active_workers":6}\n' >"$LOG"
expect_field "newflow VALID -> PASS" newflow-ceiling 0 1 PASS
expect_field "newflow VALID headline is the rate" newflow-ceiling 0 3 new_flows_per_sec
# #9922 F-160: VALID from a failed process is a summary the exit status
# contradicts — VOID (ha-smoke policy), never a PASS for a failed teardown.
expect_field "newflow VALID with rc=1 -> VOID, NOT PASS" newflow-ceiling 1 1 VOID
expect_field "newflow VALID rc=1 VOID reason names rc" newflow-ceiling 1 2 "analyzer reported VALID but the harness exited rc=1 — the document and the exit status disagree"
printf '{"verdict":"INVALID","reasons":["zero pool allocations in the window"],"new_flows_per_sec":0.0}\n' >"$LOG"
expect_field "newflow INVALID (exit 1) -> VOID, NOT FAIL" newflow-ceiling 1 1 VOID
printf '{"verdict":"INCONCLUSIVE","reasons":["too few RX queues"],"new_flows_per_sec":9000.0}\n' >"$LOG"
expect_field "newflow INCONCLUSIVE (exit 2) -> VOID" newflow-ceiling 2 1 VOID
printf 'traceback: the analyzer crashed\n' >"$LOG"
expect_field "newflow with no JSON document -> VOID" newflow-ceiling 1 1 VOID
printf '{"verdict":"VALID","reasons":[],"culprits":[]}\n' >"$LOG"
expect_field "newflow VALID without the headline metric -> VOID" newflow-ceiling 0 1 VOID

# ── 5. mouse-latency: the one tool whose exit 1 IS a regression ──────
printf '**Verdict:** FAIL\n  ratio = 3.40 (p99_us loaded 340 us / idle 100 us); threshold <= 2.0\n' >"$LOG"
expect_field "mouse FAIL (exit 1) -> FAIL, NOT VOID" mouse-latency 1 1 FAIL
expect_field "mouse headline is the ratio, lower-better" mouse-latency 1 4 lower-better
printf '**Verdict:** PASS\n  ratio = 1.20 (p99_us loaded 120 us / idle 100 us); threshold <= 2.0\n' >"$LOG"
expect_field "mouse PASS -> PASS" mouse-latency 0 1 PASS
printf '**Verdict:** INSUFFICIENT-DATA\n  reason: 3 of 5 reps voided\n' >"$LOG"
expect_field "mouse INSUFFICIENT-DATA -> VOID" mouse-latency 2 1 VOID
printf 'the aggregator crashed\n' >"$LOG"
expect_field "mouse with no verdict line -> VOID" mouse-latency 1 1 VOID

# ── 6. selftest runner ───────────────────────────────────────────────
printf '  passed=41  skipped=3  failed=0\n' >"$LOG"
expect_field "selftest all-green -> PASS" selftest 0 1 PASS
printf '  passed=39  skipped=3  failed=2\n' >"$LOG"
expect_field "selftest with failed legs -> FAIL" selftest 1 1 FAIL
printf '  passed=0  skipped=0  failed=0\n' >"$LOG"
expect_field "selftest that swept an empty set -> VOID" selftest 0 1 VOID
printf 'the runner died\n' >"$LOG"
expect_field "selftest with no summary -> VOID" selftest 1 1 VOID

# ── 7. An unknown adapter is REFUSED, never defaulted ────────────────
printf 'x\n' >"$LOG"
if harness_adapt not-a-real-adapter 0 "$LOG" >/dev/null 2>&1; then
	bad "an unknown adapter was accepted — a defaulted mapping is how a tool's vocabulary gets guessed"
else
	ok "an unknown adapter is refused (rc 2), never defaulted"
fi
if harness_adapt ha-smoke 0 "$WORK/does-not-exist.log" >/dev/null 2>&1; then
	bad "a missing log was accepted"
else
	ok "a missing log is refused, not treated as an empty (clean) run"
fi

# ── 8. exe_check: four values, because "could not check" is not "fine" ─
check() {
	local got
	got=$(harness_exe_check "$1" "$2" "$3")
	if [[ "$got" == "$4" ]]; then ok "exe_check($1,$2,$3) = $4"; else bad "exe_check($1,$2,$3): want $4 got $got"; fi
}
check aaa aaa cluster MATCH
check aaa bbb cluster MISMATCH
check aaa "" cluster UNAVAILABLE
check "" aaa cluster UNAVAILABLE
check "" "" cluster UNAVAILABLE
check "" "" hermetic NOT-APPLICABLE
check aaa bbb hermetic NOT-APPLICABLE

# ── 8b. build_git_sha: the dirty flag must be able to be OFF ─────────
#
# A throwaway git repo, because the property cannot be observed in this
# worktree: the row being written is itself what makes the tree differ, so a
# naive dirtiness test is permanently ON and the flag stops distinguishing
# anything.
if command -v git >/dev/null 2>&1; then
	REPO="$WORK/fakerepo"
	mkdir -p "$REPO/test/results"
	(
		cd "$REPO" || exit 1
		git init -q . 2>/dev/null
		git config user.email t@t && git config user.name t
		echo hello >src.txt
		git add -A && git commit -qm init
	) >/dev/null 2>&1
	if [ -d "$REPO/.git" ]; then
		clean_sha=$(harness_build_git_sha "$REPO")
		[[ "$clean_sha" != *-dirty ]] &&
			ok "build_git_sha: a pristine tree gets NO -dirty suffix" ||
			bad "build_git_sha: a pristine tree was marked dirty ($clean_sha)"

		mkdir -p "$REPO/test/results/ledger.d"
		printf '{"row":1}\n' >"$REPO/test/results/ledger.d/deadbeef.json"
		with_ledger=$(harness_build_git_sha "$REPO")
		if [[ "$with_ledger" != *-dirty ]]; then
			ok "build_git_sha: the ledger's own new row does NOT make the tree dirty"
		else
			bad "build_git_sha: writing the ledger marked the tree dirty ($with_ledger) — the flag would be permanently ON"
		fi

		# The positive control: a REAL uncommitted change must still set it.
		# Without this cell the fix above is satisfied by never setting the
		# flag at all, which is the same information loss in the other
		# direction.
		echo changed >>"$REPO/src.txt"
		really_dirty=$(harness_build_git_sha "$REPO")
		[[ "$really_dirty" == *-dirty ]] &&
			ok "build_git_sha: a genuine uncommitted change DOES set -dirty" ||
			bad "build_git_sha: a genuine uncommitted change was not marked dirty ($really_dirty)"
	else
		echo "  (skipped build_git_sha cells: git init failed in the sandbox)"
	fi
else
	echo "  (skipped build_git_sha cells: git not installed)"
fi

# ── 9. The emitter's refusals ────────────────────────────────────────
emit_base=(--ledger "$LEDGER" --build-git-sha abc123 --exe-check NOT-APPLICABLE)
refuses() {
	local label="$1"
	shift
	if harness_result_emit "${emit_base[@]}" "$@" >/dev/null 2>&1; then
		bad "emitter ACCEPTED what it must refuse: $label"
	else
		ok "emitter refuses: $label"
	fi
}
accepts() {
	local label="$1"
	shift
	if harness_result_emit "${emit_base[@]}" "$@" >/dev/null 2>&1; then
		ok "emitter accepts: $label"
	else
		bad "emitter REFUSED a valid row: $label"
	fi
}

good=(--gate g --env e --verdict PASS --headline-metric m --headline-direction higher-better --metrics "m=1 n=2")
# The positive control first. A validator that refuses everything satisfies
# every refusal cell below while being useless.
accepts "a well-formed PASS row" "${good[@]}"
accepts "a well-formed VOID row" --gate g --env e --verdict VOID --void-reason "helper restarted"
refuses "a verdict outside PASS/FAIL/VOID" --gate g --env e --verdict MAYBE
refuses "a VOID with an empty reason" --gate g --env e --verdict VOID
refuses "a PASS carrying a void reason" --gate g --env e --verdict PASS --void-reason x \
	--headline-metric m --headline-direction higher-better --metrics "m=1"
refuses "a PASS with an empty metrics map" --gate g --env e --verdict PASS \
	--headline-metric m --headline-direction higher-better --metrics ""
refuses "a headline metric absent from the row's own metrics" --gate g --env e --verdict PASS \
	--headline-metric zz --headline-direction higher-better --metrics "m=1"
refuses "a non-numeric metric value" --gate g --env e --verdict PASS \
	--headline-metric m --headline-direction higher-better --metrics "m=fast"
refuses "an unknown headline direction" --gate g --env e --verdict PASS \
	--headline-metric m --headline-direction sideways --metrics "m=1"
refuses "an empty gate name" --gate "" --env e --verdict PASS \
	--headline-metric m --headline-direction higher-better --metrics "m=1"
refuses "an empty env" --gate g --env "" --verdict PASS \
	--headline-metric m --headline-direction higher-better --metrics "m=1"
if harness_result_emit --ledger "$LEDGER" --build-git-sha abc --exe-check MISMATCH \
	--gate g --env e --verdict PASS --headline-metric m --headline-direction higher-better \
	--metrics "m=1" >/dev/null 2>&1; then
	bad "emitter accepted a PASS with exe_check=MISMATCH — a measurement of an unnameable binary"
else
	ok "emitter refuses a PASS/FAIL with exe_check MISMATCH (#2176)"
fi
if harness_result_emit --ledger "$LEDGER" --build-git-sha abc --exe-check UNAVAILABLE \
	--gate g --env e --verdict FAIL --headline-metric m --headline-direction higher-better \
	--metrics "m=1" >/dev/null 2>&1; then
	bad "emitter accepted a FAIL with exe_check=UNAVAILABLE"
else
	ok "emitter refuses a FAIL with exe_check UNAVAILABLE"
fi
refuses "an unknown exe_check value" --gate g --env e --verdict PASS \
	--headline-metric m --headline-direction higher-better --metrics "m=1" --exe-check PROBABLY

# Exactly the two accepted rows landed: a refused row must write NOTHING.
# Counting SHARDS, not lines: under one file per run (#8346) a row is a file.
ledger_rows() { find "$LEDGER" -maxdepth 1 -name '*.json' 2>/dev/null | wc -l; }
n=$(ledger_rows)
if [[ "$n" == "2" ]]; then
	ok "a refused row writes NOTHING (ledger has exactly the 2 accepted rows)"
else
	bad "ledger has $n rows, expected exactly 2 — a refused row was written anyway"
fi

# A row is always ONE physical line, even when the reason contains a newline.
rm -rf "$LEDGER"
shard=$(harness_result_emit "${emit_base[@]}" --gate g --env e --verdict VOID \
	--void-reason "$(printf 'line one\nline two')" 2>/dev/null)
n=$(ledger_rows)
if [[ "$n" == "1" ]] && [[ "$(wc -l <"$shard")" == "1" ]] &&
	python3 -c "import json,sys; json.loads(open(sys.argv[1]).read())" "$shard" 2>/dev/null; then
	ok "a multi-line void reason still serialises to ONE parseable JSON line"
else
	bad "a multi-line void reason broke the one-row-per-line invariant ($n shards)"
fi

# ── 9b. One file per run: two writes never touch one path (#8346) ────
rm -rf "$LEDGER"
s1=$(harness_result_emit "${emit_base[@]}" --gate g --env e --verdict PASS \
	--headline-metric m --headline-direction higher-better --metrics "m=1" 2>/dev/null)
s2=$(harness_result_emit "${emit_base[@]}" --gate g --env e --verdict PASS \
	--headline-metric m --headline-direction higher-better --metrics "m=2" 2>/dev/null)
if [[ -n "$s1" && -n "$s2" && "$s1" != "$s2" && "$(ledger_rows)" == "2" ]]; then
	ok "two runs write two DIFFERENT paths — the layout is conflict-free by construction"
else
	bad "two runs did not produce two distinct shards (s1=$s1 s2=$s2 count=$(ledger_rows))"
fi
# The filename IS the identity: it is what makes the paths distinct, and it is
# what run_ids_at_rev reads off a git tree WITHOUT parsing the file.
# Checked through the comparator's own lint_shard_names, so the self-test and
# the linter cannot disagree about what "the filename is the identity" means.
if python3 -c "
import sys
sys.path.insert(0, sys.argv[1])
import ledger_compare as lc
probs = lc.lint_shard_names(sys.argv[2])
sys.exit(1 if probs else 0)
" "$SCRIPT_DIR" "$LEDGER"; then
	ok "every shard's filename equals the run_id it contains"
else
	bad "shard filename != run_id — the tree-level run-id set would name a run the file does not describe"
fi
# ...and the control: a shard whose name and payload disagree must be REPORTED.
# Without it, a lint_shard_names that returns [] unconditionally passes above.
cp "$s1" "$LEDGER/nottheid.json"
if python3 -c "
import sys
sys.path.insert(0, sys.argv[1])
import ledger_compare as lc
sys.exit(1 if lc.lint_shard_names(sys.argv[2]) else 0)
" "$SCRIPT_DIR" "$LEDGER"; then
	bad "a shard renamed away from its run_id was NOT reported"
else
	ok "a shard renamed away from its run_id IS reported"
fi
rm -f "$LEDGER/nottheid.json"

# ── 10. The run wrapper ──────────────────────────────────────────────
mkfake() {
	cat >"$WORK/fake-gate.sh"
	chmod +x "$WORK/fake-gate.sh"
}
run_wrapper() {
	# Runs in a subshell so a `return` inside the lib cannot leak here, and so
	# the wrapper's own rc is observable.
	(harness_result_run --ledger "$LEDGER" --hermetic --env testenv "$@" >/dev/null 2>&1)
}
# Reads the SHARD DIRECTORY through the comparator's own loader, so the
# self-test cannot pass on a layout the comparator would reject.
last_row_field() { python3 -c "
import json,sys
sys.path.insert(0, sys.argv[3])
import ledger_compare as lc
rows=lc._sorted_rows([json.loads(l) for l in lc.load_ledger_text(sys.argv[1]).splitlines() if l.strip()])
print(rows[-1][sys.argv[2]] if rows else '<no rows>')
" "$LEDGER" "$1" "$SCRIPT_DIR"; }

rm -rf "$LEDGER"
mkfake <<'FAKE'
#!/usr/bin/env bash
echo "  PASS  iperf3 throughput: 23.1 Gbps (>= 23 Gbps)"
echo "  Failover test: 21 passed, 0 failed"
FAKE
run_wrapper --gate fake-green --adapter ha-smoke -- "$WORK/fake-gate.sh"
rc=$?
[[ "$rc" == "0" ]] && ok "run wrapper: a green gate exits 0" || bad "run wrapper: green gate exited $rc"
[[ "$(last_row_field verdict)" == "PASS" ]] && ok "run wrapper: green gate wrote a PASS row" ||
	bad "run wrapper: green gate wrote $(last_row_field verdict)"

mkfake <<'FAKE'
#!/usr/bin/env bash
echo "  Failover test: 19 passed, 2 failed"
exit 1
FAKE
run_wrapper --gate fake-red --adapter smoke-cells -- "$WORK/fake-gate.sh"
rc=$?
[[ "$rc" == "1" ]] && ok "run wrapper: a failing gate still exits 1 (make test-failover keeps failing)" ||
	bad "run wrapper: failing gate exited $rc, expected 1"
[[ "$(last_row_field verdict)" == "FAIL" ]] && ok "run wrapper: failing gate wrote a FAIL row" ||
	bad "run wrapper: failing gate wrote $(last_row_field verdict)"

# The behaviour CHANGE, and it is in the safe direction: a gate that exits 0
# without reaching its summary used to be indistinguishable from a clean run.
mkfake <<'FAKE'
#!/usr/bin/env bash
echo "starting"
exit 0
FAKE
run_wrapper --gate fake-void --adapter smoke-cells -- "$WORK/fake-gate.sh"
rc=$?
[[ "$rc" == "2" ]] && ok "run wrapper: a gate that exits 0 without a summary exits 2 (VOID), not 0" ||
	bad "run wrapper: silent-exit-0 gate exited $rc, expected 2"
[[ "$(last_row_field verdict)" == "VOID" ]] && ok "run wrapper: silent gate wrote a VOID row" ||
	bad "run wrapper: silent gate wrote $(last_row_field verdict)"

# #9922 F-087: a PASS whose row cannot be written is "passed but unrecorded"
# (exit 2 + NO ROW WRITTEN), never a silent 0. The ledger path is a regular
# FILE here, so the emitter's mkdir fails deterministically and hermetically.
# selftest adapter throughout: its verdict contract is untouched by the F-155
# smoke split, so these cells are stable across it.
touch "$WORK/not-a-ledger-dir"
mkfake <<'FAKE'
#!/usr/bin/env bash
echo "  passed=3  skipped=0  failed=0"
FAKE
out=$(harness_result_run --ledger "$WORK/not-a-ledger-dir" --hermetic --env testenv --gate fake-emitfail --adapter selftest -- "$WORK/fake-gate.sh" 2>&1)
rc=$?
[[ "$rc" == "2" ]] && ok "run wrapper: PASS + emit failure exits 2 (unrecorded), not 0" ||
	bad "run wrapper: PASS + emit failure exited $rc, expected 2"
[[ "$out" == *"NO ROW WRITTEN"* ]] && ok "run wrapper: emit failure prints NO ROW WRITTEN" ||
	bad "run wrapper: emit failure printed no marker"
# A measured FAIL is never demoted by a write failure: rc preserved.
mkfake <<'FAKE'
#!/usr/bin/env bash
echo "  passed=3  skipped=0  failed=1"
exit 1
FAKE
out=$(harness_result_run --ledger "$WORK/not-a-ledger-dir" --hermetic --env testenv --gate fake-emitfail-red --adapter selftest -- "$WORK/fake-gate.sh" 2>&1)
rc=$?
[[ "$rc" == "1" ]] && ok "run wrapper: FAIL + emit failure keeps rc 1" ||
	bad "run wrapper: FAIL + emit failure exited $rc, expected 1"
[[ "$out" == *"NO ROW WRITTEN"* ]] && ok "run wrapper: FAIL + emit failure still prints the marker" ||
	bad "run wrapper: FAIL + emit failure printed no marker"
# rc preservation past 1 (the composite recipes distinguish 1/3/else): a PASS
# verdict with a foreign rc keeps that rc, mirroring the adapter-refusal path.
mkfake <<'FAKE'
#!/usr/bin/env bash
echo "  passed=3  skipped=0  failed=0"
exit 3
FAKE
out=$(harness_result_run --ledger "$WORK/not-a-ledger-dir" --hermetic --env testenv --gate fake-emitfail-rc3 --adapter selftest -- "$WORK/fake-gate.sh" 2>&1)
rc=$?
[[ "$rc" == "3" ]] && ok "run wrapper: PASS verdict + rc 3 + emit failure keeps rc 3" ||
	bad "run wrapper: rc-3 emit failure exited $rc, expected 3"

# ── Cluster mode. `incus` is mocked as a shell function, so this stays
# hermetic: deploy_running_xpfd_sha256 calls `incus` and a function shadows the
# binary at call time (the same mechanism deploy-lib-selftest.sh uses). Without
# the mock these cells would reach the real shared cluster from a self-test.
export XPF_EXE_READBACK_TRIES=1
mkfake <<'FAKE'
#!/usr/bin/env bash
echo "  Failover test: 21 passed, 0 failed"
FAKE

# 10a. The readback fails: the row is VOID and says why. The gate's own output
#      claimed a clean pass -- of a binary nobody can name.
incus() { return 1; }
(harness_result_run --ledger "$LEDGER" --cluster --env testenv --gate fake-cluster \
	--adapter smoke-cells --node fake:node --build-exe "$WORK/no-such-binary" \
	-- "$WORK/fake-gate.sh" >/dev/null 2>&1)
rc=$?
if [[ "$(last_row_field verdict)" == "VOID" ]]; then
	ok "run wrapper: a cluster run whose binary cannot be confirmed records a VOID row, not a PASS"
else
	bad "run wrapper: unconfirmable cluster binary recorded verdict=$(last_row_field verdict)"
fi
# ...and the GATE's own exit status is NOT degraded by it. Reddening the
# mandatory HA gate because ./xpfd was never built in this worktree would be a
# loop layer breaking the gate it exists to measure.
if [[ "$rc" == "0" ]]; then
	ok "run wrapper: an unattributable row does NOT change the gate's exit status (make test-failover still exits 0)"
else
	bad "run wrapper: an unattributable row degraded the gate's exit status to $rc"
fi
if [[ "$(last_row_field void_reason)" == *"exe_check=UNAVAILABLE"* ]]; then
	ok "run wrapper: the VOID reason names exe_check"
else
	bad "run wrapper: VOID reason does not name exe_check: $(last_row_field void_reason)"
fi
if [[ "$(last_row_field exe_check)" == "UNAVAILABLE" ]]; then
	ok "run wrapper: the row records exe_check=UNAVAILABLE"
else
	bad "run wrapper: row exe_check is $(last_row_field exe_check)"
fi

# 10b. The readback SUCCEEDS and agrees with the local build: exe_check=MATCH
#      and the row is a PASS. This is the control that proves the UNAVAILABLE
#      cells above are aimed -- a readback that could never succeed would
#      satisfy every one of them while recording VOID forever.
printf 'pretend xpfd binary\n' >"$WORK/xpfd"
fake_sha=$(sha256sum "$WORK/xpfd" | awk '{print $1}')
incus() { echo "$fake_sha  /proc/1234/exe"; }
(harness_result_run --ledger "$LEDGER" --cluster --env testenv --gate fake-cluster-ok \
	--adapter smoke-cells --node fake:node --build-exe "$WORK/xpfd" \
	-- "$WORK/fake-gate.sh" >/dev/null 2>&1)
rc=$?
if [[ "$rc" == "0" && "$(last_row_field verdict)" == "PASS" && "$(last_row_field exe_check)" == "MATCH" ]]; then
	ok "run wrapper: a readback that matches the local build records exe_check=MATCH and a PASS row"
else
	bad "run wrapper: matching readback gave rc=$rc verdict=$(last_row_field verdict) exe_check=$(last_row_field exe_check)"
fi
if [[ "$(last_row_field running_exe_sha256)" == "$fake_sha" ]]; then
	ok "run wrapper: the row carries the running_exe_sha256 read back from the node"
else
	bad "run wrapper: running_exe_sha256 is '$(last_row_field running_exe_sha256)', expected $fake_sha"
fi

# 10c. The readback succeeds but names a DIFFERENT binary: MISMATCH, the
#      stale-code condition deploy-lib.sh dies on (#2176).
incus() { echo "$(printf 'f%.0s' {1..64})  /proc/1234/exe"; }
(harness_result_run --ledger "$LEDGER" --cluster --env testenv --gate fake-cluster-stale \
	--adapter smoke-cells --node fake:node --build-exe "$WORK/xpfd" \
	-- "$WORK/fake-gate.sh" >/dev/null 2>&1)
if [[ "$(last_row_field verdict)" == "VOID" && "$(last_row_field exe_check)" == "MISMATCH" ]]; then
	ok "run wrapper: a node running a DIFFERENT binary records exe_check=MISMATCH and a VOID row (#2176)"
else
	bad "run wrapper: stale-binary node gave verdict=$(last_row_field verdict) exe_check=$(last_row_field exe_check)"
fi
unset -f incus

# ── 10d-g. #9044: the attestation must cover BOTH nodes of a cluster gate ──
#
# The readback used to read node 0 only, on the ground that "both nodes carry
# the same build after a cluster-deploy". That is a property of ONE way of
# invoking the deploy, not of the system: `make cluster-deploy NODE=0` is a
# plain Makefile override, and an HA smoke FAILS OVER BY DEFINITION, so the
# node the attestation skipped is the node the result depends on.
#
# The mock answers per node, which is the only shape in which a single-node
# readback and a two-node readback give different verdicts — a mock returning
# one sha for every node would pass both the old and the new code.
_peer_incus_mock() {
	# `deploy_running_xpfd_sha256 <node>` puts the node in the argv; match on
	# it rather than on call order, so a changed retry count cannot silently
	# re-target which answer goes to which node.
	local arg
	for arg in "$@"; do
		case "$arg" in
		*fw1*) echo "$PEER_SHA  /proc/1234/exe"; return 0 ;;
		esac
	done
	echo "$fake_sha  /proc/1234/exe"
}

# 10d. THE FINDING. Node 0 matches; the peer runs a DIFFERENT build. Before
#      #9044 this row was a clean MATCH/PASS for a gate that failed over onto
#      the unattested node.
PEER_SHA=$(printf 'a%.0s' {1..64})
incus() { _peer_incus_mock "$@"; }
(harness_result_run --ledger "$LEDGER" --cluster --env testenv --gate fake-peer-stale \
	--adapter smoke-cells --node fake:fw0 --node-peer fake:fw1 --build-exe "$WORK/xpfd" \
	-- "$WORK/fake-gate.sh" >/dev/null 2>&1)
if [[ "$(last_row_field verdict)" == "VOID" && "$(last_row_field exe_check)" == "MISMATCH" ]]; then
	ok "#9044: a peer running a DIFFERENT build makes the row VOID, not a clean MATCH"
else
	bad "#9044: peer-stale run gave verdict=$(last_row_field verdict) exe_check=$(last_row_field exe_check) — this is the shape 'cluster-deploy NODE=0 && test-failover' produces, and it must not record a clean MATCH"
fi
if [[ "$(last_row_field running_exe_sha256_peer)" == "$PEER_SHA" ]]; then
	ok "#9044: the row carries the PEER's running_exe_sha256, so what fw1 was running is recoverable"
else
	bad "#9044: running_exe_sha256_peer is '$(last_row_field running_exe_sha256_peer)', expected $PEER_SHA"
fi
if [[ "$(last_row_field void_reason)" == *"peer_running_exe_sha256"* ]]; then
	ok "#9044: the VOID reason names the peer, so the row says WHICH node was unattributable"
else
	bad "#9044: VOID reason does not name the peer: $(last_row_field void_reason)"
fi

# 10e. THE CONTROL, and it is the one that matters: a properly deployed cluster
#      (NODE=all) must still be a clean MATCH. A guard that voided every
#      cluster gate would satisfy 10d perfectly and be worthless.
PEER_SHA="$fake_sha"
incus() { _peer_incus_mock "$@"; }
(harness_result_run --ledger "$LEDGER" --cluster --env testenv --gate fake-peer-ok \
	--adapter smoke-cells --node fake:fw0 --node-peer fake:fw1 --build-exe "$WORK/xpfd" \
	-- "$WORK/fake-gate.sh" >/dev/null 2>&1)
if [[ "$(last_row_field verdict)" == "PASS" && "$(last_row_field exe_check)" == "MATCH" ]]; then
	ok "#9044: both nodes on the build under test is still a clean MATCH/PASS (the NODE=all path)"
else
	bad "#9044: a correctly deployed cluster gave verdict=$(last_row_field verdict) exe_check=$(last_row_field exe_check) — the guard reds the ordinary path"
fi
if [[ "$(last_row_field exe_scope)" == "both" ]]; then
	ok "#9044: a two-node readback records exe_scope=both"
else
	bad "#9044: exe_scope is '$(last_row_field exe_scope)', expected both"
fi

# 10f. The peer is UNREADABLE. This must NOT be a void: test-ha-crash,
#      test-chained-crash and test-double-failover force-stop a node and may
#      leave it down when the gate ends, so voiding here would red exactly the
#      gates whose job is to kill a node. It is recorded as a SCOPE instead —
#      the fact ("I attested one of the two nodes") the row previously could
#      not express at all.
incus() {
	local arg
	for arg in "$@"; do
		case "$arg" in
		*fw1*) return 1 ;;
		esac
	done
	echo "$fake_sha  /proc/1234/exe"
}
(harness_result_run --ledger "$LEDGER" --cluster --env testenv --gate fake-peer-down \
	--adapter smoke-cells --node fake:fw0 --node-peer fake:fw1 --build-exe "$WORK/xpfd" \
	-- "$WORK/fake-gate.sh" >/dev/null 2>&1)
if [[ "$(last_row_field verdict)" == "PASS" && "$(last_row_field exe_check)" == "MATCH" ]]; then
	ok "#9044: an unreadable peer does NOT void the row (the crash gates leave a node down on purpose)"
else
	bad "#9044: an unreadable peer gave verdict=$(last_row_field verdict) — this reds every gate that force-stops a node"
fi
if [[ "$(last_row_field exe_scope)" == "local-only" ]]; then
	ok "#9044: an unreadable peer records exe_scope=local-only, so a partial attestation is visibly partial"
else
	bad "#9044: exe_scope is '$(last_row_field exe_scope)', expected local-only — without it this row is indistinguishable from a whole-cluster MATCH, which IS the finding"
fi
unset -f incus _peer_incus_mock

# 10g. harness_exe_scope as a table. The three cells above drive it through the
#      wrapper; this pins the function so a wrapper change cannot quietly make
#      every row read `both`.
scope_is() {
	local got
	got=$(harness_exe_scope "$1" "$2" "$3")
	if [[ "$got" == "$4" ]]; then
		ok "exe_scope($1,'$2','$3') = $4"
	else
		bad "exe_scope($1,'$2','$3'): want $4 got $got"
	fi
}
scope_is hermetic "" "" "n/a"
scope_is hermetic "fake:fw1" "abc" "n/a"
scope_is cluster "fake:fw1" "abc" "both"
scope_is cluster "fake:fw1" "" "local-only"
scope_is cluster "" "" "local-only"

# A hermetic run records NOT-APPLICABLE -- distinct from UNAVAILABLE, because
# "there is no deployed binary" and "we could not read the deployed binary" are
# different facts.
[[ "$(python3 -c "
import json,sys
sys.path.insert(0, '$SCRIPT_DIR')
import ledger_compare as lc
rows=[json.loads(l) for l in lc.load_ledger_text('$LEDGER').splitlines() if l.strip()]
print([r['exe_check'] for r in rows if r['gate']=='fake-green'][0])
")" == "NOT-APPLICABLE" ]] &&
	ok "run wrapper: a hermetic run records NOT-APPLICABLE, not UNAVAILABLE" ||
	bad "run wrapper: hermetic run did not record NOT-APPLICABLE"

# Every row the wrapper wrote must satisfy the ledger contract.
if python3 "$SCRIPT_DIR/ledger_compare.py" --lint --ledger "$LEDGER" >/dev/null 2>&1; then
	ok "every row the run wrapper wrote passes ledger-lint"
else
	bad "rows written by the run wrapper do not pass ledger-lint"
	python3 "$SCRIPT_DIR/ledger_compare.py" --lint --ledger "$LEDGER" 2>&1 | sed 's/^/    /'
fi


# ── 11. wire-gate adapter (#9531) ────────────────────────────────────
#
# Canonical line: WIRE_GATE <gate> <PASS|FAIL|VOID> reason=<slug> <k=v...>.
# reason is `--` on PASS/FAIL, a design-§8 closed slug on VOID. The adapter
# transcribes; it never re-derives a verdict from metrics.
wire_log() { printf '%b' "$1" >"$LOG"; }
wire_field_is() {
	local label="$1" rc="$2" n="$3" want="$4" got
	got=$(adapt_field wire-gate "$rc" "$n")
	if [[ "$got" == "$want" ]]; then
		ok "wire-gate: $label"
	else
		bad "wire-gate: $label (field $n: want '$want', got '$got')"
	fi
}
wire_field_has() {
	local label="$1" rc="$2" n="$3" want="$4" got
	got=$(adapt_field wire-gate "$rc" "$n")
	if [[ "$got" == *"$want"* ]]; then
		ok "wire-gate: $label"
	else
		bad "wire-gate: $label (field $n does not contain '$want': '$got')"
	fi
}
DENY_OK='WIRE_GATE wire_policy_deny PASS reason=-- probe_offered=1000 probe_leaked=0 control_offered=1000 control_observed=1000\n'
wire_log "$DENY_OK"
wire_field_is "deny PASS transcribes" 0 1 "PASS"
wire_field_is "deny headline is probe_leaked" 0 3 "probe_leaked"
wire_field_is "deny direction lower-better" 0 4 "lower-better"
wire_field_has "deny metrics keep the offered counts" 0 5 "probe_offered=1000"
wire_log 'WIRE_GATE wire_policy_deny FAIL reason=-- probe_offered=1000 probe_leaked=7 control_offered=1000 control_observed=1000\n'
wire_field_is "deny FAIL transcribes" 0 1 "FAIL"
wire_field_has "deny FAIL keeps the leak count" 0 5 "probe_leaked=7"
wire_log 'WIRE_GATE wire_policy_deny VOID reason=capture-blind probe_offered=1000 probe_leaked=0 control_offered=1000 control_observed=0\n'
wire_field_is "deny VOID transcribes" 0 1 "VOID"
wire_field_is "deny VOID keeps the closed slug" 0 2 "capture-blind"
wire_field_has "deny VOID keeps measured metrics" 0 5 "control_observed=0"
wire_log 'WIRE_GATE wire_policy_deny VOID reason=env-void\n'
wire_field_is "early VOID with an empty map is legal" 0 1 "VOID"
wire_field_is "early VOID keeps env-void" 0 2 "env-void"
wire_log 'WIRE_GATE cc-rollback-arm-b VOID reason=row-timeout mid_present=0 mid_fwd_ok=0 post_gone=0 post_blocked=0 sess_gone=0\n'
wire_field_is "arm-b row-timeout VOID transcribes" 0 1 "VOID"
wire_field_is "arm-b VOID keeps row-timeout" 0 2 "row-timeout"
wire_log 'some noise, no verdict line\n'
wire_field_is "absent line is VOID, never a pass" 0 1 "VOID"
wire_field_has "absent line names the missing line" 0 2 "no \"WIRE_GATE"
ZONE_OK='WIRE_GATE wire_zone_matrix PASS reason=-- cells_measured=12 cells_failed=0 deny_cells=6 permit_cells=6 deny_leaked=0 permit_missing=0 control_missing=0 duplicate_frames=0 permit64_offered=60000 permit64_observed=60000 permit1400_offered=60000 permit1400_observed=60000 cksum_bad=0\n'
wire_log "$ZONE_OK"
wire_field_is "zone matrix PASS transcribes" 0 1 "PASS"
wire_field_is "zone matrix headline is cells_failed" 0 3 "cells_failed"
wire_field_has "zone matrix keeps duplicate metric" 0 5 "duplicate_frames=0"
wire_log 'WIRE_GATE wire_hostinbound_deny FAIL reason=-- cells_measured=2 syn_offered=2000 handshake_completed=1 refused_total=0 exposed_total=1 reply_frames=1 ctrl_offered=1500 ctrl_observed=1500 cksum_bad=0\n'
wire_field_is "host-inbound exposure FAIL transcribes" 0 1 "FAIL"
wire_field_is "host-inbound headline is exposed_total" 0 3 "exposed_total"
wire_field_has "host-inbound keeps reply frames" 0 5 "reply_frames=1"
wire_log 'WIRE_GATE wire_conntrack_lifecycle VOID reason=under-sampled created=1 witnessed=1 evicted=1 stale_present=0 exp_offered=999 exp_leaked=0 fresh_offered=1000 fresh_leaked=0 syn_offered=1500 syn_observed=1500 ctrl_sess=1 lifecycle_bad=0 cksum_bad=0\n'
wire_field_is "conntrack under-sample VOID transcribes" 0 1 "VOID"
wire_field_is "conntrack VOID keeps under-sampled" 0 2 "under-sampled"
wire_field_has "conntrack keeps lifecycle metric" 0 5 "lifecycle_bad=0"
wire_log 'WIRE_GATE wire_policy_deny PASS reason=-- probe_offered=1000 probe_leaked=0 control_offered=1000 control_observed=1000\nWIRE_GATE wire_appmatch_twins PASS reason=-- tcp80_offered=1\n'
wire_field_is "two gate IDs in one log is VOID" 0 1 "VOID"
wire_field_has "two gate IDs says why" 0 2 "distinct WIRE_GATE gate IDs"
wire_log 'WIRE_GATE wire_policy_deny PASS reason=policy_leak probe_offered=1000 probe_leaked=0 control_offered=1000 control_observed=1000\n'
wire_field_is "PASS carrying a slug is VOID" 0 1 "VOID"
wire_field_has "PASS-with-slug names the contract" 0 2 "must carry reason=--"
wire_log "$DENY_OK"
wire_field_is "PASS with rc!=0 is VOID (disagreement)" 1 1 "VOID"
wire_field_has "disagreement says so" 1 2 "disagree"
wire_log 'WIRE_GATE wire_policy_deny FAIL reason=-- probe_offered=1000 probe_leaked=7 control_offered=1000 control_observed=1000\n'
wire_field_is "FAIL stands whatever rc" 0 1 "FAIL"
wire_log 'WIRE_GATE wire_policy_deny PASS reason=-- probe_offered=1000 probe_leaked=0\n'
wire_field_is "PASS missing required keys is VOID" 0 1 "VOID"
wire_field_has "missing keys are named" 0 2 "control_offered,control_observed"
wire_log 'WIRE_GATE wire_policy_deny PASS reason=-- probe_offered=1000 probe_leaked=x control_offered=1000 control_observed=1000\n'
wire_field_is "PASS with a corrupt metric is VOID" 0 1 "VOID"
wire_log 'WIRE_GATE wire_policy_deny VOID reason=bogus\n'
wire_field_is "unknown VOID slug is VOID" 0 1 "VOID"
wire_field_has "unknown slug cites the closed taxonomy" 0 2 "closed taxonomy"
wire_log 'WIRE_GATE nope_gate PASS reason=-- a=1\n'
wire_field_is "unknown gate is refused, never defaulted" 0 1 "VOID"
wire_field_has "unknown gate says so" 0 2 "unknown gate nope_gate"
wire_log 'WIRE_GATE wire_appmatch_twins PASS reason=-- tcp80_offered=10000 tcp80_observed=10000 tcp8080_offered=1000 tcp8080_observed=0 udp53_offered=10000 udp53_observed=10000 udp5353_offered=1000 udp5353_observed=0 deny_leaked=0 permit_missing=0\n'
wire_field_is "appmatch PASS transcribes" 0 1 "PASS"
wire_field_is "appmatch headline is deny_leaked" 0 3 "deny_leaked"
wire_log 'WIRE_GATE test-host-inbound PASS reason=-- cells_passed=24 cells_failed=0\n'
wire_field_is "host-inbound PASS transcribes" 0 1 "PASS"
wire_field_is "host-inbound headline is cells_failed" 0 3 "cells_failed"
wire_log 'WIRE_GATE cc-rollback-arm-b PASS reason=-- mid_present=1 mid_fwd_ok=1 post_gone=1 post_blocked=1 sess_gone=1\n'
wire_field_is "arm-b PASS transcribes" 0 1 "PASS"
wire_field_is "arm-b headline is sess_gone" 0 3 "sess_gone"
wire_log 'WIRE_GATE cc-rollback-arm-b FAIL reason=-- mid_present=1 mid_fwd_ok=1 post_gone=1 post_blocked=0 sess_gone=0\n'
wire_field_is "arm-b stale-permit shape transcribes FAIL" 0 1 "FAIL"
wire_field_is "arm-b FAIL headline is sess_gone" 0 3 "sess_gone"
wire_log 'WIRE_GATE cc-rollback-arm-b VOID reason=harness-void mid_present=1 mid_fwd_ok=1 post_gone=0 post_blocked=0 sess_gone=0\n'
wire_field_is "arm-b VOID transcribes" 0 1 "VOID"
wire_field_is "arm-b VOID keeps the closed slug" 0 2 "harness-void"
wire_field_has "arm-b VOID keeps measured stage flags" 0 5 "mid_fwd_ok=1"
wire_log 'WIRE_GATE cc-rollback-arm-a FAIL reason=-- mid_blocked=1 post_present=1 post_fwd_ok=0\n'
wire_field_is "arm-a FAIL transcribes" 0 1 "FAIL"
wire_field_is "arm-a headline is post_fwd_ok" 0 3 "post_fwd_ok"
# ── summary ──────────────────────────────────────────────────────────
echo
echo "  harness-result selftest: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]] || exit 1
# An empty sweep is not a pass: if the cells above stopped executing (a source
# failure, a renamed function) PASS is 0 and this is the only thing that says so.
[[ "$PASS" -gt 0 ]] || {
	echo "FAIL: the selftest ran ZERO cells" >&2
	exit 1
}
exit 0
