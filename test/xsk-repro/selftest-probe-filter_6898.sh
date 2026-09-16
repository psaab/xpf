#!/bin/sh
# #6898 A10-b5-F1: behavioural gate for the reproducer's probe filter.
#
# The XDP program redirects EVERY packet on the queue to the XSK, so the receive
# counters used to count all interface traffic. `rx > 0` was then satisfiable by
# an ARP or an IPv6 RA while the tool's own probes never arrived — the exact
# failure the reproducer exists to detect, reported as PASS.
#
# This runs the crate's unit tests for `is_probe_frame`. Reverting the filter
# (counting every descriptor) or splitting the marker into two literals makes
# them RED.
#
# Unlike its sibling selftests this is a BEHAVIOURAL gate, not a strict-warning
# compile: the defect it guards compiles perfectly.
#
# SKIPs (77) on a host without cargo, or without the vendored deps to build
# offline — matching the tool-gating convention of the other legs.
#
# --selftest runs hermetic fixture cells over the shared assertions (no cargo).
set -e

check_out() {
	# Shared cargo-output assertions for the live gate AND --selftest cells:
	# the summary line plus each behavioural cell by name. Prints the FAIL
	# line on failure, quiet on success; returns 0/1.
	_co_out="$1"
	# Guard against a vacuous pass: cargo reports ok for zero tests just as happily.
	if ! echo "$_co_out" | grep -qE "test result: ok\. [1-9][0-9]* passed"; then
		echo "FAIL: no tests ran (a filter matching nothing reports ok and exits 0)"
		return 1
	fi
	# Guard against guarded-cell deletion: the summary line above is satisfied by ANY
	# passing test, so assert each behavioural cell by name. By-name WITHOUT an
	# exact count — future added cells must not break this gate.
	for _co_cell in probe_frame_is_recognised_at_any_offset foreign_traffic_is_not_counted_as_a_probe short_frames_do_not_panic generator_and_matcher_share_one_marker; do
		if ! echo "$_co_out" | grep -qE "^test tests::${_co_cell} \.\.\. ok\$"; then
			echo "FAIL: expected cell tests::${_co_cell} did not pass (deleted, renamed, or failing)"
			return 1
		fi
	done
	return 0
}

if [ "${1:-}" = "--selftest" ]; then
	# Hermetic fixture cells over the shared check_out core: no cargo, no
	# build, no network. Each negative is a minimal delta from FIX_FULL (its
	# paired twin), proving the assertion keys on that delta. Fixtures are
	# shape-faithful canned `cargo test` outputs (header + cell lines + summary).
	FIX_FULL='running 4 tests
test tests::foreign_traffic_is_not_counted_as_a_probe ... ok
test tests::generator_and_matcher_share_one_marker ... ok
test tests::probe_frame_is_recognised_at_any_offset ... ok
test tests::short_frames_do_not_panic ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s'
	FIX_VACUOUS='running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s'
	# Twin of FIX_FULL minus THE load-bearing cell (summary drops to 3 passed,
	# as real cargo would print after the deletion).
	FIX_DELETED='running 3 tests
test tests::generator_and_matcher_share_one_marker ... ok
test tests::probe_frame_is_recognised_at_any_offset ... ok
test tests::short_frames_do_not_panic ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s'
	# Twin of FIX_FULL with one cell renamed (a different cell than the
	# deleted one, so the two negatives cover two of the four cells).
	FIX_RENAMED='running 4 tests
test tests::foreign_traffic_is_not_counted_as_a_probe ... ok
test tests::generator_and_matcher_share_one_marker ... ok
test tests::probe_frame_is_recognised_at_any_offset_renamed ... ok
test tests::short_frames_do_not_panic ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s'
	# Twin of FIX_FULL plus a fifth cell (as real cargo would print after an
	# addition): must still PASS — no exact-count anywhere.
	FIX_FIFTH='running 5 tests
test tests::a_brand_new_fifth_cell ... ok
test tests::foreign_traffic_is_not_counted_as_a_probe ... ok
test tests::generator_and_matcher_share_one_marker ... ok
test tests::probe_frame_is_recognised_at_any_offset ... ok
test tests::short_frames_do_not_panic ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s'
	ok=0; bad=0
	expect_pass() {
		_ep_label="$1"; _ep_out="$2"
		if _ep_msg=$(check_out "$_ep_out"); then
			echo "  PASS  $_ep_label"
			ok=$((ok + 1))
		else
			echo "  FAIL  $_ep_label (expected PASS, got '$_ep_msg')"
			bad=$((bad + 1))
		fi
	}
	expect_fail() {
		_ef_label="$1"; _ef_out="$2"; _ef_want="$3"
		if _ef_msg=$(check_out "$_ef_out"); then
			echo "  FAIL  $_ef_label (expected FAIL, got PASS)"
			bad=$((bad + 1))
		else
			case "$_ef_msg" in
				*"$_ef_want"*)
					echo "  PASS  $_ef_label"
					ok=$((ok + 1))
					;;
				*)
					echo "  FAIL  $_ef_label (FAIL did not name '$_ef_want': '$_ef_msg')"
					bad=$((bad + 1))
					;;
			esac
		fi
	}
	expect_pass "full canned output passes" "$FIX_FULL"
	expect_fail "summary-only vacuous output fails" "$FIX_VACUOUS" "no tests ran"
	expect_fail "THE-cell-deleted output fails naming it" "$FIX_DELETED" "foreign_traffic_is_not_counted_as_a_probe"
	expect_fail "one-cell-renamed output fails naming it" "$FIX_RENAMED" "probe_frame_is_recognised_at_any_offset"
	expect_pass "added fifth cell still passes (no exact-count)" "$FIX_FIFTH"
	echo "  selftest-probe-filter selftest: $ok passed, $bad failed"
	if [ "$bad" -ne 0 ]; then exit 1; fi
	if [ "$ok" -eq 0 ]; then echo "FAIL: zero cells ran"; exit 1; fi
	exit 0
fi

cd "$(dirname "$0")"

if ! command -v cargo >/dev/null 2>&1; then
	echo "SKIP: cargo not available"
	exit 77
fi

if ! out=$(cargo test --offline 2>&1); then
	case "$out" in
	*"no matching package"*|*"failed to download"*|*"offline"*)
		echo "SKIP: cargo cannot build offline (deps unavailable)"
		exit 77
		;;
	esac
	echo "FAIL: xsk-repro unit tests"
	echo "$out"
	exit 1
fi

# Shared assertions (summary + by-name cells); check_out prints the FAIL line.
if ! check_out "$out"; then
	echo "$out"
	exit 1
fi
echo "PASS: xsk-repro probe-filter tests"
exit 0
