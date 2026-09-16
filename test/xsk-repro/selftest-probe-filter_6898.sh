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
set -e
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

# Guard against a vacuous pass: cargo reports ok for zero tests just as happily.
if ! echo "$out" | grep -qE "test result: ok\. [1-9][0-9]* passed"; then
	echo "FAIL: no tests ran (a filter matching nothing reports ok and exits 0)"
	echo "$out"
	exit 1
fi

# Guard against guarded-cell deletion: the summary line above is satisfied by ANY
# passing test, so assert each behavioural cell by name. By-name WITHOUT an
# exact count — future added cells must not break this gate.
for cell in probe_frame_is_recognised_at_any_offset foreign_traffic_is_not_counted_as_a_probe short_frames_do_not_panic generator_and_matcher_share_one_marker; do
	if ! echo "$out" | grep -qE "^test tests::${cell} \.\.\. ok\$"; then
		echo "FAIL: expected cell tests::${cell} did not pass (deleted, renamed, or failing)"
		echo "$out"
		exit 1
	fi
done
echo "PASS: xsk-repro probe-filter tests"
exit 0
