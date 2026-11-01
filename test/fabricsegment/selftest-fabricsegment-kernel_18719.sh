#!/bin/sh
# selftest-fabricsegment-kernel_18719.sh — run the pkg/fabricsegment
# real-kernel cells (#18719, #18751 review) under `unshare -rn` with
# XPF_REQUIRE_NETNS=1.
#
# The cells drive the fabric-segment watcher's real AF_PACKET tap on veth
# pairs: nothing queued before bind, the kernel cBPF filter (counted with
# PACKET_STATISTICS, so an accept-all filter cannot hide behind the
# userspace re-check), the IEEE 802.1 link-constrained exclusion, and the
# reader surviving a parent down/up and a bind while the parent is down.
# Under a plain `go test` they SKIP, and a skipped cell reads exactly like a
# passing one, so this leg forces them and checks every cell BY NAME.
#
# It cannot establish production visibility: no XDP program is attached
# here, and on a fabric parent the shim runs before every AF_PACKET tap.
# That is the loss gate's positive control (docs/fabric-cross-chassis-fwd.md).
#
# The names below must match TapSamplerKernelCells18719 in
# pkg/fabricsegment/sampler_linux_test.go; TestKernelCellRegistryMatchesTheLeg18719
# pins both directions.
#
# Exit codes follow the selftest contract: 0 = PASS, 77 = SKIP (a tool or
# capability this host does not have), anything else = FAIL.

set -u

GO=${GO:-go}

if ! command -v "$GO" >/dev/null 2>&1; then
	echo "SKIP: $GO not installed — cannot run the fabric-segment kernel cells"
	exit 77
fi
if ! command -v unshare >/dev/null 2>&1; then
	echo "SKIP: unshare not found — cannot self-isolate a private netns"
	exit 77
fi
if ! unshare -rn true 2>/dev/null; then
	echo "SKIP: cannot create a private netns (needs unprivileged userns or root)"
	exit 77
fi

CELLS="TestTapSamplerOnARealSegment18719 TestTapSamplerSurvivesParentDownUp18719 TestTapSamplerBoundWhileParentDown18719"
pattern=$(printf '%s' "$CELLS" | tr ' ' '|')

# -count=1: a cached PASS must never stand in for a run that did not happen.
# -json=false: the guard below scans anchored `=== RUN` records.
out=$(XPF_REQUIRE_NETNS=1 unshare -rn "$GO" test -json=false -count=1 -v -run "^(${pattern})\$" ./pkg/fabricsegment/ 2>&1)
rc=$?

fail=0
for cell in $CELLS; do
	if ! printf '%s\n' "$out" | grep -q "^=== RUN   $cell\$"; then
		echo "FAIL: $cell did not run — the -run predicate has rotted"
		fail=1
	fi
	if printf '%s\n' "$out" | grep -q -- "--- SKIP: $cell "; then
		echo "FAIL: $cell SKIPPED under XPF_REQUIRE_NETNS=1 — the forcing broke"
		fail=1
	fi
	if ! printf '%s\n' "$out" | grep -q -- "^--- PASS: $cell "; then
		echo "FAIL: $cell did not pass"
		fail=1
	fi
done
if [ "$rc" -ne 0 ] || [ "$fail" -ne 0 ]; then
	printf '%s\n' "$out"
	echo "FAIL: fabric-segment kernel cells (go test rc=$rc)"
	exit 1
fi
echo "PASS: fabric-segment kernel cells ($(printf '%s' "$CELLS" | wc -w | tr -d ' ') by name, under XPF_REQUIRE_NETNS=1)"
exit 0
