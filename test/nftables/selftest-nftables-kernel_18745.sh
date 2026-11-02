#!/bin/sh
# selftest-nftables-kernel_18745.sh — run EVERY pkg/nftables test under a
# private network namespace with XPF_REQUIRE_NETNS=1, and count any SKIP as
# a failure (#18745).
#
# Why: the pkg/nftables real-kernel cells enter a netns with enterPrivateNetns
# and friends, which SKIP when the namespace cannot be created. Under a plain
# `go test` they all skip, and a skip reads like a pass in aggregate output.
# #16841 broke two of them, #13955 two more, and #10483 and #11574 one
# each. All six sat red for weeks with nothing to show it. This is the same
# class as #15241, whose leg forces only the pkg/daemon kernel cells.
#
# The whole package runs: the -run flag is pinned to '^Test' below rather
# than trusted from the environment, because an inherited GOFLAGS=-run (or
# -skip) previously filtered the leg down to one passing non-kernel cell
# and reported a whole-package PASS (#18841 review). A name filter that
# comes from the caller rots exactly the way a hand-maintained one does
# (#6743 r2-N3).
# The expected 216-test package count and the 36 kernel-cell names below are
# manual pins. A changed package test count or a missing named kernel cell
# fails closed; any new or renamed kernel cell requires a deliberate review
# and update of the list and count. The shell censuses prove runner discovery
# and reachability, not coverage of Go test source names.
#
# A SKIP line, top-level or subtest, is a failure here, because under
# XPF_REQUIRE_NETNS=1 every skip arm these cells have means the forcing
# broke, and the hermetic tests that do not touch a netns never skip.
# The leg exits 77 (SKIP) when the capability probes fail on this host,
# but under XPF_REQUIRE_NETNS=1 the Makefile wrapper converts that 77
# into a failure instead of NOT-EXAMINED.
#
# Exit codes follow the selftest contract: 0 = PASS, 77 = SKIP (a tool
# or capability this host does not have), anything else = FAIL.

set -u

GO=${GO:-go}

if ! command -v "$GO" >/dev/null 2>&1; then
	echo "SKIP: $GO not installed — cannot run the pkg/nftables kernel cells"
	exit 77
fi
if ! command -v unshare >/dev/null 2>&1; then
	echo "SKIP: unshare not found — cannot self-isolate a private netns"
	exit 77
fi
# Probe the capability rather than assuming it: unprivileged user namespaces
# are disabled on some hosts.
if ! unshare -rn true 2>/dev/null; then
	echo "SKIP: cannot create a private netns (needs unprivileged userns or root)"
	exit 77
fi

expected_kernel_count=36
expected_kernel_cells='
TestArmedBridgeFenceLoadsInKernel10641
TestCounterReadbackThroughExistingReaders
TestDHCPBackstopMixedL2L3Frames12127
TestEarlyInputBarrierDiscriminatesVRFMembers15286
TestEarlyInputBarrierNetlinkLifecycle10751
TestFenceTableReadsCounterless
TestGapExceptionDiscriminatesVRFMembers10751
TestGapFenceWithholdsSharedNetns10751
TestGapLifelineExceptionBothIngress10751
TestHostInboundEstablishedUDPFloodDropsAboveThreshold11087
TestHostInboundGapRetainedBackstop11577
TestHostInboundNonUnicastUDPDelivery13925
TestInstallLo0ReportsZeroForAnEmptyRender18746
TestIpsecDivertInstallsBothFamiliesAtomically9506
TestIpsecQuarantineGuardVerify16703
TestIpsecQuarantineGuardWithLifelinesLoadsInKernel16618
TestIpsecQuarantineInstallRemoveRoundTrip9506
TestKernelStoresTheIntervalSetAsEmitted_8597
TestLargeReplaceRecoversUncertainAck12128
TestLo0CounterReadback
TestNetlinkInstallLoadsInKernel
TestNetlinkSocketBufferLimit12128
TestOverlayReadbackFailsClosedOnAMidReadbackCommit18721
TestProbeNFTablesAvailableLive
TestRSTSuppressionDropsConntracklessRSTLive15727
TestRSTSuppressionSparesLiveSocketRSTLive16839
TestTableDropsInputRequiresDropVerdict10751
TestTableEnforcingDistinguishesShellTables10751
TestTablePredicatesAreGenerationBracketed18746
TestTablePredicatesIgnoreOnlyTheZeroHopRule18746
TestUnleasedBackstopAtomicReplace10751
TestUnleasedBackstopFamilyGuard10751
TestUnleasedDHCPAcquisitionThroughBackstop10751
TestUnleasedDHCPv4BroadcastFallsThroughL3Backstop12127
TestZonedDHCPBareMemberVLANVRFLeaseWindow11577
TestZonedDHCPLeaseAppearanceWindow11577
'

# Keep both filters explicit: flags from GOFLAGS are parsed before command-line
# flags, so these values override inherited -run and -skip selections.
# -count=1: a cached PASS must never stand in for a run that did not happen.
# -json=false pins text output for the line scans below.
out=$(XPF_REQUIRE_NETNS=1 unshare -rn "$GO" test -json=false -count=1 -v -run '^Test' -skip '' ./pkg/nftables/ 2>&1)
rc=$?

fail=0
skips=$(printf '%s\n' "$out" | grep -E '^[[:space:]]*--- SKIP: ' || true)
if [ -n "$skips" ]; then
	echo "FAIL: pkg/nftables cells SKIPPED under XPF_REQUIRE_NETNS=1 — the forcing broke:"
	printf '%s\n' "$skips" | sed 's/^/      /'
	fail=1
fi
fails=$(printf '%s\n' "$out" | grep -E '^[[:space:]]*--- FAIL: ' || true)
if [ -n "$fails" ]; then
	echo "FAIL: pkg/nftables tests failed:"
	printf '%s\n' "$fails" | sed 's/^/      /'
	fail=1
fi
if [ "$rc" -ne 0 ]; then
	echo "FAIL: go test exited $rc"
	fail=1
fi
passed=$(printf '%s\n' "$out" | grep -cE '^--- PASS: Test[^[:space:]]+[[:space:]]' || true)
if [ "$passed" -ne 216 ]; then
	echo "FAIL: expected all 216 pkg/nftables tests to PASS, got $passed — the package was narrowed or its expected cell count changed"
	fail=1
fi
kernel_list_count=$(printf '%s\n' "$expected_kernel_cells" | grep -cE '^Test[^[:space:]]+$' || true)
if [ "$kernel_list_count" -ne "$expected_kernel_count" ]; then
	echo "FAIL: internal expected kernel-cell list has $kernel_list_count names, want $expected_kernel_count"
	fail=1
fi
for cell in $expected_kernel_cells; do
	if ! printf '%s\n' "$out" | grep -qE "^--- PASS: $cell([[:space:]]|$)"; then
		echo "FAIL: expected kernel cell did not PASS: $cell"
		fail=1
	fi
done
if [ "$fail" -ne 0 ]; then
	printf '%s\n' "$out" | grep -vE '^(=== (RUN|PAUSE|CONT)|--- PASS|    --- PASS)' | tail -60 | sed 's/^/      /'
	exit 1
fi
echo "PASS: all $passed pkg/nftables tests ran; all $expected_kernel_count pinned kernel cells passed under a forced netns; no SKIP"
exit 0
