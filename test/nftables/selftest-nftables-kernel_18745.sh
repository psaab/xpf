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
# Which tests must PASS is read from the package's own source (#19141):
# every top-level `func TestXxx(t *testing.T)` in pkg/nftables/*_test.go,
# compared NAME FOR NAME with the `--- PASS:` lines. A declared test that did
# not PASS means the run was narrowed (or the test failed); a PASS the scan
# did not find means the scan is narrower than the compiler, and either one
# fails. The package total used to be a hand-set count. It was right when it
# landed (216, 6b11dee651) and went stale two commits later, when #18728's
# tests landed from a branch cut before the count existed; #19088 added one
# more, and the leg was red over a complete run for that alone. What
# the scan no longer notices is a non-kernel test DELETED from source; that
# deletion is in the diff that makes it.
# The 36 kernel-cell names below stay a manual pin: deleting or renaming a
# kernel cell must fail here until the list is deliberately updated. The
# shell censuses prove runner discovery and reachability, not coverage of Go
# test source names.
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
runner="$(cd "$(dirname "$0")/../.." && pwd)/scripts/testguard-run.sh"
out=$(XPF_REQUIRE_NETNS=1 "$runner" "$GO" test -json=false -count=1 -v -run '^Test' -skip '' ./pkg/nftables/ 2>&1)
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
# The declared set, from the same tree `go test ./pkg/nftables/` compiles: a
# top-level Test function per Go's rule (no lowercase letter after "Test").
declared=$(sed -n -E 's/^func (Test([A-Z0-9_][A-Za-z0-9_]*)?)\([A-Za-z_][A-Za-z0-9_]* \*testing\.T\).*/\1/p' ./pkg/nftables/*_test.go 2>/dev/null | sort)
declared_count=$(printf '%s\n' "$declared" | grep -c . || true)
ran=$(printf '%s\n' "$out" | sed -n -E 's/^--- PASS: (Test[^[:space:]]*)[[:space:]].*/\1/p' | sort)
if [ "$declared_count" -eq 0 ]; then
	echo "FAIL: found no Test functions in ./pkg/nftables/*_test.go — the scan cannot say which tests had to run"
	fail=1
fi
# "missing NAME": declared, did not PASS. "unscanned NAME": PASSed, not found
# by the scan. The separator cannot be a Go identifier.
set_diff=$(printf '%s\n%s\n%s\n' "$declared" '--' "$ran" | awk '
	$0 == "--" { second = 1; next }
	$0 == "" { next }
	!second { d[$0] = 1; next }
	{ r[$0] = 1 }
	END {
		for (n in d) if (!(n in r)) print "missing " n
		for (n in r) if (!(n in d)) print "unscanned " n
	}' | sort)
missing=$(printf '%s\n' "$set_diff" | sed -n 's/^missing //p')
unscanned=$(printf '%s\n' "$set_diff" | sed -n 's/^unscanned //p')
if [ -n "$missing" ]; then
	echo "FAIL: $(printf '%s\n' "$missing" | grep -c .) of the $declared_count Test functions in ./pkg/nftables/*_test.go did not PASS — the package run was narrowed, or they failed:"
	printf '%s\n' "$missing" | sed 's/^/      /'
	fail=1
fi
if [ -n "$unscanned" ]; then
	echo "FAIL: tests PASSed that the source scan did not find — the scan is narrower than the compiler, so it cannot vouch for the run; fix the scan:"
	printf '%s\n' "$unscanned" | sed 's/^/      /'
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
