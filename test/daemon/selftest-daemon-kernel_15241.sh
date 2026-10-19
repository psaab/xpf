#!/bin/sh
# selftest-daemon-kernel_15241.sh — run the pkg/daemon host-inbound
# real-kernel cells (#15241 A58-06: 9637 x2, 11409, 12034, 12229, 12087).
#
# Why this leg exists at all: the #9637 ingress, #11409 unzoned-ingress,
# #9637 reinject-TUN, #12034 shared-VRF, #12229 lifeline deny-all and
# #12087 secure-tunnel VRF cells are kernel halves of their fixes. The
# pre-fix code passed shape-side tests; the failures were entirely in
# what the KERNEL judged. The only instrument that can see these is one
# that talks to a real kernel.
#
# Why it is not simply part of `make test-go`: the cells need to create
# a private netns, so under a plain `go test` they SKIP -- and a skipped
# cell is indistinguishable from a passing one in aggregate output. That
# is the exact shape that lets a kernel-semantics regression sit green
# forever. This leg runs them under `unshare -rn` with
# XPF_REQUIRE_NETNS=1, where (#15241) every tool-absent arm -- nft,
# unshare, ip and friends, checked before the namespace is even
# attempted -- is a failure, not a skip. Before A58-06 those arms
# skipped before the forcing check on the netns-start arm could fire,
# and no runner set the env for pkg/daemon at all (the #9812/#11418
# forcing covered pkg/routing only).
#
# The predicate runs the issue-numbered cells in pkg/daemon. The guard
# below pins all six kernel cells BY NAME, because a `-run` predicate
# that rots matches nothing and reports a clean pass over an empty set.
#
# Exit codes follow the selftest contract: 0 = PASS, 77 = SKIP (a tool
# or capability this host does not have), anything else = FAIL.

set -u

GO=${GO:-go}

if ! command -v "$GO" >/dev/null 2>&1; then
	echo "SKIP: $GO not installed — cannot run the kernel cells"
	exit 77
fi

if ! command -v unshare >/dev/null 2>&1; then
	echo "SKIP: unshare not found — cannot self-isolate a private netns"
	exit 77
fi

if ! command -v ip >/dev/null 2>&1; then
	echo "SKIP: iproute2 not found — the kernel cells drive the FIB through ip"
	exit 77
fi

if ! command -v bash >/dev/null 2>&1; then
	echo "SKIP: bash not found — the kernel cells drive their netns scripts through bash"
	exit 77
fi

if ! command -v nsenter >/dev/null 2>&1; then
	echo "SKIP: nsenter not found — the kernel cells enter client namespaces with nsenter"
	exit 77
fi

if ! command -v timeout >/dev/null 2>&1; then
	echo "SKIP: timeout not found — the kernel cells bound their probes with timeout"
	exit 77
fi

if ! command -v sleep >/dev/null 2>&1; then
	echo "SKIP: sleep not found — the kernel cells hold client namespaces open with sleep"
	exit 77
fi

# findNft in the tests also probes /usr/sbin/nft and /sbin/nft (nft ships
# in /usr/sbin on the target distro, off a non-root PATH); mirror that
# here so the probe measures the same lookup the cells perform.
if ! command -v nft >/dev/null 2>&1 && [ ! -x /usr/sbin/nft ] && [ ! -x /sbin/nft ]; then
	echo "SKIP: nft not found — the kernel cells load rulesets with nft"
	exit 77
fi

# Probe the capability rather than assuming it: unprivileged user
# namespaces are disabled on some hosts, and running as a non-root user
# without them cannot create a netns. A probe that cannot distinguish
# "denied" from "works" would make this leg report PASS while running
# nothing.
if ! unshare -rn true 2>/dev/null; then
	echo "SKIP: cannot create a private netns (needs unprivileged userns or root)"
	exit 77
fi

# -count=1 so a cached PASS can never stand in for a run that did not happen.
# -json=false pins text output: the guard below scans anchored `=== RUN`
# records, and an inherited GOFLAGS=-json would embed them in JSON Output
# records and false-red every cell as "did not run".
# XPF_REQUIRE_NETNS=1 turns every tool/netns skip arm in the six kernel
# cells into a failure (#15241 A58-06); without it an environment that
# silently degrades would read green. unshare propagates the environment
# into the namespace.
out=$(XPF_REQUIRE_NETNS=1 unshare -rn "$GO" test -json=false -count=1 -v -run 'TestHostInboundIngressZoneVerdictsOnRealKernel9637|TestHostInboundUnzonedIngressVerdictsOnRealKernel11409|TestHostInboundReinjectTunVerdicts9637|TestHostInboundSharedVRFMasterIngressAndFineDeny12034|TestLifelineSharedDenyAllVerdictsOnRealKernel12229|TestRIMemberSecureTunnelUnitBindsToVRF12087' ./pkg/daemon/ 2>&1)
rc=$?

fail=0
for cell in TestHostInboundIngressZoneVerdictsOnRealKernel9637 TestHostInboundUnzonedIngressVerdictsOnRealKernel11409 TestHostInboundReinjectTunVerdicts9637 TestHostInboundSharedVRFMasterIngressAndFineDeny12034 TestLifelineSharedDenyAllVerdictsOnRealKernel12229 TestRIMemberSecureTunnelUnitBindsToVRF12087; do
	if ! printf '%s\n' "$out" | grep -q "^=== RUN   $cell\$"; then
		echo "FAIL: $cell did not run — the -run predicate has rotted"
		fail=1
	fi
	if printf '%s\n' "$out" | grep -q "^--- SKIP: $cell "; then
		echo "FAIL: $cell SKIPPED under XPF_REQUIRE_NETNS=1 — the forcing broke"
		fail=1
	fi
done
if [ "$rc" -ne 0 ]; then
	echo "FAIL: go test exited $rc"
	fail=1
fi
if [ "$fail" -ne 0 ]; then
	printf '%s\n' "$out" | sed 's/^/      /'
	exit 1
fi
echo "PASS: all six daemon kernel cells ran and passed"
exit 0
