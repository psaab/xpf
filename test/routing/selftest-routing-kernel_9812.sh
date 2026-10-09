#!/bin/sh
# selftest-routing-kernel_9812.sh — run the routing real-kernel cells (#9420, #9819, #11319, #12083).
#
# Why this leg exists at all: the #9420 next-table ingress-scope, #9819 VRF-miss
# terminator, #11319 PBR-before-leak and #12083 VRF-held-source keepalive are
# kernel halves of their fixes. The pre-fix code passed compile-side tests;
# the failures were entirely in what the KERNEL resolved (an unscoped ip rule
# diverting VRF ingress into another table; a VRF miss falling through to main;
# and a leak rule outranking an explicit PBR selector). The only instrument
# that can see these is one that talks to a real kernel.
#
# Why it is not simply part of `make test-go`: the cells need to create a
# private netns, so under a plain `go test` they SKIP — and a skipped cell is
# indistinguishable from a passing one in aggregate output. That is the exact
# shape that lets a kernel-semantics regression sit green forever. This leg runs
# them under `unshare -rn` with XPF_REQUIRE_NETNS=1, where a missing tool or a
# failed namespace is a failure, not a skip.
#
# The predicate runs the issue-numbered cells in pkg/routing. The fake-ops
# cells are hermetic and harmless under unshare; the guard below pins all four
# kernel cells BY NAME, because a `-run` predicate that rots matches nothing
# and reports a clean pass over an empty set.
#
# Exit codes follow the selftest contract: 0 = PASS, 77 = SKIP (a tool or
# capability this host does not have), anything else = FAIL.

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
	echo "SKIP: bash not found — the 9420 kernel cell drives its netns script through bash"
	exit 77
fi

# Probe the capability rather than assuming it: unprivileged user namespaces are
# disabled on some hosts, and running as a non-root user without them cannot
# create a netns. A probe that cannot distinguish "denied" from "works" would
# make this leg report PASS while running nothing.
if ! unshare -rn true 2>/dev/null; then
	echo "SKIP: cannot create a private netns (needs unprivileged userns or root)"
	exit 77
fi

# -count=1 so a cached PASS can never stand in for a run that did not happen.
# XPF_REQUIRE_NETNS=1 turns every tool/netns skip arm in the four kernel cells
# into a failure; without it an environment that silently degrades would read
# green. unshare propagates the environment into the namespace.
# Match the netns acceptance cell by name: the loopback capability test intentionally
# fails under XPF_REQUIRE_NETNS when this fresh namespace denies ICMP datagrams.
out=$(XPF_REQUIRE_NETNS=1 unshare -rn "$GO" test -count=1 -v -run '9420|9819|11319|TestTunnelKeepaliveVRFHeldSourcePeerAlive12083' ./pkg/routing/ 2>&1)
rc=$?

fail=0
for cell in TestNextTableIngressScopeOnRealKernel_9420 TestVRFMissTerminatorOnRealKernel9819 TestPBRPrecedesLeakBandsOnRealKernel11319 TestTunnelKeepaliveVRFHeldSourcePeerAlive12083; do
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
echo "PASS: all four routing kernel cells ran and passed"
exit 0
