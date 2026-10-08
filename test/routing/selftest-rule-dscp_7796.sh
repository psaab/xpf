#!/bin/sh
# selftest-rule-dscp_7796.sh — run the #7796 FBF DSCP ip-rule APPLY LEG.
#
# Why this leg exists at all: the #7796 defect was invisible to every
# compile-side test. The pre-fix code built a well-formed netlink.Rule and all
# build-side assertions passed; the failure was entirely in what the KERNEL
# accepted (FRA_TOS is masked to IPTOS_TOS_MASK, so a DSCP shifted into a TOS
# byte was rejected with EINVAL from dscp 8 up, failing the whole commit). The
# only instrument that can see that is one that talks to a real kernel.
#
# Why it is not simply part of `make test-go`: the cells need CAP_NET_ADMIN to
# create a private netns, so under a plain `go test` they SKIP — and a skipped
# cell is indistinguishable from a passing one in aggregate output. That is the
# exact shape that lets an apply-leg regression sit green forever. This leg runs
# them under `unshare -rn` where they actually execute.
#
# Exit codes follow the selftest contract: 0 = PASS, 77 = SKIP (a tool or
# capability this host does not have), anything else = FAIL.

set -u

GO=${GO:-go}

if ! command -v "$GO" >/dev/null 2>&1; then
	echo "SKIP: $GO not installed — cannot run the apply leg"
	exit 77
fi

if ! command -v unshare >/dev/null 2>&1; then
	echo "SKIP: unshare not found — cannot self-isolate a private netns"
	exit 77
fi

if ! command -v ip >/dev/null 2>&1; then
	echo "SKIP: iproute2 not found — the readback cells verify the kernel's stored selector through ip"
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
# -v plus the named scan below so a skipped cell can never read as a pass: the
# two readback cells SKIP when `ip` is absent, and without -v go test prints
# only `ok` and the leg exits 0. The scan pins the four kernel cells BY NAME,
# because a `-run` predicate that rots matches nothing and reports a clean pass
# over an empty set. The two hermetic 7796 cells still run; they cannot skip.
out=$(unshare -rn "$GO" test -count=1 -v -run 7796 ./pkg/routing/ 2>&1)
rc=$?

fail=0
for cell in TestRuleAddDSCPAcceptedByKernel7796 TestRuleDSCPRoundTripsThroughKernel7796 TestRuleAddDSCPRejectsLegacyTOS7796 TestDSCPZeroIsDistinctFromNoDSCP7796; do
	if ! printf '%s\n' "$out" | grep -q "^=== RUN   $cell\$"; then
		echo "FAIL: $cell did not run — the -run predicate has rotted"
		fail=1
	fi
	if printf '%s\n' "$out" | grep -q "^--- SKIP: $cell "; then
		echo "FAIL: $cell SKIPPED — a skipped apply-leg cell reads as a pass"
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
echo "PASS: all four 7796 kernel cells ran and passed"
exit 0
