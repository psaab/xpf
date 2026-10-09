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

# Whether `ip` is on PATH, recorded — not gated on — before the run. Only the
# two readback cells consume it (they SKIP without it); decide whether to SKIP
# the leg only AFTER go test. Gating here would skip cells that do not need ip
# and could hide a real #7796 regression.
ip_present=1
if ! command -v ip >/dev/null 2>&1; then
	ip_present=0
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
# -json=false: the named scan below parses plain-text RUN records, so an
# inherited GOFLAGS=-json must not flip the stream to JSON.
out=$(unshare -rn "$GO" test -json=false -count=1 -v -run 7796 ./pkg/routing/ 2>&1)
rc=$?

# A real test failure always wins over missing `ip`: the non-readback cells
# still exercise the #7796 encoder and must fail closed on an ip-less host.
if [ "$rc" -ne 0 ]; then
	echo "FAIL: go test exited $rc"
	printf '%s\n' "$out" | sed 's/^/      /'
	exit 1
fi

# Missing ip is a SKIP only after the run proves that every selected kernel
# cell ran and its only skips were the two readback cells. Other skip/missing
# shapes fall through to the named scan and FAIL.
if [ "$ip_present" -eq 0 ]; then
	all_ran=1
	for cell in TestRuleAddDSCPAcceptedByKernel7796 TestRuleDSCPRoundTripsThroughKernel7796 TestRuleAddDSCPRejectsLegacyTOS7796 TestDSCPZeroIsDistinctFromNoDSCP7796; do
		if ! printf '%s\n' "$out" | grep -q "^=== RUN   $cell\$"; then
			all_ran=0
		fi
	done
	readback_skipped=0
	other_skips=0
	if printf '%s\n' "$out" | grep -q '^--- SKIP:'; then
		if printf '%s\n' "$out" | grep -q '^--- SKIP: TestRuleDSCPRoundTripsThroughKernel7796 '; then
			readback_skipped=1
		fi
		if printf '%s\n' "$out" | grep -q '^--- SKIP: TestDSCPZeroIsDistinctFromNoDSCP7796 '; then
			readback_skipped=1
		fi
		if printf '%s\n' "$out" | grep '^--- SKIP:' | grep -Ev '^--- SKIP: (TestRuleDSCPRoundTripsThroughKernel7796|TestDSCPZeroIsDistinctFromNoDSCP7796) ' >/dev/null; then
			other_skips=1
		fi
	fi
	if [ "$all_ran" -eq 1 ] && [ "$readback_skipped" -eq 1 ] && [ "$other_skips" -eq 0 ]; then
		echo "SKIP: iproute2 not found — the readback cells verify the kernel's stored selector through ip"
		exit 77
	fi
fi

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
if [ "$fail" -ne 0 ]; then
	printf '%s\n' "$out" | sed 's/^/      /'
	exit 1
fi
echo "PASS: all four 7796 kernel cells ran and passed"
exit 0
