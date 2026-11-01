#!/bin/sh
# selftest-nftables-kernel_18745.sh — run EVERY pkg/nftables test under a
# private network namespace with XPF_REQUIRE_NETNS=1, and count any SKIP as a
# failure (#18745).
#
# Why: the pkg/nftables real-kernel cells enter a netns with enterPrivateNetns
# and friends, which SKIP when the namespace cannot be created. Under a plain
# `go test` they all skip, and a skip reads like a pass in aggregate output.
# #16841 broke two of them, #13955 two more, and #10483 and #11574 one each.
# All six sat red for weeks with nothing to show it. This is the same class
# as #15241, whose leg forces only the pkg/daemon kernel cells.
#
# The whole package runs, with no -run predicate: a name filter rots and
# reports a clean pass over an empty set (#6743 r2-N3). A SKIP line, top-level
# or subtest, is a failure here, because under XPF_REQUIRE_NETNS=1 every skip
# arm the cells have means the forcing broke.
#
# Exit codes follow the selftest contract: 0 = PASS, 77 = SKIP (a tool or
# capability this host does not have), anything else = FAIL.

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

# -count=1: a cached PASS must never stand in for a run that did not happen.
# -json=false pins text output for the line scans below.
out=$(XPF_REQUIRE_NETNS=1 unshare -rn "$GO" test -json=false -count=1 -v ./pkg/nftables/ 2>&1)
rc=$?

fail=0
skips=$(printf '%s\n' "$out" | grep -E '^[[:space:]]*--- SKIP: ' || true)
if [ -n "$skips" ]; then
	echo "FAIL: pkg/nftables cells SKIPPED under XPF_REQUIRE_NETNS=1 — the forcing broke:"
	printf '%s\n' "$skips" | sed 's/^/      /'
	fail=1
fi
fails=$(printf '%s\n' "$out" | grep -E '^--- FAIL: ' || true)
if [ -n "$fails" ]; then
	echo "FAIL: pkg/nftables kernel cells failed:"
	printf '%s\n' "$fails" | sed 's/^/      /'
	fail=1
fi
if [ "$rc" -ne 0 ]; then
	echo "FAIL: go test exited $rc"
	fail=1
fi
passed=$(printf '%s\n' "$out" | grep -cE '^--- PASS: ' || true)
if [ "$fail" -eq 0 ] && [ "$passed" -eq 0 ]; then
	echo "FAIL: no pkg/nftables test reported PASS — the run collected nothing"
	fail=1
fi
if [ "$fail" -ne 0 ]; then
	printf '%s\n' "$out" | grep -vE '^(=== (RUN|PAUSE|CONT)|--- PASS|    --- PASS)' | tail -60 | sed 's/^/      /'
	exit 1
fi
echo "PASS: all $passed pkg/nftables tests ran under a forced netns; no SKIP"
exit 0
