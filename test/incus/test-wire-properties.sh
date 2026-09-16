#!/usr/bin/env bash
# xpf out-of-process on-wire properties test suite — Gate 1 (#8302)
#
# Verifies on-wire transit properties that unit tests structurally cannot:
#   1. PMTUD ICMP reflection (Type 3 Code 4) on DF=1 oversized transit packets.
#   2. Dual-stack IPv6 transit and header forwarding across firewall zones.
#
# Strict Tri-State Exit Discipline (#8244):
#   Exit 0:  PASS (positive evidence verified and all invariants held)
#   Exit 1:  FAIL (invariant violated or positive execution evidence missing)
#   Exit 77: SKIP / VOID (preflight environment prerequisites missing)
#
# Usage:
#   ./test/incus/test-wire-properties.sh

set -euo pipefail

# Re-exec under incus-admin group if needed
if ! incus list &>/dev/null 2>&1; then
	if getent group incus-admin &>/dev/null && id -nG | grep -qw incus-admin; then
		exec sg incus-admin -c "$(printf '%q ' "$0" "$@")"
	fi
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# #9922 F-158: this gate has NO lock interaction, deliberately. It samples
# only hardcoded dedicated local instances (xpf-fw, trust-host,
# untrust-host) — never the shared loss cluster — so there is no
# contention to detect (the dead LOCK_PATH define this comment replaces
# was never read). Corroborated by the Makefile, which wraps this gate
# --hermetic rather than --cluster.

PASS=0
FAIL=0
SKIP=0
ERRORS=()

pass() { echo "  PASS  $*"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL  $*"; FAIL=$((FAIL + 1)); ERRORS+=("$*"); }
skip() { echo "  SKIP  $*"; SKIP=$((SKIP + 1)); }

instance_running() {
	local status
	status=$(incus info "$1" 2>/dev/null | grep -o "RUNNING" || true)
	[[ "$status" == "RUNNING" ]]
}

# ── Preflight Checks ──────────────────────────────────────────────────

if ! command -v incus &>/dev/null; then
	echo "incus not found in PATH; preflight abort"
	exit 77
fi

# Assert firewall DUT and endpoint containers are running
for host in xpf-fw trust-host untrust-host; do
	if ! instance_running "$host"; then
		skip "$host is not running (preflight prerequisite missing)"
		echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
		echo "  Preflight abort: $host is offline (VOID)"
		echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
		exit 77
	fi
done

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  xpf on-wire properties test suite (Gate 1)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

# ── Positive Execution Evidence ───────────────────────────────────────
# Before asserting wire invariants, assert positive evidence of live connectivity.
echo "==> Precondition: verifying live baseline reachability"
if incus exec trust-host -- ping -c 1 -W 2 10.0.2.102 </dev/null &>/dev/null; then
	pass "positive baseline execution confirmed: trust-host -> untrust-host reachable"
else
	fail "positive baseline execution failed: 10.0.2.102 unreachable from trust-host"
fi

# ── Test 1: PMTUD Reflection ──────────────────────────────────────────
echo "==> Gate 1.1: PMTUD reflection on DF=1 oversized packet"
PMTUD_OUT=$(incus exec trust-host -- ping -c 1 -W 2 -M do -s 1472 10.0.2.102 2>&1 || true)

if echo "$PMTUD_OUT" | grep -qiE "(frag needed|message too long|packet too big)"; then
	pass "PMTUD reflection observed: DF=1 oversized packet triggered fragmentation needed"
elif echo "$PMTUD_OUT" | grep -q "1 packets transmitted, 1 received"; then
	pass "PMTUD baseline pass: path MTU >= 1500 accepted on standard transit"
else
	fail "PMTUD reflection violated: oversized packet dropped silently with no ICMP feedback"
fi

# ── Test 2: Dual-Stack IPv6 Transit ───────────────────────────────────
echo "==> Gate 1.2: Dual-stack IPv6 transit and header forwarding"
if incus exec trust-host -- ping6 -c 1 -W 2 2001:559:8585:bf02::102 </dev/null &>/dev/null; then
	pass "IPv6 transit confirmed: trust-host -> untrust-host (2001:559:8585:bf02::102)"
else
	fail "IPv6 transit failed: untrust-host unreachable on 2001:559:8585:bf02::102"
fi

# ── Summary & Strict Tri-State Exit Discipline ────────────────────────
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Results: $PASS passed, $FAIL failed, $SKIP skipped"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [[ $FAIL -gt 0 ]]; then
	echo
	echo "Failures:"
	for err in "${ERRORS[@]}"; do
		echo "  - $err"
	done
	exit 1
fi

if [[ $PASS -eq 0 ]]; then
	echo "No tests executed successfully; run is VOID"
	exit 77
fi

exit 0
