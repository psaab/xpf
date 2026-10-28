#!/usr/bin/env bash
# #18168/#18174: exercise the IPv4 and IPv6 RETH MTR validators against
# captured reports and negative fixtures, extracted from connectivity logic.
# This tests the production shell logic without Incus or a live cluster.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

python3 - "${SCRIPT_DIR}/test-connectivity.sh" "${TMP_DIR}/validator.sh" <<'PY'
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
matches = re.findall(
    r"^check_mtr_linklocal[46]\(\) \{\n.*?^\}\n", source, re.M | re.S
)
if len(matches) != 2:
    raise SystemExit("cannot extract both link-local MTR validators from test-connectivity.sh")
pathlib.Path(sys.argv[2]).write_text("\n".join(matches), encoding="utf-8")
PY
# shellcheck source=/dev/null
source "${TMP_DIR}/validator.sh"

passed=0
fail() { echo "FAIL: $*" >&2; exit 1; }
expect_pass() {
	local label="$1" target="$2" report="$3"
	if ! check_mtr_linklocal4 "$report" "$target"; then
		fail "${label}: captured path rejected"
	fi
	passed=$((passed + 1))
	echo "PASS: ${label}"
}
expect_fail() {
	local label="$1" target="$2" report="$3"
	if check_mtr_linklocal4 "$report" "$target" >/dev/null; then
		fail "${label}: invalid path accepted"
	fi
	passed=$((passed + 1))
	echo "PASS: ${label} rejected"
}

expect_pass6() {
	local label="$1" target="$2" report="$3"
	if ! check_mtr_linklocal6 "$report" "$target"; then
		fail "${label}: valid IPv6 path rejected"
	fi
	passed=$((passed + 1))
	echo "PASS: ${label}"
}
expect_fail6() {
	local label="$1" target="$2" report="$3"
	if check_mtr_linklocal6 "$report" "$target" >/dev/null; then
		fail "${label}: invalid IPv6 path accepted"
	fi
	passed=$((passed + 1))
	echo "PASS: ${label} rejected"
}

# Captured from /var/worktrees/.cache/diag-18168-loss/run1/cell.log
# (lan-mtr-wan, lines 2368-2373).
WAN_REPORT=$'Start: 2026-10-28T08:06:09+0000\nHOST: cluster-userspace-host      Loss%   Snt   Last   Avg  Best  Wrst StDev\n  1.|-- 169.254.2.1                0.0%     3    0.2   0.2   0.2   0.2   0.0\n  2.|-- 172.16.50.1                0.0%     3    0.6   7.0   0.6  19.6  10.9'
expect_pass "captured WAN gateway MTR" "172.16.50.1" "$WAN_REPORT"

# Captured from the same cell (lan-mtr-internet, lines 2374-2389).
INTERNET_REPORT=$'Start: 2026-10-28T08:06:17+0000\nHOST: cluster-userspace-host      Loss%   Snt   Last   Avg  Best  Wrst StDev\n  1.|-- 169.254.2.1                0.0%     3    0.1   0.2   0.1   0.3   0.1\n  2.|-- ???                       100.0     3    0.0   0.0   0.0   0.0   0.0\n  3.|-- ???                       100.0     3    0.0   0.0   0.0   0.0   0.0\n  4.|-- ???                       100.0     3    0.0   0.0   0.0   0.0   0.0\n  5.|-- ???                       100.0     3    0.0   0.0   0.0   0.0   0.0\n  6.|-- ???                       100.0     3    0.0   0.0   0.0   0.0   0.0\n  7.|-- ???                       100.0     3    0.0   0.0   0.0   0.0   0.0\n  8.|-- ???                       100.0     3    0.0   0.0   0.0   0.0   0.0\n  9.|-- ???                       100.0     3    0.0   0.0   0.0   0.0   0.0\n 10.|-- ???                       100.0     3    0.0   0.0   0.0   0.0   0.0\n 11.|-- ???                       100.0     3    0.0   0.0   0.0   0.0   0.0\n 12.|-- 1.1.1.1                    0.0%     3    4.1   4.0   3.8   4.1   0.1'
expect_pass "captured IPv4 internet MTR" "1.1.1.1" "$INTERNET_REPORT"

expect_fail "VIP is not an MTR hop-1 source" "172.16.50.1" \
	$'  1.|-- 10.0.61.1  0.0%  3  0.2  0.2  0.2  0.2  0.0\n  2.|-- 172.16.50.1  0.0%  3  0.6  7.0  0.6 19.6 10.9'
expect_fail "WAN gateway is not an MTR hop-1 source" "172.16.50.1" \
	$'  1.|-- 172.16.50.1  0.0%  3  0.6  7.0  0.6 19.6 10.9'
expect_fail "unresolved first hop" "172.16.50.1" \
	$'  1.|-- ??? 100.0% 3 0.0 0.0 0.0 0.0 0.0\n  2.|-- 172.16.50.1 0.0% 3 0.6 7.0 0.6 19.6 10.9'
expect_fail "destination is missing" "172.16.50.1" \
	$'  1.|-- 169.254.2.1 0.0% 3 0.2 0.2 0.2 0.2 0.0\n  2.|-- ??? 100.0% 3 0.0 0.0 0.0 0.0 0.0'
expect_fail "destination reports loss" "172.16.50.1" \
	$'  1.|-- 169.254.2.1 0.0% 3 0.2 0.2 0.2 0.2 0.0\n  2.|-- 172.16.50.1 100.0% 3 0.0 0.0 0.0 0.0 0.0'
expect_fail "destination is not the final row" "1.1.1.1" \
	$'  1.|-- 169.254.2.1 0.0% 3 0.2 0.2 0.2 0.2 0.0\n  2.|-- 1.1.1.1 0.0% 3 4.1 4.0 3.8 4.1 0.1\n  3.|-- ??? 100.0% 3 0.0 0.0 0.0 0.0 0.0'
expect_fail "destination at hop 1 does not prove traversal" "169.254.2.1" \
	$'  1.|-- 169.254.2.1 0.0% 3 0.2 0.2 0.2 0.2 0.0'

# Captured from /var/worktrees/.cache/diag-18168-loss/run1/cell.log
# (lan-mtr-internet6, lines 2390-2395): RETH answers hop 1, public target does not.
IPV6_TARGET="2607:f8b0:4005:80e::200e"
IPV6_CAPTURED=$'Start: 2026-10-28T08:06:26+0000\nHOST: cluster-userspace-host      Loss%   Snt   Last   Avg  Best  Wrst StDev\n  1.|-- fe80::bf:72ff:fe16:202     0.0%     3    0.2   0.2   0.2   0.2   0.0\n  2.|-- ???                       100.0     3    0.0   0.0   0.0   0.0   0.0'
expect_fail6 "captured IPv6 public target remains unresolved" "$IPV6_TARGET" "$IPV6_CAPTURED"
expect_pass6 "responding IPv6 target beyond link-local RETH" "$IPV6_TARGET" \
	$'  1.|-- fe80::bf:72ff:fe16:202 0.0% 3 0.2 0.2 0.2 0.2 0.0\n  2.|-- 2607:f8b0:4005:80e::200e 0.0% 3 4.1 4.0 3.8 4.1 0.1'
expect_fail6 "IPv6 VIP is not an MTR hop-1 source" "$IPV6_TARGET" \
	$'  1.|-- 2001:559:8585:ef00::1 0.0% 3 0.2 0.2 0.2 0.2 0.0\n  2.|-- 2607:f8b0:4005:80e::200e 0.0% 3 4.1 4.0 3.8 4.1 0.1'
expect_fail6 "IPv6 report has no hop lines" "$IPV6_TARGET" 'mtr failed'
expect_fail6 "global IPv6 first hop is not link-local" "$IPV6_TARGET" \
	$'  1.|-- 2001:db8::1 0.0% 3 0.2 0.2 0.2 0.2 0.0\n  2.|-- 2607:f8b0:4005:80e::200e 0.0% 3 4.1 4.0 3.8 4.1 0.1'
expect_fail6 "IPv6 target is not the final row" "$IPV6_TARGET" \
	$'  1.|-- fe80::bf:72ff:fe16:202 0.0% 3 0.2 0.2 0.2 0.2 0.0\n  2.|-- 2607:f8b0:4005:80e::200e 0.0% 3 4.1 4.0 3.8 4.1 0.1\n  3.|-- ??? 100.0 3 0.0 0.0 0.0 0.0 0.0'
expect_fail6 "IPv6 target reports loss" "$IPV6_TARGET" \
	$'  1.|-- fe80::bf:72ff:fe16:202 0.0% 3 0.2 0.2 0.2 0.2 0.0\n  2.|-- 2607:f8b0:4005:80e::200e 100.0% 3 0.0 0.0 0.0 0.0 0.0'

printf 'ALL %d IPv4 and IPv6 MTR fixture cases PASS\n' "$passed"
