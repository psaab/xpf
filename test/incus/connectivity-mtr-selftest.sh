#!/usr/bin/env bash
# #18168/#18174: exercise the cluster RETH MTR validator against captured
# reports and negative fixtures, extracted from connectivity logic. This tests
# the production shell logic without Incus or a live cluster.
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
    r"^check_mtr_reth_vip\(\) \{\n.*?^\}\n", source, re.M | re.S
)
if len(matches) != 1:
    raise SystemExit("cannot extract check_mtr_reth_vip from test-connectivity.sh")
pathlib.Path(sys.argv[2]).write_text(matches[0], encoding="utf-8")
PY
# shellcheck source=/dev/null
source "${TMP_DIR}/validator.sh"

passed=0
fail() { echo "FAIL: $*" >&2; exit 1; }
expect_pass() {
	local label="$1" target="$2" vip="$3" report="$4"
	if ! check_mtr_reth_vip "$report" "$target" "$vip"; then
		fail "${label}: valid path rejected"
	fi
	passed=$((passed + 1))
	echo "PASS: ${label}"
}
expect_fail() {
	local label="$1" target="$2" vip="$3" report="$4" want="$5" verdict
	if verdict=$(check_mtr_reth_vip "$report" "$target" "$vip"); then
		fail "${label}: invalid path accepted (${verdict})"
	fi
	# Pin WHICH predicate rejected it, so a fixture cannot pass on an
	# unrelated earlier check.
	if [[ "$verdict" != *"$want"* ]]; then
		fail "${label}: rejected for the wrong reason: ${verdict}"
	fi
	passed=$((passed + 1))
	echo "PASS: ${label} rejected (${verdict})"
}

VIP4="10.0.61.1"
VIP6="2001:559:8585:ef00::1"
HDR=$'HOST: cluster-userspace-host      Loss%   Snt   Last   Avg  Best  Wrst StDev\n'

# ---- IPv4 ----------------------------------------------------------------
# Post-#18174 shapes: the RETH VIP answers hop 1, the WAN gateway answers
# hop 2 (its Time Exceeded un-NATed back to the host), the target is final.
expect_pass "WAN gateway via RETH VIP" "172.16.50.1" "$VIP4" \
	"${HDR}"$'  1.|-- 10.0.61.1                  0.0%     3    0.2   0.2   0.2   0.2   0.0\n  2.|-- 172.16.50.1                0.0%     3    0.6   7.0   0.6  19.6  10.9'
expect_pass "internet IPv4 via RETH VIP, hops resolved" "1.1.1.1" "$VIP4" \
	"${HDR}"$'  1.|-- 10.0.61.1    0.0%  3  0.2  0.2  0.2  0.2  0.0\n  2.|-- 172.16.50.1  0.0%  3  0.6  0.6  0.6  0.6  0.0\n  3.|-- 50.220.171.29  0.0%  3  1.0  1.0  1.0  1.0  0.0\n  4.|-- ???  100.0  3  0.0  0.0  0.0  0.0  0.0\n  5.|-- 1.1.1.1  0.0%  3  4.1  4.0  3.8  4.1  0.1'

# Captured 2026-10-30 17:58 from the loss LAN host (the #18174 report):
# link-local hop 1 AND every hop past the firewall unresolved.
CAPTURED4="${HDR}"$'  1.|-- 169.254.2.1                0.0%     1   13.4  13.4  13.4  13.4   0.0\n  2.|-- ???                       100.0     1    0.0   0.0   0.0   0.0   0.0\n  3.|-- ???                       100.0     1    0.0   0.0   0.0   0.0   0.0\n 11.|-- ???                       100.0     1    0.0   0.0   0.0   0.0   0.0\n 12.|-- 1.1.1.1                    0.0%     1   11.9  11.9  11.9  11.9   0.0'
expect_fail "captured #18174 IPv4 report" "1.1.1.1" "$VIP4" "$CAPTURED4" "not the RETH VIP"
expect_fail "link-local hop 1 (pre-#18174 TE source)" "172.16.50.1" "$VIP4" \
	$'  1.|-- 169.254.2.1  0.0%  3  0.2  0.2  0.2  0.2  0.0\n  2.|-- 172.16.50.1  0.0%  3  0.6  7.0  0.6 19.6 10.9' "not the RETH VIP"
expect_fail "hops past the firewall unresolved (#18174 blackhole)" "1.1.1.1" "$VIP4" \
	$'  1.|-- 10.0.61.1  0.0%  3  0.2  0.2  0.2  0.2  0.0\n  2.|-- ???  100.0  3  0.0  0.0  0.0  0.0  0.0\n  3.|-- ???  100.0  3  0.0  0.0  0.0  0.0  0.0\n  4.|-- 1.1.1.1  0.0%  3  4.1  4.0  3.8  4.1  0.1' "hop 2"
expect_fail "WAN gateway is not an MTR hop-1 source" "172.16.50.1" "$VIP4" \
	$'  1.|-- 172.16.50.1  0.0%  3  0.6  7.0  0.6 19.6 10.9' "not the RETH VIP"
expect_fail "unresolved first hop" "172.16.50.1" "$VIP4" \
	$'  1.|-- ??? 100.0% 3 0.0 0.0 0.0 0.0 0.0\n  2.|-- 172.16.50.1 0.0% 3 0.6 7.0 0.6 19.6 10.9' "not the RETH VIP"
expect_fail "destination is missing" "172.16.50.1" "$VIP4" \
	$'  1.|-- 10.0.61.1 0.0% 3 0.2 0.2 0.2 0.2 0.0\n  2.|-- ??? 100.0% 3 0.0 0.0 0.0 0.0 0.0' "not the final hop"
expect_fail "destination reports loss" "172.16.50.1" "$VIP4" \
	$'  1.|-- 10.0.61.1 0.0% 3 0.2 0.2 0.2 0.2 0.0\n  2.|-- 172.16.50.1 100.0% 3 0.0 0.0 0.0 0.0 0.0' "loss at target"
expect_fail "destination is not the final row" "1.1.1.1" "$VIP4" \
	$'  1.|-- 10.0.61.1 0.0% 3 0.2 0.2 0.2 0.2 0.0\n  2.|-- 1.1.1.1 0.0% 3 4.1 4.0 3.8 4.1 0.1\n  3.|-- ??? 100.0% 3 0.0 0.0 0.0 0.0 0.0' "not the final hop"
expect_fail "destination at hop 1 does not prove traversal" "10.0.61.1" "$VIP4" \
	$'  1.|-- 10.0.61.1 0.0% 3 0.2 0.2 0.2 0.2 0.0' "not the final hop"
expect_fail "unset VIP never matches" "172.16.50.1" "" \
	$'  1.|-- 10.0.61.1 0.0% 3 0.2 0.2 0.2 0.2 0.0\n  2.|-- 172.16.50.1 0.0% 3 0.6 7.0 0.6 19.6 10.9' "not the RETH VIP"

# ---- IPv6 ----------------------------------------------------------------
IPV6_TARGET="2001:4860:4860::8888"
expect_pass "internet IPv6 via RETH VIP, hops resolved" "$IPV6_TARGET" "$VIP6" \
	"${HDR}"$'  1.|-- 2001:559:8585:ef00::1  0.0%  3  0.4  0.4  0.4  0.4  0.0\n  2.|-- 2001:559:8585:50::1  0.0%  3  0.6  0.6  0.6  0.6  0.0\n  3.|-- 2001:559:800c:1900::8819  0.0%  3  1.0  1.0  1.0  1.0  0.0\n  4.|-- 2001:4860:4860::8888  0.0%  3  2.6  2.6  2.6  2.6  0.0'
# Captured 2026-10-30 17:58 from the loss LAN host: VIP hop 1 (v6 TE source
# was already right) but every hop past the firewall unresolved.
CAPTURED6="${HDR}"$'  1.|-- 2001:559:8585:ef00::1      0.0%     1    0.4   0.4   0.4   0.4   0.0\n  2.|-- ???                       100.0     1    0.0   0.0   0.0   0.0   0.0\n  7.|-- ???                       100.0     1    0.0   0.0   0.0   0.0   0.0\n  8.|-- 2001:4860:4860::8888       0.0%     1    2.6   2.6   2.6   2.6   0.0'
expect_fail "captured #18174 IPv6 report" "$IPV6_TARGET" "$VIP6" "$CAPTURED6" "hop 2"
# Captured /var/worktrees/.cache/diag-18168-loss/run1/cell.log (lan-mtr-internet6,
# lines 2390-2395): fe80 hop 1, dead public target.
expect_fail "captured #18168 IPv6 report (fe80 hop 1)" "2607:f8b0:4005:80e::200e" "$VIP6" \
	"${HDR}"$'  1.|-- fe80::bf:72ff:fe16:202     0.0%     3    0.2   0.2   0.2   0.2   0.0\n  2.|-- ???                       100.0     3    0.0   0.0   0.0   0.0   0.0' "not the RETH VIP"
expect_fail "IPv6 link-local hop 1 with a resolved path" "$IPV6_TARGET" "$VIP6" \
	$'  1.|-- fe80::bf:72ff:fe16:202 0.0% 3 0.2 0.2 0.2 0.2 0.0\n  2.|-- 2001:559:8585:50::1 0.0% 3 0.6 0.6 0.6 0.6 0.0\n  3.|-- 2001:4860:4860::8888 0.0% 3 4.1 4.0 3.8 4.1 0.1' "not the RETH VIP"
expect_fail "IPv6 report has no hop lines" "$IPV6_TARGET" "$VIP6" 'mtr failed' "not the RETH VIP"
expect_fail "IPv6 target is not the final row" "$IPV6_TARGET" "$VIP6" \
	$'  1.|-- 2001:559:8585:ef00::1 0.0% 3 0.2 0.2 0.2 0.2 0.0\n  2.|-- 2001:4860:4860::8888 0.0% 3 4.1 4.0 3.8 4.1 0.1\n  3.|-- ??? 100.0 3 0.0 0.0 0.0 0.0 0.0' "not the final hop"
expect_fail "IPv6 target reports loss" "$IPV6_TARGET" "$VIP6" \
	$'  1.|-- 2001:559:8585:ef00::1 0.0% 3 0.2 0.2 0.2 0.2 0.0\n  2.|-- 2001:4860:4860::8888 100.0% 3 0.0 0.0 0.0 0.0 0.0' "loss at target"

printf 'ALL %d IPv4 and IPv6 MTR fixture cases PASS\n' "$passed"
