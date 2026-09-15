#!/usr/bin/env bash
# Hermetic self-test for test/incus/host-inbound-lib.sh (#6936).
#
# No cluster, no incus, no network. Runs in `make test-host-inbound-lib`.
#
# The rows that matter are DENY_SILENT_CONTROL_*. A probe cannot observe a
# deny; it observes SILENCE. "the firewall dropped it" and "my prober never
# reached the firewall" are the same reading, and only the run's positive
# control separates them. Under any form that scores a bare timeout as PASS,
# the two collapse — which is precisely the defect #7798 had to remove from the
# FBF smoke, and which the #6936 comment asks to be avoided here on the first
# pass rather than after someone notices.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./host-inbound-lib.sh
. "${SCRIPT_DIR}/host-inbound-lib.sh"

pass=0
fail=0

# --- classification: raw prober output -> admission vocabulary --------------
checkc() {
	local name="$1" want="$2" out="$3" target="$4" port="$5" got
	got="$(hi_classify_probe "$out" "$target" "$port")"
	if [[ "$got" == "$want" ]]; then
		pass=$((pass + 1)); printf 'ok   %-34s -> %s\n' "$name" "$got"
	else
		fail=$((fail + 1)); printf 'FAIL %-34s -> want %s got %s\n' "$name" "$want" "$got"
	fi
	[[ "$(grep -c . <<<"$got")" -eq 1 ]] || {
		fail=$((fail + 1)); printf 'FAIL %-34s -> not exactly one word: %q\n' "$name" "$got"; }
}

MATRIX_OUT='PROBE 10.0.61.1 22 REFUSED 0.00
PROBE 10.0.61.1 23 TIMEOUT 3.00
PROBE 172.16.50.8 22 TIMEOUT 3.00
PROBE 2001:559:8585:ef00::1 22 OPEN 0.01
PROBE 198.51.100.7 22 ERROR 0.00'

checkc CLS_REFUSED_IS_ADMITTED  ADMITTED  "$MATRIX_OUT" 10.0.61.1 22
checkc CLS_OPEN_IS_ADMITTED     ADMITTED  "$MATRIX_OUT" 2001:559:8585:ef00::1 22
checkc CLS_TIMEOUT_IS_SILENT    SILENT    "$MATRIX_OUT" 10.0.61.1 23
checkc CLS_V6_TARGET_MATCHES    SILENT    "$MATRIX_OUT" 172.16.50.8 22
checkc CLS_ERROR_IS_UNREACHED   UNREACHED "$MATRIX_OUT" 198.51.100.7 22
# A cell the prober never reported must be BLIND, never SILENT: "the prober
# said nothing about this cell" must not be able to pose as "the firewall said
# nothing to this cell".
checkc CLS_MISSING_CELL_IS_BLIND BLIND    "$MATRIX_OUT" 10.0.61.1 80
checkc CLS_EMPTY_OUTPUT_IS_BLIND BLIND    ""            10.0.61.1 22
checkc CLS_GARBAGE_IS_BLIND      BLIND    "incus: command not found" 10.0.61.1 22
checkc CLS_UNKNOWN_WORD_IS_BLIND BLIND    "PROBE 10.0.61.1 22 WAT 0.00" 10.0.61.1 22
# Port must match as a whole field: a cell for port 2 must not be answered by
# the port-22 line.
checkc CLS_PORT_NEAR_MISS        BLIND    "$MATRIX_OUT" 10.0.61.1 2

# --- classification: ping ---------------------------------------------------
checkp() {
	local name="$1" want="$2" out="$3" got
	got="$(hi_classify_ping "$out")"
	if [[ "$got" == "$want" ]]; then
		pass=$((pass + 1)); printf 'ok   %-34s -> %s\n' "$name" "$got"
	else
		fail=$((fail + 1)); printf 'FAIL %-34s -> want %s got %s\n' "$name" "$want" "$got"
	fi
}

checkp PING_REPLIES_ADMITTED ADMITTED '3 packets transmitted, 3 received, 0% packet loss, time 2044ms'
checkp PING_PARTIAL_ADMITTED ADMITTED '3 packets transmitted, 1 received, 66% packet loss, time 2044ms'
checkp PING_NO_REPLY_SILENT  SILENT   '3 packets transmitted, 0 received, 100% packet loss, time 2044ms'
checkp PING_UNREACH_IS_ERR   UNREACHED 'From 10.0.61.9 icmp_seq=1 Destination Host Unreachable
3 packets transmitted, 0 received, +3 errors, 100% packet loss, time 2044ms'
# No statistics line at all means the prober never ran — BLIND, not SILENT.
checkp PING_EMPTY_IS_BLIND   BLIND    ''
checkp PING_INCUS_ERR_BLIND  BLIND    'Error: Instance is not running'

# --- socket ownership: `ss -tlnp` -> wildcard-bound PIDs ----------------------
# Hermetic rows for hi_wildcard_socket_pids (#9637 fail-closed listener
# gate). Only wildcard-bound sockets with an EXACT port match are emitted;
# the helper deliberately does NOT filter by ownership — a foreign PID is
# emitted and the caller rejects it, never silently dropped.
checkpids() {
	local name="$1" want="$2" port="$3" ss="$4" got
	got="$(hi_wildcard_socket_pids "$port" <<<"$ss")"
	if [[ "$got" == "$want" ]]; then
		pass=$((pass + 1)); printf 'ok   %-34s -> %s\n' "$name" "${got:-<empty>}"
	else
		fail=$((fail + 1)); printf 'FAIL %-34s -> want %q got %q\n' "$name" "$want" "$got"
	fi
}

SS_OUT='State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
LISTEN 0 16 0.0.0.0:22 0.0.0.0:* users:(("python3",pid=1234,fd=3))
LISTEN 0 16 [::]:22 [::]:* users:(("python3",pid=1234,fd=4))
LISTEN 0 16 0.0.0.0:220 0.0.0.0:* users:(("other",pid=9999,fd=5))
LISTEN 0 16 127.0.0.1:22 0.0.0.0:* users:(("xpfd",pid=111,fd=9))
LISTEN 0 16 [::1]:23 [::]:* users:(("xpfd",pid=111,fd=10))
LISTEN 0 16 [::]:23 [::]:* users:(("python3",pid=1234,fd=5),("python3",pid=5678,fd=5))'

# Wildcard v4+v6 rows match; same PID on both dedups to one line.
checkpids SS_WILDCARD_V4_V6_MATCH "1234" 22 "$SS_OUT"
# ":22" must not catch ":220" — and 220 itself still matches exactly.
checkpids SS_PORT_NEAR_MISS_EMPTY "" 22 "$(grep ':220' <<<"$SS_OUT")"
checkpids SS_EXACT_HIGH_PORT_MATCH "9999" 220 "$SS_OUT"
# Loopback-only listeners are unreachable to external probers: no PIDs.
checkpids SS_LOOPBACK_V4_EXCLUDED "" 22 "$(grep '127.0.0.1:22' <<<"$SS_OUT")"
checkpids SS_LOOPBACK_V6_EXCLUDED "" 23 "$(grep '\[::1\]:23' <<<"$SS_OUT")"
# Multi-PID socket: every user emitted, sorted.
checkpids SS_MULTI_PID_ROW $'1234\n5678' 23 "$SS_OUT"
# Foreign PID is emitted, not filtered: the caller's ownership check is
# what rejects it (grep -qxF against the marker PIDs).
checkpids SS_FOREIGN_PID_EMITTED "9999" 220 "$SS_OUT"
checkpids SS_EMPTY_SS_EMPTY "" 22 ""

# --- THE CORE TABLE: every (expectation x observation x control) combination -
checkv() {
	local name="$1" want="$2" expect="$3" obs="$4" control="$5" got verdict
	got="$(hi_cell_verdict "$expect" "$obs" "$control")"
	verdict="${got%% *}"
	if [[ "$verdict" == "$want" ]]; then
		pass=$((pass + 1)); printf 'ok   %-34s -> %s\n' "$name" "$verdict"
	else
		fail=$((fail + 1)); printf 'FAIL %-34s -> want %s got %s (%s)\n' "$name" "$want" "$verdict" "$got"
	fi
	# TOTALITY: exactly one line, and it is one of the two known words.
	[[ "$(grep -c . <<<"$got")" -eq 1 ]] || {
		fail=$((fail + 1)); printf 'FAIL %-34s -> verdict was not exactly one line: %q\n' "$name" "$got"; }
	[[ "$verdict" == PASS || "$verdict" == FAIL ]] || {
		fail=$((fail + 1)); printf 'FAIL %-34s -> verdict word %q is neither PASS nor FAIL\n' "$name" "$verdict"; }
}

# ADMIT cells.
checkv ADMIT_ADMITTED        PASS ADMIT ADMITTED  ADMITTED
checkv ADMIT_SILENT          FAIL ADMIT SILENT    ADMITTED
checkv ADMIT_UNREACHED       FAIL ADMIT UNREACHED ADMITTED
checkv ADMIT_BLIND           FAIL ADMIT BLIND     ADMITTED
checkv ADMIT_EMPTY_OBS       FAIL ADMIT ""        ADMITTED

# DENY cells. The leak direction.
checkv DENY_ADMITTED_IS_LEAK FAIL DENY  ADMITTED  ADMITTED

# THE MIDDLE ROW. Same observation, same expectation; only the control
# differs. Any form that scores a bare timeout as "denied" makes these four
# indistinguishable, and the smoke then certifies a deny on a prober that was
# never shown able to reach the box.
checkv DENY_SILENT_CONTROL_OK      PASS DENY SILENT ADMITTED
checkv DENY_SILENT_CONTROL_SILENT  FAIL DENY SILENT SILENT
checkv DENY_SILENT_CONTROL_UNREACH FAIL DENY SILENT UNREACHED
checkv DENY_SILENT_CONTROL_BLIND   FAIL DENY SILENT BLIND
checkv DENY_SILENT_CONTROL_EMPTY   FAIL DENY SILENT ""

# An ICMP unreachable is not a deny even with a healthy control: the packet
# never reached a host-inbound decision.
checkv DENY_UNREACHED_IS_NOT_DENY  FAIL DENY UNREACHED ADMITTED
checkv DENY_BLIND                  FAIL DENY BLIND     ADMITTED
checkv DENY_EMPTY_OBS              FAIL DENY ""        ADMITTED

# A malformed table must fail loudly rather than fall through to a healthy word.
checkv UNKNOWN_EXPECTATION         FAIL WAT   ADMITTED ADMITTED
checkv EMPTY_EXPECTATION           FAIL ""    ADMITTED ADMITTED

# --- zone posture precondition ----------------------------------------------
ZONES='set security zones security-zone mgmt interfaces fxp0
set security zones security-zone mgmt host-inbound-traffic system-services ssh
set security zones security-zone wan interfaces reth0.50
set security zones security-zone wan interfaces reth0.80
set security zones security-zone wan host-inbound-traffic system-services ping
set security zones security-zone wan host-inbound-traffic system-services gre
set security zones security-zone lan interfaces reth1
set security zones security-zone lan host-inbound-traffic system-services ssh
set security zones security-zone lan host-inbound-traffic system-services ping'

checkz() {
	local name="$1" want="$2" lines="$3" zone="$4" svc="$5" expect="$6" got verdict
	got="$(hi_zone_service_verdict "$lines" "$zone" "$svc" "$expect")"
	verdict="${got%% *}"
	if [[ "$verdict" == "$want" ]]; then
		pass=$((pass + 1)); printf 'ok   %-34s -> %s\n' "$name" "$verdict"
	else
		fail=$((fail + 1)); printf 'FAIL %-34s -> want %s got %s (%s)\n' "$name" "$want" "$verdict" "$got"
	fi
	[[ "$(grep -c . <<<"$got")" -eq 1 ]] || {
		fail=$((fail + 1)); printf 'FAIL %-34s -> not exactly one line: %q\n' "$name" "$got"; }
}

checkz ZONE_LAN_ADMITS_SSH    PASS "$ZONES" lan ssh PRESENT
checkz ZONE_WAN_DENIES_SSH    PASS "$ZONES" wan ssh ABSENT
checkz ZONE_WAN_ADMITS_PING   PASS "$ZONES" wan ping PRESENT
checkz ZONE_LAN_SSH_NOT_ABSENT FAIL "$ZONES" lan ssh ABSENT
checkz ZONE_WAN_SSH_NOT_PRESENT FAIL "$ZONES" wan ssh PRESENT
# THE MIDDLE ROW AGAIN, for the precondition: an unreadable config must not be
# allowed to answer an ABSENT question. "wan does not admit ssh" and "I could
# not read the config" are the same string to grep, and only one of them is a
# reason to run the matrix.
checkz ZONE_EMPTY_CONFIG_BLIND    FAIL ""  wan ssh ABSENT
checkz ZONE_WS_CONFIG_BLIND       FAIL "   " wan ssh ABSENT
checkz ZONE_CLI_ERROR_BLIND       FAIL "error: unknown command" wan ssh ABSENT
checkz ZONE_NO_ZONES_BLIND        FAIL "set interfaces reth1 unit 0 family inet address 10.0.61.1/24" wan ssh ABSENT
# `system-services all` subsumes every named service, so an ABSENT expectation
# must fail on it. Without this, a zone opened wide still satisfies "ssh is not
# listed" and every DENY cell for that zone silently becomes a false pass.
ZONES_ALL='set security zones security-zone wan interfaces reth0.50
set security zones security-zone wan host-inbound-traffic system-services all'
checkz ZONE_ALL_DEFEATS_ABSENT    FAIL "$ZONES_ALL" wan ssh ABSENT
checkz ZONE_ALL_SATISFIES_PRESENT PASS "$ZONES_ALL" wan ssh PRESENT
# Whole-line match: a longer service name sharing the prefix is not the same
# token (the near-miss direction #7798's NEAR_MISS_GW row caught in the FBF lib).
ZONES_NEAR='set security zones security-zone wan interfaces reth0.50
set security zones security-zone wan host-inbound-traffic system-services ssh-alt'
checkz ZONE_NEAR_MISS_SERVICE     PASS "$ZONES_NEAR" wan ssh ABSENT
checkz ZONE_UNKNOWN_EXPECT        FAIL "$ZONES" wan ssh MAYBE

# --- probe-target derivation -------------------------------------------------
IFACES='set interfaces reth1 unit 0 family inet address 10.0.61.1/24
set interfaces reth1 unit 0 family inet6 address 2001:559:8585:ef00::1/64
set interfaces reth0 unit 50 family inet address 172.16.50.8/24
set interfaces reth0 unit 80 family inet address 172.16.80.8/24
set interfaces reth0 unit 80 family inet6 address 2001:559:8585:80::8/64'

checka() {
	local name="$1" want="$2" lines="$3" iface="$4" unit="$5" fam="$6" got
	got="$(hi_iface_address "$lines" "$iface" "$unit" "$fam")"
	if [[ "$got" == "$want" ]]; then
		pass=$((pass + 1)); printf 'ok   %-34s -> %s\n' "$name" "${got:-<empty>}"
	else
		fail=$((fail + 1)); printf 'FAIL %-34s -> want %q got %q\n' "$name" "$want" "$got"
	fi
}

checka ADDR_LAN_V4      10.0.61.1               "$IFACES" reth1 0  inet
checka ADDR_LAN_V6      2001:559:8585:ef00::1   "$IFACES" reth1 0  inet6
checka ADDR_VLAN50_V4   172.16.50.8             "$IFACES" reth0 50 inet
checka ADDR_VLAN80_V6   2001:559:8585:80::8     "$IFACES" reth0 80 inet6
# Unit is a whole field: unit 8 must not be answered by the unit-80 line.
checka ADDR_UNIT_NEAR_MISS ""                   "$IFACES" reth0 8  inet
checka ADDR_MISSING_FAMILY ""                   "$IFACES" reth0 50 inet6
# An unreadable config yields nothing — the caller treats empty as a
# precondition failure, so this must not fabricate an address.
checka ADDR_EMPTY_CONFIG   ""                   ""        reth1 0  inet
checka ADDR_NO_IFACES      ""                   "set security zones security-zone lan interfaces reth1" reth1 0 inet

# --- matrix stability across a failover --------------------------------------
checkm() {
	local name="$1" want="$2" a="$3" b="$4" got verdict
	got="$(hi_matrix_stable_verdict before "$a" after "$b")"
	verdict="${got%% *}"
	if [[ "$verdict" == "$want" ]]; then
		pass=$((pass + 1)); printf 'ok   %-34s -> %s\n' "$name" "$verdict"
	else
		fail=$((fail + 1)); printf 'FAIL %-34s -> want %s got %s (%s)\n' "$name" "$want" "$verdict" "$got"
	fi
	[[ "$(grep -c . <<<"$got")" -eq 1 ]] || {
		fail=$((fail + 1)); printf 'FAIL %-34s -> not exactly one line: %q\n' "$name" "$got"; }
}

BASE='lan-v4-ssh ADMITTED
lan-v4-telnet SILENT
wan-vlan50-v4-ssh SILENT'
checkm MATRIX_IDENTICAL   PASS "$BASE" "$BASE"
# Order must not matter; content must.
checkm MATRIX_REORDERED   PASS "$BASE" 'wan-vlan50-v4-ssh SILENT
lan-v4-ssh ADMITTED
lan-v4-telnet SILENT'
# The regression this leg exists for: an admission that silently stopped
# working across the failover. Both matrices' own cells could still be scored
# against their expectations; only the DIFF sees it.
checkm MATRIX_ADMIT_LOST  FAIL "$BASE" 'lan-v4-ssh SILENT
lan-v4-telnet SILENT
wan-vlan50-v4-ssh SILENT'
checkm MATRIX_DENY_LEAKED FAIL "$BASE" 'lan-v4-ssh ADMITTED
lan-v4-telnet SILENT
wan-vlan50-v4-ssh ADMITTED'
checkm MATRIX_CELL_VANISHED FAIL "$BASE" 'lan-v4-ssh ADMITTED
lan-v4-telnet SILENT'
# THE MIDDLE ROW, third time: an empty run must never read as "unchanged".
checkm MATRIX_AFTER_EMPTY   FAIL "$BASE" ''
checkm MATRIX_BEFORE_EMPTY  FAIL ''      "$BASE"
checkm MATRIX_BOTH_EMPTY    FAIL ''      ''

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
