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
# Since #12912 it also pins the listener-presence gate: unit rows for
# hi_socket_ownership_verdict and a sed-lifted run of the live smoke's
# start_ssh_probe_listener against fake ss/pgrep fixtures, so a missing or
# foreign TCP/23 listener can no longer pass telnet DENY cells vacuously.
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

# --- listener presence gate: per-port verdict (#12912) ------------------------
# hi_socket_ownership_verdict is the per-port gate start_ssh_probe_listener
# runs before ANY host-inbound cell is scored. THE FIRST ROW is the #12912
# defect itself: an owned marker process alone must not satisfy a port with
# no wildcard-bound socket — the empty socket list used to walk through an
# empty ownership loop and pass every telnet DENY cell vacuously while the
# live TCP/22 listener kept the shared marker non-empty.
checkg() {
	local name="$1" want="$2" port="$3" owned="$4" ss="$5" got verdict
	got="$(hi_socket_ownership_verdict "$port" "$owned" <<<"$ss")"
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

GATE_SS_22='State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
LISTEN 0 16 [::]:22 [::]:* users:(("python3",pid=1022,fd=3))'
# THE #12912 ROW: this port's marker process is alive (owned non-empty) but
# no wildcard socket exists for it — FAIL, never a vacuous pass.
checkg GATE_NO_SOCKET_FAILS FAIL 23 "1023" "$GATE_SS_22"
# The same reading with nothing owned at all, and with no ss output at all.
checkg GATE_EMPTY_OWNED_FAILS FAIL 22 "" "$GATE_SS_22"
checkg GATE_EMPTY_SS_FAILS     FAIL 22 "1022" ""
# Foreign holder: the socket exists but belongs to another process.
GATE_SS_FOREIGN='State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
LISTEN 0 16 [::]:22 [::]:* users:(("python3",pid=1022,fd=3))
LISTEN 0 16 [::]:23 [::]:* users:(("inetd",pid=9876,fd=5))'
checkg GATE_FOREIGN_HOLDER_FAILS FAIL 23 "1023" "$GATE_SS_FOREIGN"
# Loopback-only is not externally reachable: no wildcard row for the port.
GATE_SS_LO='State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
LISTEN 0 16 [::]:22 [::]:* users:(("python3",pid=1022,fd=3))
LISTEN 0 16 127.0.0.1:23 0.0.0.0:* users:(("python3",pid=1023,fd=3))'
checkg GATE_LOOPBACK_ONLY_FAILS FAIL 23 "1023" "$GATE_SS_LO"
# Near-miss port: :230 is not :23.
GATE_SS_NEAR='State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
LISTEN 0 16 [::]:230 [::]:* users:(("python3",pid=1023,fd=3))'
checkg GATE_PORT_NEAR_MISS_FAILS FAIL 23 "1023" "$GATE_SS_NEAR"
# Multi-pid socket: one foreign co-holder spoils the whole port...
GATE_SS_MULTI='State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
LISTEN 0 16 [::]:23 [::]:* users:(("python3",pid=1023,fd=3),("python3",pid=9876,fd=3))'
checkg GATE_MULTI_ONE_FOREIGN_FAILS FAIL 23 "1023" "$GATE_SS_MULTI"
# ...while a fully-owned multi-pid socket passes, as does each plain port.
checkg GATE_MULTI_ALL_OWNED_PASSES PASS 23 $'1023\n9876' "$GATE_SS_MULTI"
GATE_SS_BOTH='State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
LISTEN 0 16 [::]:22 [::]:* users:(("python3",pid=1022,fd=3))
LISTEN 0 16 [::]:23 [::]:* users:(("python3",pid=1023,fd=3))'
checkg GATE_OWNED_22_PASSES PASS 22 "1022" "$GATE_SS_BOTH"
checkg GATE_OWNED_23_PASSES PASS 23 "1023" "$GATE_SS_BOTH"

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
	local name="$1" want="$2" lines="$3" zone="$4" svc="$5" expect="$6" iface="${7:-}" got verdict
	got="$(hi_zone_service_verdict "$lines" "$zone" "$svc" "$expect" "$iface")"
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
checkz ZONE_WAN_INTERFACE_SSH_ADMITS FAIL "$ZONES" wan ssh PRESENT reth0.50
checkz ZONE_WAN_INTERFACE_SSH_DENIED PASS "$ZONES" wan ssh ABSENT reth0.50
ZONES_IFACE_SSH='set security zones security-zone wan interfaces reth0.50
set security zones security-zone wan host-inbound-traffic system-services all
set security zones security-zone wan interfaces reth0.50 host-inbound-traffic system-services ssh'
checkz ZONE_IFACE_OVERRIDE_ADMITS PASS "$ZONES_IFACE_SSH" wan ssh PRESENT reth0.50
checkz ZONE_IFACE_OVERRIDE_REPLACES PASS "$ZONES_IFACE_SSH" wan telnet ABSENT reth0.50
ZONES_ALL_EXCEPT='set security zones security-zone wan interfaces reth0.50
set security zones security-zone wan host-inbound-traffic system-services all
set security zones security-zone wan host-inbound-traffic system-services ssh except'
checkz ZONE_ALL_EXCEPT_DENIES FAIL "$ZONES_ALL_EXCEPT" wan ssh PRESENT
checkz ZONE_ALL_EXCEPT_ABSENT PASS "$ZONES_ALL_EXCEPT" wan ssh ABSENT
ZONES_ANY='set security zones security-zone wan interfaces reth0.50
set security zones security-zone wan host-inbound-traffic system-services any-service'
checkz ZONE_ANY_ADMITS PASS "$ZONES_ANY" wan ssh PRESENT
checkz ZONE_ANY_DEFEATS_ABSENT FAIL "$ZONES_ANY" wan ssh ABSENT
ZONES_ALL_TOKEN_EXCEPT='set security zones security-zone wan interfaces reth0.50
set security zones security-zone wan host-inbound-traffic system-services all except'
checkz ZONE_ALL_TOKEN_EXCEPT_ABSENT PASS "$ZONES_ALL_TOKEN_EXCEPT" wan ssh ABSENT
ZONES_ANY_EXCEPT='set security zones security-zone wan interfaces reth0.50
set security zones security-zone wan host-inbound-traffic system-services any-service
set security zones security-zone wan host-inbound-traffic system-services any-service except'
# xpf rejects this combination in strict validation; tolerant compilation
# retains the packet-wide full-admit token, so it must never certify ABSENT.
checkz ZONE_ANY_EXCEPT_STAYS_OPEN FAIL "$ZONES_ANY_EXCEPT" wan ssh ABSENT
ZONES_ANY_SSH_EXCEPT='set security zones security-zone wan interfaces reth0.50
set security zones security-zone wan host-inbound-traffic system-services any-service
set security zones security-zone wan host-inbound-traffic system-services ssh except'
# CompileConfigLenient retains any-service despite this unsupported subtraction.
checkz ZONE_ANY_SSH_EXCEPT_REMAINS_OPEN FAIL "$ZONES_ANY_SSH_EXCEPT" wan ssh ABSENT
checkz ZONE_ANY_SSH_EXCEPT_PRESENT      PASS "$ZONES_ANY_SSH_EXCEPT" wan ssh PRESENT
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

# --- THE DECISIVE CHECK (#12912): the live gate under hermetic ss/pgrep -----
# The unit rows above pin hi_socket_ownership_verdict; these rows pin the
# WIRING in test-host-inbound.sh. The live start_ssh_probe_listener (and,
# post-fix, hi_ssh_listener_mark) is lifted out of the real script by
# sed-range eval — the same pattern cluster-cell-selftest.sh uses to lift
# xpf_assert_cluster_lock_idle out of test-connectivity.sh — and run against
# a fake `incus` whose `pgrep -f` answers come from the listener processes
# the function itself just started and whose `ss -tlnp` rows come from the
# same world. THE FIRST ROW is the issue's scenario: only the TCP/22
# listener alive. On master the shared marker kept `owned` non-empty and the
# port-23 socket list came back empty, so the ownership loop iterated zero
# times and the gate sailed through to its info line — the vacuous pass
# behind every telnet DENY cell. Only the both-owned scenario may pass.
GATE_TMP="$(mktemp -d)"
trap 'rm -rf "$GATE_TMP"' EXIT
mkdir -p "$GATE_TMP/bin"
cat >"$GATE_TMP/bin/incus" <<'FAKE_INCUS'
#!/usr/bin/env bash
# Fake incus for the #12912 listener-gate drive: hermetic ss/pgrep fixtures.
# It models exactly the four verbs start_ssh_probe_listener uses:
#   exec <inst> -- pkill -f <pat>    no-op success (stale cleanup)
#   exec <inst> -- bash -c <cmd>     record the listener: parse MARK= and the
#                                    s.bind port out of the python payload,
#                                    pid := 9000+port
#   exec <inst> -- pgrep -f <pat>    pids of LIVE listeners whose recorded
#                                    MARK contains the pattern (pgrep -f on
#                                    a plain-string mark is a substring test)
#   exec <inst> -- ss -tlnp          one [::]:<port> row per LIVE listener,
#                                    plus one foreign row when
#                                    HI_FAKE_FOREIGN_PORT/HI_FAKE_FOREIGN_PID
#                                    name a foreign holder
# "LIVE" is decided by HI_FAKE_WORLD, a file listing the ports whose listener
# actually survived: a port missing from it never started or died at bind —
# no process, no socket.
set -u
[[ "${1:-}" == exec ]] || exit 0
shift 2
[[ "${1:-}" == -- ]] && shift
world="${HI_FAKE_WORLD:?HI_FAKE_WORLD must name the live-ports file}"
case "${1:-}" in
pkill)
	exit 0
	;;
bash)
	cmd="$3"
	mark="${cmd#*MARK=\"}"
	mark="${mark%%\"*}"
	port="${cmd#*s.bind((\"::\", }"
	port="${port%%)*}"
	if [[ -z "$mark" || -z "$port" || ! "$port" =~ ^[0-9]+$ ]]; then
		echo "fake-incus: cannot parse MARK/bind port from: $cmd" >&2
		exit 1
	fi
	printf '%s %s %s\n' "$port" "$((9000 + port))" "$mark" >>"${world}.procs"
	exit 0
	;;
pgrep)
	pat="$3"
	found=0
	while read -r p pid m; do
		[[ -n "$p" ]] || continue
		grep -qx "$p" "$world" || continue
		if [[ "MARK=$m" == *"$pat"* ]]; then
			echo "$pid"
			found=1
		fi
	done <"${world}.procs"
	exit $((1 - found))
	;;
ss)
	echo 'State Recv-Q Send-Q Local Address:Port Peer Address:Port Process'
	while read -r p pid m; do
		[[ -n "$p" ]] || continue
		grep -qx "$p" "$world" || continue
		printf 'LISTEN 0 16 [::]:%s [::]:* users:(("python3",pid=%s,fd=3))\n' "$p" "$pid"
	done <"${world}.procs"
	if [[ -n "${HI_FAKE_FOREIGN_PORT:-}" ]]; then
		printf 'LISTEN 0 16 [::]:%s [::]:* users:(("inetd",pid=%s,fd=5))\n' \
			"$HI_FAKE_FOREIGN_PORT" "${HI_FAKE_FOREIGN_PID:?}"
	fi
	exit 0
	;;
*)
	echo "fake-incus: unexpected verb: $*" >&2
	exit 1
	;;
esac
FAKE_INCUS
chmod +x "$GATE_TMP/bin/incus"
cat >"$GATE_TMP/bin/sleep" <<'FAKE_SLEEP'
#!/usr/bin/env sh
# The real gate sleeps 1s per node to let listeners bind; the fake ones bind
# instantly.
exit 0
FAKE_SLEEP
chmod +x "$GATE_TMP/bin/sleep"

# Lift the LIVE gate out of test-host-inbound.sh. hi_ssh_listener_mark is a
# one-line function, so it is matched whole-line (a `{...},/^}/` range would
# run past its end-of-line brace and double-print the function below). A
# missing start function must be a loud FAIL, not three silently-green
# scenarios over a stub.
HI_GATE_SRC="$(sed -n '/^HI_SSH_LISTENER_MARK=/p
	/^hi_ssh_listener_mark()/p
	/^start_ssh_probe_listener() {/,/^}/p' "${SCRIPT_DIR}/test-host-inbound.sh")"
if [[ -n "$(sed -n '/^start_ssh_probe_listener() {/,/^}/p' "${SCRIPT_DIR}/test-host-inbound.sh")" ]]; then
	pass=$((pass + 1)); printf 'ok   %-34s -> start_ssh_probe_listener lifted from the live smoke\n' "GATE_EXTRACT"
else
	fail=$((fail + 1)); printf 'FAIL %-34s -> could not extract start_ssh_probe_listener from test-host-inbound.sh\n' "GATE_EXTRACT"
fi

# gate_case <name> <dies|passes> <live-ports...>
#   Run the live gate against a world where exactly <live-ports> survived.
#   dies:   the gate must fail closed (die, exit 2) naming the guilty port.
#   passes: the gate must reach its per-port ownership info line (exit 0).
gate_case() {
	local name="$1" want="$2"; shift 2
	local out rc=0 world ok=0 why
	world="${GATE_TMP}/${name}.world"
	printf '%s\n' "$@" >"$world"
	rm -f "${world}.procs"
	out="$(
		(
			export HI_FAKE_WORLD="$world" PATH="${GATE_TMP}/bin:$PATH"
			eval "$HI_GATE_SRC"
			# FW0/FW1 ride the command environment (the eval'd gate reads
			# them); die/info stand in for the smoke's own helpers.
			die() { printf 'DIE: %s\n' "$*"; exit 2; }
			info() { printf 'INFO: %s\n' "$*"; }
			FW0=node0 FW1=node1 start_ssh_probe_listener
		) 2>&1
	)" || rc=$?
	case "$want" in
	dies)
		[[ "$rc" -eq 2 ]] && grep -q '^DIE: .*23' <<<"$out" && ok=1
		why="want fail-closed die naming port 23, got rc=$rc: $(head -1 <<<"$out")"
		;;
	passes)
		[[ "$rc" -eq 0 ]] && grep -q '^INFO: ' <<<"$out" && ok=1
		why="want the per-port ownership info line, got rc=$rc: $(head -1 <<<"$out")"
		;;
	*)
		why="bad want: $want"
		;;
	esac
	if [[ "$ok" -eq 1 ]]; then
		pass=$((pass + 1)); printf 'ok   %-34s -> %s\n' "$name" "$want"
	else
		fail=$((fail + 1)); printf 'FAIL %-34s -> %s\n' "$name" "$why"
	fi
}

# Owned TCP/22 only (no /23): the #12912 scenario — must DIE.
gate_case GATE_LIVE_OWNED_22_ONLY_DIES dies 22
# Foreign TCP/23 (our 23 dead, someone else's socket): must DIE.
HI_FAKE_FOREIGN_PORT=23 HI_FAKE_FOREIGN_PID=9876 \
	gate_case GATE_LIVE_FOREIGN_23_DIES dies 22
# Both owned: the only world that may reach the info line.
gate_case GATE_LIVE_BOTH_OWNED_PASSES passes 22 23
# A fatal precondition must still publish the same structured envelope as a
# completed run. The old die() exited 2 before the normal-summary WIRE_GATE.
HI_DIE_SRC="$(sed -n '/^die() {/,/^}/p' "${SCRIPT_DIR}/test-host-inbound.sh")"
die_out="$(HI_DIE_SRC="$HI_DIE_SRC" bash -c '
	eval "$HI_DIE_SRC"
	PASS=3 FAIL=1 POSTURE_PASS=2 POSTURE_FAIL=1 WITH_FAILOVER=0
	die "fixture precondition failed"
' 2>&1)"
die_rc=$?
if [[ "$die_rc" -eq 2 ]] && grep -qxF 'WIRE_GATE test-host-inbound VOID reason=harness-void cells_passed=3 cells_failed=1 posture_passed=2 posture_failed=1' <<<"$die_out"; then
	pass=$((pass + 1)); printf 'ok   %-34s -> fatal WIRE_GATE envelope\n' "GATE_FATAL_LEDGER"
else
	fail=$((fail + 1)); printf 'FAIL %-34s -> fatal WIRE_GATE missing or malformed: rc=%s output=%s\n' "GATE_FATAL_LEDGER" "$die_rc" "$die_out"
fi


printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
