#!/usr/bin/env bash
#
# v6-na-recovery-12495-selftest.sh — hermetic self-test for #12495's
# analysis layer (v6-na-recovery-lib-12495.sh + v6-na-parse-12495.py).
#
# NO incus, NO cluster, NO network, NO raw sockets. Every case is a literal
# evidence file or a synthetic pcap built byte-by-byte in a temp dir.
#
# The load-bearing properties, each asserted with a case that MUST pass and
# a mutation-shaped case that MUST NOT:
#
#   TOTALITY    every input class renders exactly one V6NA-VERDICT line and
#               one exit code — missing files, unprimed baselines, empty
#               captures, and a truncated capture record all decide VOID or
#               FAIL, never a silent empty pass.
#   ORDERING    the instrument is decided before the subject: a capture with
#               a live GARP witness and no NA is the #12201 mutant-A FAIL,
#               not a "no NA observed" VOID; a capture with NEITHER is VOID.
#   ATTRIBUTION the discriminator is the GLOBAL VIP entry flip with an
#               override NA at-or-before the flip. An RA repairing the
#               gateway entry does not produce a PASS; a flip without a
#               preceding override NA does not either.
#   FAIL-CLOSED an unparseable frame is PARSEERR → VOID, not a zero; the
#               pcap reader refuses bad magic / wrong linktype with rc1
#               instead of emitting an empty clean sweep.
#
# Usage: ./test/incus/v6-na-recovery-12495-selftest.sh   (rc 0 = all pass)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=v6-na-recovery-lib-12495.sh
source "${SCRIPT_DIR}/v6-na-recovery-lib-12495.sh"
PARSE="${SCRIPT_DIR}/v6-na-parse-12495.py"

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); echo "PASS ($PASS): $*"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL: $*" >&2; }

# check_verdict <name> <want-verdict> <want-rc> <want-instrument> -- <verdict args...>
#   Runs v6na_verdict, asserts the final line's verdict token, the mapped
#   exit status, and the INSTRUMENT cell.
check_verdict() {
	local name="$1" want_v="$2" want_rc="$3" want_instr="$4"
	shift 4
	[[ "${1:-}" == "--" ]] && shift
	local out rc
	out="$(v6na_verdict "$@")" || true
	local line instr
	line="$(printf '%s\n' "$out" | sed -n 's/^V6NA-VERDICT: //p' | tail -1)"
	instr="$(printf '%s\n' "$out" | sed -n 's/^INSTRUMENT: //p')"
	v6na_exit_status "V6NA-VERDICT: $line"
	rc=$?
	if [[ "$line" == "$want_v"* && "$instr" == "$want_instr" ]]; then
		if [[ "$rc" -eq "$want_rc" ]]; then
			ok "$name → $want_v (instrument $want_instr, rc $rc)"
			return 0
		fi
		bad "$name → verdict ok but rc $rc, want $want_rc (line: $line)"
		return 1
	fi
	bad "$name → verdict '$line' (instrument '$instr'), want '$want_v' with instrument '$want_instr'"
	printf '%s\n' "$out" | sed 's/^/      /' >&2
	return 1
}

T="$(mktemp -d /tmp/xpf-v6na-selftest.XXXXXX)"
trap 'rm -rf "$T"' EXIT

VIP="2001:559:8585:cf01::1"
GW="fe80::bf72:16:2"
OLD="02:bf:72:16:02:00" # old-master RETH vMAC (baseline binding)
NEW="02:bf:72:16:01:00" # new-master RETH vMAC
T0=100000
WIN=20000

# ── Shared evidence builders ────────────────────────────────────────────
events_na_flap() { # the healthy wire: GARP witness + override NAs for the
	# VIP and the gateway LLA, then the periodic RA
	cat <<EOF
99500 ARP 10.0.60.1 $OLD 1
100100 ARP 10.0.60.1 $NEW 1
100100 ARP 10.0.60.1 $NEW 2
100120 NA $GW $VIP $NEW RO
100140 NA $GW $GW $NEW RO
101500 RA $GW $NEW 180
EOF
}

neigh_healthy() {
	cat <<EOF
99000 NEIGH $VIP $OLD STALE
99010 NEIGH $GW $OLD REACHABLE
100300 NEIGH $VIP $NEW REACHABLE
100400 NEIGH $GW $NEW REACHABLE
EOF
}

# ── The verdict matrix ─────────────────────────────────────────────────
EV="$T/ev.txt"
NH="$T/nh.txt"

# 1. Happy path: witness + override NA, VIP flip after the NA, transit OK.
events_na_flap >"$EV"
neigh_healthy >"$NH"
check_verdict "healthy failover" PASS 0 LIVE-NA -- \
	"$T0" "$WIN" "$VIP" "$GW" "$OLD" "$OLD" "$EV" "$NH" 5 5 3 ||
	true

# 2. #12201 mutant-A: the GARP witness fired but no NA on the wire.
grep -v '^100[13][0-9][0-9] NA ' "$EV" >"$T/ev-mutant.txt" ||
	grep -v ' NA ' "$EV" >"$T/ev-mutant.txt"
check_verdict "mutant-A (GARP witness, no NA)" FAIL 1 MISSING-NA -- \
	"$T0" "$WIN" "$VIP" "$GW" "$OLD" "$OLD" "$T/ev-mutant.txt" "$NH" 0 5 3 ||
	true

# 3. Blind instrument: nothing at all in the window.
grep -v '^100' "$EV" >"$T/ev-blind.txt"
check_verdict "blind capture" VOID 2 BLIND -- \
	"$T0" "$WIN" "$VIP" "$GW" "$OLD" "$OLD" "$T/ev-blind.txt" "$NH" 0 5 3 ||
	true

# 4. NA present but not attribution-grade: Override clear.
sed 's/ RO$/ R/' "$EV" >"$T/ev-nooverride.txt"
check_verdict "NA without Override" VOID 2 NA-NOT-ATTRIBUTABLE -- \
	"$T0" "$WIN" "$VIP" "$GW" "$OLD" "$OLD" "$T/ev-nooverride.txt" "$NH" 5 5 3 ||
	true

# 5. NA with Override but the SAME (baseline) TLLA — a re-announcement,
#    not a takeover; must not count as attribution-grade.
sed "s/ $NEW RO\$/ $OLD RO/" "$EV" >"$T/ev-samemac.txt"
check_verdict "override NA re-announcing the baseline MAC" VOID 2 NA-NOT-ATTRIBUTABLE -- \
	"$T0" "$WIN" "$VIP" "$GW" "$OLD" "$OLD" "$T/ev-samemac.txt" "$NH" 5 5 3 ||
	true

# 6. Unprimed baseline: no pre-failover VIP entry — nothing to attribute.
events_na_flap >"$EV"
grep -v "NEIGH $VIP" "$NH" >"$T/nh-unprimed.txt"
check_verdict "unprimed baseline" VOID 2 LIVE-NA -- \
	"$T0" "$WIN" "$VIP" "$GW" "" "$OLD" "$EV" "$T/nh-unprimed.txt" 5 5 3 ||
	true

# 7. Flip with NO override NA before it: recovered, but not by the burst.
cat >"$NH" <<EOF
99000 NEIGH $VIP $OLD STALE
99010 NEIGH $GW $OLD REACHABLE
100110 NEIGH $VIP $NEW REACHABLE
EOF
check_verdict "recovered unattributed" VOID 2 LIVE-NA -- \
	"$T0" "$WIN" "$VIP" "$GW" "$OLD" "$OLD" "$EV" "$NH" 5 5 3 ||
	true

# 8. RA repairs the gateway entry only, VIP entry stale + transit dead:
#    the discrimination the issue is asking for. (Instrument is still
#    LIVE-NA here because the NA for the VIP is on the wire; the STALE
#    entry + blackhole is the receiver-side FAIL.)
cat >"$NH" <<EOF
99000 NEIGH $VIP $OLD STALE
99010 NEIGH $GW $OLD REACHABLE
100500 NEIGH $GW $NEW REACHABLE
EOF
check_verdict "VIP entry never moves, transit blackholed" FAIL 1 LIVE-NA -- \
	"$T0" "$WIN" "$VIP" "$GW" "$OLD" "$OLD" "$EV" "$NH" 0 5 3 || true

# 9. Entry attributed but transit still blackholed: a different defect.
neigh_healthy >"$NH"
check_verdict "NA-attributed recovery, transit blackholed" FAIL 1 LIVE-NA -- \
	"$T0" "$WIN" "$VIP" "$GW" "$OLD" "$OLD" "$EV" "$NH" 0 5 3 || true

# 10. Transit not measured: VOID, never a pass on missing evidence.
check_verdict "transit not measured" VOID 2 LIVE-NA -- \
	"$T0" "$WIN" "$VIP" "$GW" "$OLD" "$OLD" "$EV" "$NH" "" "" 3 || true

# 11. Unparseable frame in the capture: broken instrument, VOID.
EV2="$T/ev-parseerr.txt"
{ events_na_flap; echo "100500 PARSEERR NA truncated before target address"; } >"$EV2"
check_verdict "unparseable frame" VOID 2 PARSEERR -- \
	"$T0" "$WIN" "$VIP" "$GW" "$OLD" "$OLD" "$EV2" "$NH" 5 5 3 || true

# 12. Missing events file: VOID (nothing learned), not a shell abort.
check_verdict "missing events file" VOID 2 BLIND -- \
	"$T0" "$WIN" "$VIP" "$GW" "$OLD" "$OLD" "$T/does-not-exist.txt" "$NH" 5 5 3 || true

# 13. Empty argument list: the layer must still render one verdict line.
out="$(v6na_verdict)" || true
line="$(printf '%s\n' "$out" | sed -n 's/^V6NA-VERDICT: //p' | tail -1)"
v6na_exit_status "V6NA-VERDICT: $line" && rc=0 || rc=$?
if [[ "$line" == VOID* && "$rc" -eq 2 ]]; then
	ok "empty argument list → VOID rc2"
else
	bad "empty argument list → '$line' rc $rc, want VOID rc2"
fi

# 14. Exit-status totality: unrecognized verdict lines fail closed to 4.
for garbage in "" "PASS" "V6NA-VERDICT: MAYBE something"; do
	v6na_exit_status "$garbage" && rc=0 || rc=$?
	if [[ "$rc" -ne 4 ]]; then
		bad "exit status for '${garbage:-<empty>}' = $rc, want 4 (fail closed)"
	fi
done
ok "unrecognized verdict lines fail closed to rc4"

# ── The pcap parser, against a byte-built capture ─────────────────────
# Frames: GARP request, NA (Router+Override, TLLA=new vMAC), RA (SLLA,
# lifetime 180), NA truncated mid-target → PARSEERR, plus a final record
# that promises more bytes than the file holds. Timestamps are picked so
# the µs→ms rounding cannot collide (100/500/800/900/950 ms).
python3 - "$T/cap.pcap" "$OLD" "$NEW" "$VIP" "$GW" <<'PYEOF'
import ipaddress
import struct
import sys

path, old, new, vip, gw = sys.argv[1:6]
vip_b = ipaddress.IPv6Address(vip).packed
gw_b = ipaddress.IPv6Address(gw).packed
mc = ipaddress.IPv6Address("ff02::1").packed
mac_old = bytes(int(x, 16) for x in old.split(":"))
mac_new = bytes(int(x, 16) for x in new.split(":"))


def eth(payload, ethertype, src, dst):
    return dst + src + struct.pack("!H", ethertype) + payload


def ip6(payload, src, dst):
    hdr = struct.pack("!IHBB", 6 << 28, len(payload), 58, 255) + src + dst
    return hdr + payload


def na(target, tlla, flags=0xA0):
    body = bytes([136, 0, 0, 0, flags, 0, 0, 0]) + target
    if tlla is not None:
        body += bytes([2, 1]) + tlla + b"\x00\x00"
    return body  # checksum left zero: the parser reads fields only


def ra(slla, lifetime=180):
    body = bytes([134, 0, 0, 0, 64, 0]) + struct.pack("!H", lifetime) + b"\x00" * 8
    if slla is not None:
        body += bytes([1, 1]) + slla + b"\x00\x00"
    return body


def arp_request(sender_mac, sender_ip):
    return (
        struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
        + sender_mac
        + sender_ip
        + b"\xff\xff\xff\xff\xff\xff"
        + sender_ip
    )


frames = [
    (100000, eth(arp_request(mac_old, bytes([10, 0, 60, 1])), 0x0806, mac_old, b"\xff\xff\xff\xff\xff\xff")),
    (500000, eth(ip6(na(vip_b, mac_new), gw_b, mc), 0x86DD, mac_new, b"\x33\x33\x00\x00\x00\x01")),
    (800000, eth(ip6(ra(mac_new), gw_b, mc), 0x86DD, mac_new, b"\x33\x33\x00\x00\x00\x01")),
    (900000, eth(ip6(na(vip_b, mac_new)[:10], gw_b, mc), 0x86DD, mac_new, b"\x33\x33\x00\x00\x00\x01")),
]
out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
for usec, frame in frames:
    out.append(struct.pack("<IIII", 1700000000, usec, len(frame), len(frame)))
    out.append(frame)
# A truncated final record: header promises 40 bytes, only 10 present.
out.append(struct.pack("<IIII", 1700000000, 950000, 40, 40))
out.append(b"\x33" * 10)
open(path, "wb").write(b"".join(out))
PYEOF
if [[ $? -ne 0 ]]; then
	bad "synthetic pcap builder failed"
fi
PARSED="$(python3 "$PARSE" "$T/cap.pcap" 2>"$T/parse.err")"
want_parsed="1700000000100 ARP 10.0.60.1 $OLD 1
1700000000500 NA $GW $VIP $NEW RO
1700000000800 RA $GW $NEW 180
1700000000900 PARSEERR NA truncated before target address
1700000000950 PARSEERR truncated capture record"
if [[ "$PARSED" == "$want_parsed" ]]; then
	ok "pcap parser normalizes NA/RA/ARP and fails closed on truncation"
else
	bad "pcap parser output mismatch"
	printf '      want:\n%s\n      got:\n%s\n' "$want_parsed" "$PARSED" >&2
fi

# Unreadable captures are refused with rc1 + a stderr diagnostic — an
# unread capture must not render as an empty clean sweep.
printf 'not a pcap at all' >"$T/bad.pcap"
python3 "$PARSE" "$T/bad.pcap" >/dev/null 2>"$T/bad.err"
rc=$?
if [[ "$rc" -eq 1 && -s "$T/bad.err" ]]; then
	ok "bad-magic capture refused with rc1 + diagnostic"
else
	bad "bad-magic capture rc=$rc (want 1) or silent stderr"
fi
# A non-Ethernet linktype is the same refusal class (the lab capture must
# come from the LAN host's Ethernet device).
python3 - "$T/sll.pcap" <<'PYEOF'
import struct
import sys

with open(sys.argv[1], "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 113))
PYEOF
python3 "$PARSE" "$T/sll.pcap" >/dev/null 2>"$T/sll.err"
rc=$?
if [[ "$rc" -eq 1 && -s "$T/sll.err" ]]; then
	ok "non-Ethernet linktype refused with rc1 + diagnostic"
else
	bad "non-Ethernet linktype rc=$rc (want 1) or silent stderr"
fi

# ── #15733: the LAB gate must preserve pcap/timeline on non-zero exit ──
# Regression for the live 2026-10-19 run: the gate printed its FAIL
# verdict and then `trap 'rm -rf "$T"' EXIT` deleted cap.pcap/neigh.txt,
# destroying the only raw evidence. Exercise the gate script's actual
# EXIT trap hermetically: stub incus/python3 on PATH, drive it to a
# FAIL verdict (rc 1) and a PASS verdict (rc 0), and assert where the
# evidence ends up. A run that cannot reach a live verdict (VOID)
# preserves whatever partial timeline exists and invents nothing.
GATE="${SCRIPT_DIR}/test-v6-na-recovery-12495.sh"
STUB="$T/gate-stub"
mkdir -p "$STUB/bin" "$STUB/home"
# Synthetic pcap the stub "captures" from the LAN host: reuse the
# byte-built capture above (GARP + override NA + RA + PARSEERRs).
# Clean wire fixture for the gate cases — healthy attribution without
# PARSEERR: override NA (new MAC) for the VIP, epoch-2100 timestamps so
# they fall in the gate's [T0, window] without a fake clock.
python3 - "$STUB/fake.pcap" "$OLD" "$NEW" "$VIP" "$GW" <<'PYEOF'
import ipaddress, struct, sys
path, old, new, vip, gw = sys.argv[1:6]
vip_b = ipaddress.IPv6Address(vip).packed
gw_b = ipaddress.IPv6Address(gw).packed
mc = ipaddress.IPv6Address("ff02::1").packed
mac_old = bytes(int(x, 16) for x in old.split(":"))
mac_new = bytes(int(x, 16) for x in new.split(":"))
def eth(payload, ethertype, src, dst):
    return dst + src + struct.pack("!H", ethertype) + payload
def ip6(payload, src, dst):
    return struct.pack("!IHBB", 6 << 28, len(payload), 58, 255) + src + dst + payload
def na(target, tlla, flags=0xA0):
    return bytes([136, 0, 0, 0, flags, 0, 0, 0]) + target + bytes([2, 1]) + tlla + b"\x00\x00"
def arp(sender_mac, sender_ip):
    return struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + sender_mac + sender_ip + b"\xff" * 6 + sender_ip
frames = [
    (400000, eth(arp(mac_old, bytes([10, 0, 60, 1])), 0x0806, mac_old, b"\xff" * 6)),
    (400000, eth(ip6(na(vip_b, mac_new), gw_b, mc), 0x86DD, mac_new, b"\x33\x33\x00\x00\x00\x01")),
    (400000, eth(ip6(na(gw_b, mac_new), gw_b, mc), 0x86DD, mac_new, b"\x33\x33\x00\x00\x00\x01")),
]
out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
for usec, frame in frames:
    out.append(struct.pack("<IIII", 4102444800, usec, len(frame), len(frame)))
    out.append(frame)
open(path, "wb").write(b"".join(out))
PYEOF
cat >"$STUB/bin/date" <<'STUB_DATE'
#!/usr/bin/env bash
# Two clocks, deliberately separated. +%s%3N (the gate's T0 and
# neighbor-sample stamps) is CONSTANT at the wire stamps'
# epoch+400ms, so every wire event is exactly at T0 and at-or-before
# the first flipped sample — the attribution the fixture models.
# +%s (whole seconds) is used ONLY by wait_primary's deadline
# arithmetic, and it ADVANCES 1s per date call: a constant seconds
# clock would freeze `now - start` and hang the gate forever on any
# case whose failback cannot move (the pre-#15959 gate under the
# stranded stub included). Advancing only the seconds clock keeps
# the millisecond attribution exact while deadlines still expire —
# a 4s deadline after ~4 wait_primary polls.
c="${V6NA_DATE_COUNTER:-/dev/null}"
n=0; [[ -f "$c" ]] && n="$(cat "$c")"
echo $((n + 1)) >"$c" 2>/dev/null || true
if [[ "${1:-}" == "+%s%3N" ]]; then echo 4102444800400; elif [[ "${1:-}" == "+%s" ]]; then echo $((4102444800 + n)); else echo 4102444800400; fi
STUB_DATE
chmod +x "$STUB/bin/date"
rm -f "$STUB/fake.pcap.marker"
cat >"$STUB/bin/incus" <<'STUB_INCUS'
#!/usr/bin/env bash
# Hermetic incus stub for #15733 gate-preservation cases and the #15959
# failback-sequence case. State (RG primary) lives in $V6NA_STUB_STATE:
# line1 = primary before, and the stub flips it on every failover
# request, like the real cluster — EXCEPT when V6NA_STUB_STRANDED=1,
# which models the recorded #15959 strand: a plain (untargeted) failover
# request is a local yield that moves nothing (Preempt=no strands the
# RG on the current primary), a failover reset alone moves nothing, and
# only a targeted `... node <n>` request issued on the target node
# commits the transfer. Gate CLI commands are appended to
# $V6NA_STUB_CLI_LOG as "<host> <request>" before any state change.
case "$1" in
info) exit 0 ;;
exec)
	host="$2"; shift 2; [[ "${1:-}" == -- ]] && shift
	case "$host" in
	*host*)
		case "$*" in
		*"command -v tcpdump"*) echo /usr/sbin/tcpdump ;;
		*"ip -6 route show default"*) echo "default via fe80::bf72:16:2 dev eth0 proto ra metric 100" ;;
		"ping6 -c 1"*) echo ok ;;
		"ping6 -c 5"*) echo "5 packets transmitted, ${V6NA_STUB_TRANSIT:-5} received, 0% packet loss" ;;
		*"ip -6 neigh show"*)
			if [[ "$(cat "$V6NA_STUB_STATE")" == node1 ]]; then
				echo "2001:559:8585:ef00::1 dev eth0 lladdr 02:bf:72:16:01:00 REACHABLE"
				echo "fe80::bf72:16:2 dev eth0 lladdr 02:bf:72:16:01:00 REACHABLE"
			else
				echo "2001:559:8585:ef00::1 dev eth0 lladdr 02:bf:72:16:02:00 REACHABLE"
				echo "fe80::bf72:16:2 dev eth0 lladdr 02:bf:72:16:02:00 REACHABLE"
			fi ;;
		*"tcpdump: listening on"*) echo "tcpdump: listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes" ;;
		*nohup\ tcpdump*) : ;;
		"pkill -x tcpdump") : ;;
		"cat /tmp/v6na-12495.pcap") cat "$V6NA_STUB_PCAP" ;;
		"rm -f /tmp/v6na-12495.pcap"*) : ;;
		*) : ;;
		esac ;;
	*)
		case "$*" in
		*"show chassis cluster status"*)
			prim="$(cat "$V6NA_STUB_STATE")"
			# #15959: emit the REAL 6-line block (FormatStatus,
			# pkg/cluster/status.go): header, QUERIED HOST's row
			# first, its Takeover/Transfer/Forwarding sub-lines,
			# then the peer row. Prior stub emitted a 2-line block
			# (header + single primary row), which hid the gate's
			# grep -A2 blindness: in split state the peer primary
			# row is 5 lines below the header. Priorities follow
			# the live render (primary 200 / secondary* 100).
			# V6NA_STUB_HOLD=1 renders BOTH rows secondary-hold
			# (dual-hold transient: no primary row -> fail-closed).
			echo "Redundancy group: 2 , Failover count: 1"
			if [[ "$host" == *fw1 ]]; then local_node=node1; peer_node=node0; else local_node=node0; peer_node=node1; fi
			if [[ "${V6NA_STUB_HOLD:-0}" == 1 ]]; then
				local_row="secondary-hold"; peer_row="secondary-hold"
			elif [[ "$prim" == "$local_node" ]]; then
				local_row="primary"; peer_row="secondary"
			else
				local_row="secondary-hold"; peer_row="primary"
			fi
			if [[ "$local_row" == primary ]]; then local_prio=200; peer_prio=100; else local_prio=100; peer_prio=200; fi
			[[ "${V6NA_STUB_HOLD:-0}" == 1 ]] && { local_prio=100; peer_prio=100; }
			local_manual=no; [[ "$local_row" == secondary-hold ]] && local_manual=yes
			printf '%s %s %s no %s None\n' "$local_node" "$local_prio" "$local_row" "$local_manual"
			echo "  Takeover ready: yes"
			echo "  Transfer ready: yes"
			echo "  Forwarding: rg-active=inactive"
			printf '%s %s %s no no None\n' "$peer_node" "$peer_prio" "$peer_row" ;;
		*"request chassis cluster failover"*)
			printf '%s %s\n' "$host" "$*" >>"${V6NA_STUB_CLI_LOG:-/dev/null}"
			cur="$(cat "$V6NA_STUB_STATE")"
			if [[ "${V6NA_STUB_STRANDED:-0}" == 1 ]]; then
				# #15959 strand model. A TARGETED request naming the
				# node that hosts this command commits the transfer
				# to that node. A PLAIN request moves the RG only on
				# the FIRST failover (the gate's move under test,
				# tracked by $V6NA_STUB_MOVED): replayed as a
				# failback it is a local yield that moves NOTHING —
				# the recorded strand. A reset alone moves nothing.
				case "$*" in
				*" node 0"*) [[ "$host" == *fw0 ]] && echo node0 >"$V6NA_STUB_STATE" ;;
				*" node 1"*) [[ "$host" == *fw1 ]] && echo node1 >"$V6NA_STUB_STATE" ;;
				*"reset redundancy-group"*) : ;;
				*)
					if [[ ! -e "${V6NA_STUB_STATE}.moved" ]]; then
						: >"${V6NA_STUB_STATE}.moved"
						if [[ "$cur" == node0 ]]; then echo node1 >"$V6NA_STUB_STATE"; else echo node0 >"$V6NA_STUB_STATE"; fi
					fi ;;
				esac
			elif [[ "${V6NA_STUB_STRANDED:-0}" != 1 ]]; then
				# Faithful request classes: reset moves nothing, a
				# targeted request sets the named primary, a plain
				# request flips (yields the current primary).
				case "$*" in
				*"reset redundancy-group"*) : ;;
				*" node 0"*) echo node0 >"$V6NA_STUB_STATE" ;;
				*" node 1"*) echo node1 >"$V6NA_STUB_STATE" ;;
				*) if [[ "$cur" == node0 ]]; then echo node1 >"$V6NA_STUB_STATE"; else echo node0 >"$V6NA_STUB_STATE"; fi ;;
				esac
			fi ;;
		*) : ;;
		esac ;;
	esac ;;
esac
exit 0
STUB_INCUS
chmod +x "$STUB/bin/incus"
# cluster-env.sh (sourced by the gate) would point at real instances;
# shadow the FW*/host vars by pre-exporting them — cluster-env uses
# ${VAR:-default}, and the stub only needs incus on PATH.
run_gate() { # <name> <transit-recv> <want-rc>
	local name="$1" transit="$2" want_rc="$3"
	local g="$STUB/$name" out rc dest
	mkdir -p "$g/logs"
	echo node0 >"$g/state"
	# loss-userspace-cluster.env pins LAN_VIP6=...ef00::1 unconditionally,
	# so feed the gate a custom BPFRX_CLUSTER_ENV-free run with the self-
	# test VIP ($VIP=...cf01::1) — write a stub env that only sets it.
	printf 'LAN_VIP6="%s"\nLAN_HOST="cluster-userspace-host"\nINCUS_REMOTE="loss"\n' "$VIP" >"$g/cluster.env"
	out="$(cd "$SCRIPT_DIR" && BPFRX_CLUSTER_ENV="$g/cluster.env" V6NA_DATE_COUNTER="$g/date-counter" V6NA_STUB_STATE="$g/state" V6NA_STUB_PCAP="$STUB/fake.pcap" \
		V6NA_STUB_TRANSIT="$transit" V6_NA_LOG_DIR="$g/logs" V6_NA_WINDOW_MS=1000 V6_NA_POLL_MS=500 \
		PATH="$STUB/bin:$PATH" bash "$GATE" 2>&1)" && rc=0 || rc=$?
	if [[ "$rc" -ne "$want_rc" ]]; then
		bad "gate $name: exit $rc, want $want_rc"
		printf '%s\n' "$out" | sed 's/^/      /' >&2
		return
	fi
	dest="$(find "$g/logs" -maxdepth 1 -type d -name 'v6na-12495-*' | head -1)"
	if [[ "$want_rc" -eq 0 ]]; then
		if [[ -z "$dest" ]]; then
			ok "gate $name: PASS exit cleans scratch, preserves nothing"
		else
			bad "gate $name: PASS exit preserved evidence under $g/logs (want cleanup only)"
		fi
		return
	fi
	if [[ -n "$dest" && -s "$dest/cap.pcap" && -s "$dest/neigh.txt" && -s "$dest/events.txt" ]] &&
		grep -q 'evidence preserved' <<<"$out"; then
		ok "gate $name: non-zero exit $rc preserves pcap/timeline/events under log dir"
	else
		bad "gate $name: non-zero exit $rc did not preserve cap.pcap+neigh.txt+events.txt under $g/logs"
		printf '%s\n' "$out" | sed 's/^/      /' >&2
		find "$g" -type f | sed 's/^/      /' >&2
	fi
}
# FAIL shape (rc 1): neighbors recover via NA but transit blackholes —
# the exact 2026-10-19 live shape whose evidence was deleted.
run_gate fail-transit 0 1
# PASS shape (rc 0): transit healthy — scratch removed, nothing kept.
run_gate pass 5 0
# ── #15959: the gate failback must use the operator sequence ──────────
# With V6NA_STUB_STRANDED=1 the stub models the recorded strand: a
# plain (untargeted) failover request is a local yield that moves
# NOTHING (Preempt=no strands the RG on the current primary), a reset
# alone moves nothing, and only a targeted `... node <n>` request
# issued on the target node commits the transfer. The gate must
# therefore still converge to PASS (rc 0) — under the pre-#15959
# plain-request failback this case exits 3 (failback strands RG2) —
# and its CLI log must show the operator order on the target host:
# reset BEFORE the targeted request. FAILOVER_DEADLINE is pinned to
# 4s so a regression fails in seconds, not 300s. The one plain request
# in the log is the initial failover (the move under test); the
# failback half must contribute none — asserted by counting exactly
# one untargeted request.
# Parser regression (#15959): the stub emits the REAL 6-line block, so
# in split state rg_primary(fw0) must read node1 (peer row 5 lines below
# the header) and the failback branch must fire. Note this stranded case
# does NOT pin the parser: the gate's FW1 cross-check rescues it under
# the old grep -A2 parser (fw1's own primary row sits inside the -A2
# window), so it still passes with the parser reverted — verified by
# reverting it. The parser unit cases below are the parser pin: they
# fail (3 cases) under the old parser.
run_gate_stranded() {
	local g="$STUB/stranded" out rc log reset_ln target_ln plain_count
	mkdir -p "$g/logs"
	echo node0 >"$g/state"
	rm -f "$g/state.moved"
	: >"$g/cli.log"
	printf 'LAN_VIP6="%s"\nLAN_HOST="cluster-userspace-host"\nINCUS_REMOTE="loss"\n' "$VIP" >"$g/cluster.env"
	out="$(cd "$SCRIPT_DIR" && BPFRX_CLUSTER_ENV="$g/cluster.env" V6NA_DATE_COUNTER="$g/date-counter" V6NA_STUB_STATE="$g/state" V6NA_STUB_PCAP="$STUB/fake.pcap" \
		V6NA_STUB_TRANSIT=5 V6NA_STUB_STRANDED=1 V6NA_STUB_CLI_LOG="$g/cli.log" V6_NA_LOG_DIR="$g/logs" \
		V6_NA_WINDOW_MS=1000 V6_NA_POLL_MS=500 FAILOVER_DEADLINE=4 \
		PATH="$STUB/bin:$PATH" bash "$GATE" 2>&1)" && rc=0 || rc=$?
	log="$(cat "$g/cli.log")"
	reset_ln="$(grep -n 'fw0 .*failover reset redundancy-group 2$' "$g/cli.log" | head -1 | cut -d: -f1)"
	target_ln="$(grep -n 'fw0 .*failover redundancy-group 2 node 0$' "$g/cli.log" | head -1 | cut -d: -f1)"
	plain_count="$(grep -cE 'failover redundancy-group 2$' "$g/cli.log" || true)"
	if [[ "$rc" -eq 0 && -n "$reset_ln" && -n "$target_ln" && "$reset_ln" -lt "$target_ln" && "$plain_count" -eq 1 ]]; then
		ok "gate stranded: operator failback (reset then targeted node 0 on fw0) returns RG2, rc 0"
	else
		bad "gate stranded: rc=$rc reset_ln=${reset_ln:-none} target_ln=${target_ln:-none} plain=$plain_count (pre-#15959 plain failback exits 3 here)"
		printf '%s\n' "$out" | sed 's/^/      /' >&2
		printf '%s\n' "$log" | sed 's/^/      cli: /' >&2
	fi
}
run_gate_stranded
# ── #15959 parser unit cases: rg_primary over the REAL 6-line block ──
# Extract the gate's rg_primary verbatim and drive it against canned
# status text (stub incus below returns $V6NA_STUB_STATUS verbatim).
# Old grep -A2 parser MUST fail the split cases: on fw0's view the
# node1-primary row is 5 lines below the header, outside -A2.
mkdir -p "$T/parser/bin"
cat >"$T/parser/bin/incus" <<'STUB_PARSER_INCUS'
#!/usr/bin/env bash
case "$*" in
*"show chassis cluster status"*) printf '%s\n' "$V6NA_STUB_STATUS" ;;
*) : ;;
esac
exit 0
STUB_PARSER_INCUS
chmod +x "$T/parser/bin/incus"
sed -n '/^rg_primary() {/,/^}/p' "$GATE" >"$T/parser/rg_primary.sh"
check_rg() { # <name> <host fw0|fw1> <want> <status>
	local name="$1" host="$2" want="$3" status="$4" got
	got="$(V6NA_STUB_STATUS="$status" PATH="$T/parser/bin:$PATH" bash -c 'source "$1"; V6_NA_RG=2; rg_primary "$2"' _ "$T/parser/rg_primary.sh" "$host")"
	if [[ "$got" == "$want" ]]; then ok "parser $name: rg_primary($host)=${want:-<empty>}"; else bad "parser $name: rg_primary($host)=${got:-<empty>}, want ${want:-<empty>}"; fi
}
# Host-ordered 6-line blocks: queried host's row first, then its three
# sub-lines, then the peer row (pkg/cluster/status.go FormatStatus).
BLK_FW0_N0='Redundancy group: 2 , Failover count: 1
node0 200 primary no no None
  Takeover ready: yes
  Transfer ready: yes
  Forwarding: rg-active=active
node1 100 secondary no no None'
BLK_FW0_N1='Redundancy group: 2 , Failover count: 6
node0 100 secondary-hold no yes None
  Takeover ready: yes
  Transfer ready: yes
  Forwarding: rg-active=inactive
node1 100 primary no no None'
BLK_FW1_N1='Redundancy group: 2 , Failover count: 6
node1 100 primary no no None
  Takeover ready: yes
  Transfer ready: yes
  Forwarding: rg-active=active
node0 100 secondary-hold no yes None'
BLK_FW1_N0='Redundancy group: 2 , Failover count: 1
node1 100 secondary no no None
  Takeover ready: yes
  Transfer ready: yes
  Forwarding: rg-active=inactive
node0 200 primary no no None'
BLK_HOLD='Redundancy group: 2 , Failover count: 6
node0 100 secondary-hold no yes None
  Takeover ready: no (peer secondary not ready to become primary)
  Transfer ready: yes
  Forwarding: rg-active=inactive
node1 100 secondary-hold no no None'
BLK_MULTI='Redundancy group: 1 , Failover count: 0
node0 200 primary no no None
  Takeover ready: yes
  Transfer ready: yes
  Forwarding: rg-active=active
node1 100 secondary no no None
Redundancy group: 2 , Failover count: 6
node0 100 secondary-hold no yes None
  Takeover ready: yes
  Transfer ready: yes
  Forwarding: rg-active=inactive
node1 100 primary no no None
Redundancy group: 10 , Failover count: 0
node0 200 primary no no None
  Takeover ready: yes
  Transfer ready: yes
  Forwarding: rg-active=active
node1 100 secondary no no None'
check_rg node0-primary-fw0 fw0 node0 "$BLK_FW0_N0"
check_rg node1-primary-split-fw0 fw0 node1 "$BLK_FW0_N1"
check_rg node1-primary-fw1 fw1 node1 "$BLK_FW1_N1"
check_rg node0-primary-split-fw1 fw1 node0 "$BLK_FW1_N0"
check_rg dual-hold-empty fw0 "" "$BLK_HOLD"
check_rg multi-rg-scoped fw0 node1 "$BLK_MULTI"
check_rg empty-status fw0 "" ""
echo "RESULTS: ${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
