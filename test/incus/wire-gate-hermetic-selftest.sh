#!/usr/bin/env bash
# shellcheck shell=bash
#
# wire-gate-hermetic-selftest.sh — the #11056 hermetic legs of the three
# zero-ledger-row wire gates (wire_policy_deny, wire_hostinbound_deny,
# wire_appmatch_twins).
#
# The live legs of those gates need the loss userspace cluster and are
# operator-held (issue #11056 triage 2026-09-27 / 2026-10-09). Until they
# run, everything about the gates that is CODE is proven HERE, hermetically:
#
#   Part A (always, no privileges, seconds):
#     A1  the capture REDUCTION functions count real tcpdump text exactly
#         (committed transcripts under test/fixtures/wire/, produced by the
#         real probes + real tcpdump; see each file's header);
#     A2  the reductions reject near-misses: a prefix port, an over-long
#         port, a reply FROM a service port (vs frames TO it), corruption on
#         a transport the gate did not filter for;
#     A3  the gates' own --fixture modes turn the real measured transcripts
#         into the verdicts the runs produced (PASS / leak-FAIL / exposed-
#         FAIL / capture-blind VOID);
#     A4  the §2 floors bind on REAL captures: an exact, healthy but small
#         capture cannot PASS — the verdict is VOID under-sampled, so a
#         green row can never be manufactured from a thin excerpt.
#
#   Part B (root + netns + tcpdump + nft + ethtool; skipped with a printed
#   reason otherwise): rebuilds the measurements live in an isolated 3-netns
#   veth topology — prober --nft-forward-drop--> sink/capture — using the
#   real wire_probe_burst.py / wire_tcp_accept.py, the gates' tcpdump flag
#   sets and the gate burst sizes, then feeds the SAME reduction functions
#   and verdict cores. The committed Part-A transcripts were produced by
#   exactly this pipeline (docs/log/11056.md records the run).
#
# Nothing here proves the DUT enforces policy on the wire; that is the live
# leg and it stays owed to the operator. What this proves is that everything
# AROUND the DUT — probe accounting, capture reduction, floors, verdicts, and
# their falsifiability in BOTH directions — is correct, so the operator's run
# measures the thing it claims.
#
# Exit: 0 all cells green, 1 any cell failed, 77 nothing could run.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/incus/wire-gate-lib.sh
source "${SCRIPT_DIR}/wire-gate-lib.sh"

FIXDIR="$(cd "$SCRIPT_DIR/../../test/fixtures/wire" && pwd)"
PROBE="${SCRIPT_DIR}/wire_probe_burst.py"
ACCEPT="${SCRIPT_DIR}/wire_tcp_accept.py"

LIVE=auto
for arg in "$@"; do
	case "$arg" in
	--live-only) LIVE=only ;;
	--no-live) LIVE=no ;;
	-h | --help) sed -n '1,40p' "$0"; exit 0 ;;
	*) echo "unknown flag: $arg" >&2; exit 2 ;;
	esac
done

PASS=0
FAIL=0
SKIP=0

cell() { # cell <want> <label> — rc 0 iff want matches
	local want="$1" label="$2"
	if [[ "$3" == "$want" ]]; then
		echo "  PASS  $label"
		PASS=$((PASS + 1))
	else
		echo "  FAIL  $label (want $want, got '$3')"
		FAIL=$((FAIL + 1))
	fi
}
skip_cell() {
	echo "  SKIP  $1"
	SKIP=$((SKIP + 1))
}

# ── Part A0: probe accounting on loopback (unprivileged) ──────────────
#
# The OFFERED counts every wire verdict floors come from the probe scripts'
# SENT lines, and the #10029 control leg reads wire_tcp_accept.py's ACCEPTED
# count. A probe that under-reports turns a full burst into a VOID; one that
# over-reports fakes the floor. Loopback is lossless, so offered MUST equal
# what the sink observes — no capture or privileges needed.
echo "=== A0: probe SENT accounting against loopback sinks ==="
if ! command -v python3 >/dev/null 2>&1; then
	skip_cell "probe accounting: python3 not installed"
else
	A0_DIR="$(mktemp -d "${TMPDIR:-/var/worktrees/.cache/tmpdir}/xpf-wire-a0.XXXXXX")"
	UP1=$((51000 + $$ % 4000))
	UP2=$((UP1 + 1))
	python3 - "$UP1" "$UP2" >"$A0_DIR/sink.out" 2>"$A0_DIR/sink.err" <<'PYEOF' &
import socket, sys, time
p1, p2 = int(sys.argv[1]), int(sys.argv[2])
s1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s1.bind(("127.0.0.1", p1)); s2.bind(("127.0.0.1", p2))
except OSError as exc:
    print("BINDFAIL %s" % exc); sys.exit(3)
print("READY", flush=True)
deadline = time.time() + 8
for s in (s1, s2):
    s.settimeout(0.5)
n1 = n2 = 0
while time.time() < deadline:
    for s, which in ((s1, 1), (s2, 2)):
        try:
            s.recvfrom(2048)
            if which == 1: n1 += 1
            else: n2 += 1
        except socket.timeout:
            pass
print("SINK %d %d" % (n1, n2), flush=True)
PYEOF
	A0_SINK=$!
	for _ in $(seq 50); do
		grep -q '^READY$' "$A0_DIR/sink.out" 2>/dev/null && break
		grep -q '^BINDFAIL' "$A0_DIR/sink.err" "$A0_DIR/sink.out" 2>/dev/null && break
		sleep 0.1
	done
	if grep -q '^BINDFAIL' "$A0_DIR/sink.err" "$A0_DIR/sink.out" 2>/dev/null; then
		skip_cell "probe accounting: loopback ports $UP1/$UP2 unavailable"
	else
		sent=$(python3 "$PROBE" --dst 127.0.0.1 --probe-port "$UP1" --control-port "$UP2" --count 20 --rate 400 2>/dev/null | grep '^SENT')
		wait "$A0_SINK" 2>/dev/null || true
		sink=$(grep -E '^SINK [0-9]+ [0-9]+$' "$A0_DIR/sink.out" | tail -1)
		s1n=$(awk '{print $2}' <<<"$sink")
		s2n=$(awk '{print $3}' <<<"$sink")
		cell "SENT probe=20 control=20" "probe/control SENT line reports the offered burst" "$sent"
		cell 20 "the udp sink observes every probe datagram (loopback is lossless)" "${s1n:-none}"
		cell 20 "the udp sink observes every control datagram" "${s2n:-none}"
	fi

	# TCP legs: established AND refused both count as offered (#9531 twins
	# semantics); the acceptor counts completed handshakes.
	TP=$((UP1 + 100))
	python3 "$ACCEPT" --port "$TP" --duration 4 >"$A0_DIR/acc.out" 2>&1 &
	A0_ACC=$!
	for _ in $(seq 50); do grep -q '^LISTENING' "$A0_DIR/acc.out" 2>/dev/null && break; sleep 0.1; done
	if ! grep -q '^LISTENING' "$A0_DIR/acc.out" 2>/dev/null; then
		skip_cell "tcp-leg accounting: loopback port $TP unavailable"
	else
		tsent=$(python3 "$PROBE" --dst 127.0.0.1 --tcp-timeout 1 --tcp-leg "$TP:5" --tcp-leg "$((TP + 1)):5" 2>/dev/null | grep '^SENT')
		wait "$A0_ACC" 2>/dev/null || true
		acc=$(grep -E '^ACCEPTED [0-9]+$' "$A0_DIR/acc.out" | tail -1)
		accn=$(awk '{print $2}' <<<"$acc")
		cell "SENT tcplegs=$TP=5,$((TP + 1))=5" "established AND refused connects both count as offered" "$tsent"
		cell 5 "the acceptor completed every offered handshake" "${accn:-none}"
	fi
	rm -rf "$A0_DIR"
fi

# ── Part A1: reductions over the committed real captures ─────────────
echo "=== A1: capture reductions over committed real tcpdump transcripts ==="

cell 0 "drop-direction capture counts ZERO probe frames" \
	"$(wire_count_dst_frames "$FIXDIR/capture-udp-dropped.txt" 54901)"
cell 30 "drop-direction capture counts the control frames" \
	"$(wire_count_dst_frames "$FIXDIR/capture-udp-dropped.txt" 54902)"
cell 0 "drop-direction capture has no corruption" \
	"$(wire_count_bad_cksum "$FIXDIR/capture-udp-dropped.txt" 'udp|ip')"
cell 20 "leak-direction capture counts the leaked probe frames" \
	"$(wire_count_dst_frames "$FIXDIR/capture-udp-leaked.txt" 54901)"
cell 20 "leak-direction capture counts the control frames" \
	"$(wire_count_dst_frames "$FIXDIR/capture-udp-leaked.txt" 54902)"
cell 25 "corruption annotations count under the UDP gate's alternation" \
	"$(wire_count_bad_cksum "$FIXDIR/capture-udp-badcksum.txt" 'udp|ip')"
cell 15 "deny-direction capture counts netconf SYN-ACK replies" \
	"$(wire_count_flag_replies "$FIXDIR/capture-tcp-replies-deny.txt" 830 'S\.')"
cell 0 "deny-direction capture counts ZERO ssh completed handshakes" \
	"$(wire_count_flag_replies "$FIXDIR/capture-tcp-replies-deny.txt" 22 'S\.')"
cell 0 "deny-direction capture counts ZERO https refusals" \
	"$(wire_count_flag_replies "$FIXDIR/capture-tcp-replies-deny.txt" 443 'R')"
cell 15 "deny-direction capture still SAW the offered ssh SYNs" \
	"$(wire_count_dst_frames "$FIXDIR/capture-tcp-replies-deny.txt" 22)"
cell 15 "exposed-direction capture counts ssh SYN-ACK replies" \
	"$(wire_count_flag_replies "$FIXDIR/capture-tcp-replies-exposed.txt" 22 'S\.')"
cell 15 "exposed-direction capture counts https RST refusals" \
	"$(wire_count_flag_replies "$FIXDIR/capture-tcp-replies-exposed.txt" 443 'R')"
cell 12 "twins capture counts tcp/80 frames" \
	"$(wire_count_dst_frames "$FIXDIR/capture-twins-narrowed.txt" 80)"
cell 12 "twins capture counts udp/53 frames" \
	"$(wire_count_dst_frames "$FIXDIR/capture-twins-narrowed.txt" 53)"
cell 0 "twins capture counts ZERO tcp/8080 frames (narrowed)" \
	"$(wire_count_dst_frames "$FIXDIR/capture-twins-narrowed.txt" 8080)"
cell 0 "twins capture counts ZERO udp/5353 frames (narrowed)" \
	"$(wire_count_dst_frames "$FIXDIR/capture-twins-narrowed.txt" 5353)"
cell 12 "widened capture counts the leaked tcp/8080 twin" \
	"$(wire_count_dst_frames "$FIXDIR/capture-twins-widened.txt" 8080)"
cell 12 "widened capture counts the leaked udp/5353 twin" \
	"$(wire_count_dst_frames "$FIXDIR/capture-twins-widened.txt" 5353)"

# ── Part A2: the reductions reject near-misses ────────────────────────
echo "=== A2: near-miss rejection ==="
cell 0 "a PREFIX of the probe port matches nothing (5490)" \
	"$(wire_count_dst_frames "$FIXDIR/capture-udp-leaked.txt" 5490)"
cell 0 "an EXTENSION of the probe port matches nothing (549011)" \
	"$(wire_count_dst_frames "$FIXDIR/capture-udp-leaked.txt" 549011)"
cell 0 "replies FROM the netconf port are not frames TO it" \
	"$(wire_count_dst_frames "$FIXDIR/capture-tcp-replies-deny.txt" 830)"
cell 0 "the prober's outbound SYN is not a reply from the service port" \
	"$(wire_count_flag_replies "$FIXDIR/capture-tcp-replies-deny.txt" 22 'S')"
cell 0 "UDP corruption does not count under the TCP gate's alternation" \
	"$(wire_count_bad_cksum "$FIXDIR/capture-udp-badcksum.txt" 'tcp|ip')"
cell 0 "a missing capture file reduces to zero, not garbage" \
	"$(wire_count_dst_frames "$FIXDIR/no-such-file.txt" 80)"

# ── Part A3: the gates' --fixture modes over the real transcripts ─────
echo "=== A3: gate --fixture modes over measured transcripts ==="
fixture_cell() { # fixture_cell <gate-script> <transcript> <want-verdict> <want-rc>
	local out rc v
	out=$("$SCRIPT_DIR/$1" --fixture "$FIXDIR/$2" 2>&1)
	rc=$?
	v=$(awk '{print $3}' <<<"$out")
	if [[ "$v" == "$3" && "$rc" == "$4" ]]; then
		echo "  PASS  $2 -> $3 (rc $rc)"
		PASS=$((PASS + 1))
	else
		echo "  FAIL  $2 -> want $3/rc$4, got '$v'/rc$rc: $out"
		FAIL=$((FAIL + 1))
	fi
}
fixture_cell wire-policy-deny.sh policy-deny-pass.tsv PASS 0
fixture_cell wire-policy-deny.sh policy-deny-leak.tsv FAIL 1
fixture_cell wire-policy-deny.sh policy-deny-capture-blind.tsv VOID 2
fixture_cell wire-appmatch-twins.sh twins-pass.tsv PASS 0
fixture_cell wire-appmatch-twins.sh twins-widen.tsv FAIL 1
fixture_cell wire-hostinbound-deny.sh hostinbound-pass.tsv PASS 0
fixture_cell wire-hostinbound-deny.sh hostinbound-exposed.tsv FAIL 1

# ── Part A4: floors bind on real captures ─────────────────────────────
echo "=== A4: the §2 floors refuse thin real captures ==="
{
	pl=$(wire_count_dst_frames "$FIXDIR/capture-udp-dropped.txt" 54901)
	co=$(wire_count_dst_frames "$FIXDIR/capture-udp-dropped.txt" 54902)
	ck=$(wire_count_bad_cksum "$FIXDIR/capture-udp-dropped.txt" 'udp|ip')
} 2>/dev/null
out="$(wire_deny_verdict "$co" "$pl" "$co" "$co" "$ck")"
rc=$?
cell VOID "an exact healthy excerpt of 30 frames is VOID, never PASS" "$(awk '{print $3}' <<<"$out")"
cell 2 "…and its rc is VOID (2), not PASS (0)" "$rc"

echo "  wire-gate-hermetic selftest part A: $PASS passed, $FAIL failed, $SKIP skipped"

# ── Part B: live netns pipeline (privileged) ───────────────────────────
run_live=0
live_reason=""
if [[ "$LIVE" == "no" ]]; then
	live_reason="--no-live requested"
elif [[ "$LIVE" == "only" ]]; then
	run_live=1
elif [[ "$(id -u)" != 0 ]]; then
	live_reason="not root (needs netns + tcpdump + nft + ethtool)"
elif ! command -v nft >/dev/null 2>&1; then
	live_reason="nft not installed"
elif ! command -v tcpdump >/dev/null 2>&1; then
	live_reason="tcpdump not installed"
elif [[ ! -x /usr/sbin/ethtool && ! -x /sbin/ethtool ]] && ! command -v ethtool >/dev/null 2>&1; then
	live_reason="ethtool not installed"
else
	run_live=1
fi

if [[ "$run_live" != 1 ]]; then
	echo "=== B: live netns pipeline SKIPPED ==="
	skip_cell "live netns pipeline (real probes, real drop, real capture): $live_reason"
else
	echo "=== B: live netns pipeline (real probes, real drop, real capture) ==="
	B_DIR="$(mktemp -d "${TMPDIR:-/var/worktrees/.cache/tmpdir}/xpf-wire-hermetic.XXXXXX")"
	trap 'wire_hermetic_teardown; rm -rf "$B_DIR"' EXIT

	wire_hermetic_netns() {
		ip netns del wghA 2>/dev/null || true
		ip netns del wghR 2>/dev/null || true
		ip netns del wghB 2>/dev/null || true
		ip link del wghA0 2>/dev/null || true
		ip link del wghB0 2>/dev/null || true
		ip netns add wghA; ip netns add wghR; ip netns add wghB
		ip link add wghA0 type veth peer name wghA1
		ip link add wghB0 type veth peer name wghB1
		ip link set wghA0 netns wghA; ip link set wghA1 netns wghR
		ip link set wghB0 netns wghB; ip link set wghB1 netns wghR
		ip -n wghA addr add 10.9.0.1/24 dev wghA0; ip -n wghA link set wghA0 up; ip -n wghA link set lo up
		ip -n wghR addr add 10.9.0.254/24 dev wghA1; ip -n wghR link set wghA1 up
		ip -n wghR addr add 10.9.1.254/24 dev wghB1; ip -n wghR link set wghB1 up; ip -n wghR link set lo up
		ip -n wghB addr add 10.9.1.2/24 dev wghB0; ip -n wghB link set wghB0 up; ip -n wghB link set lo up
		ip -n wghA route add default via 10.9.0.254
		ip -n wghB route add default via 10.9.1.254
		ip netns exec wghR sysctl -qw net.ipv4.ip_forward=1
		ip netns exec wghR nft add table inet wgate
		ip netns exec wghR nft add chain inet wgate d '{ type filter hook forward priority 0; policy accept; }'
		# The DUT stand-in computes real checksums (veth offload would fake
		# `[bad udp cksum]` annotations the real DUT never produces).
		local et
		et="$(command -v ethtool || echo /usr/sbin/ethtool)"
		ip netns exec wghA "$et" -K wghA0 rx off tx off >/dev/null 2>&1 || true
		ip netns exec wghB "$et" -K wghB0 rx off tx off >/dev/null 2>&1 || true
	}
	wire_hermetic_drop() { ip netns exec wghR nft add rule inet wgate d "$1" drop; }
	wire_hermetic_nodrop() { ip netns exec wghR nft flush chain inet wgate d; }
	wire_hermetic_teardown() {
		pkill -f 'tcpdump -i wgh' 2>/dev/null || true
		ip netns del wghA 2>/dev/null || true
		ip netns del wghR 2>/dev/null || true
		ip netns del wghB 2>/dev/null || true
	}
	wire_hermetic_cap() { # <netns> <iface> <name> <flag-set...> -- <filter...>
		local ns="$1" ifc="$2" name="$3"
		shift 3
		local -a flags=()
		while [[ "${1:-}" != "--" ]]; do flags+=("$1"); shift; done
		shift
		ip netns exec "$ns" timeout 120 tcpdump -i "$ifc" "${flags[@]}" -U -c 40000 "$*" >"$B_DIR/$name" 2>&1 &
		B_CAP_PID=$!
		sleep 2
	}
	wire_hermetic_capend() {
		pkill -f "tcpdump -i $2 " 2>/dev/null || true
		kill "$B_CAP_PID" 2>/dev/null || true
		wait "$B_CAP_PID" 2>/dev/null || true
		sleep 1
	}
	# wire_hermetic_sent <run-output> — offered sum of ONE probe/control-mode
	# SENT line. The gate sends each leg as one run with --probe-port and
	# --control-port set to the SAME port (the #9531 invocation shape), so the
	# offered count for the leg is probe+control from that line.
	wire_hermetic_sent() {
		local pp pc
		pp=$(sed -E 's/.*probe=([0-9]+).*/\1/;t;d' <<<"$1")
		pc=$(sed -E 's/.*control=([0-9]+).*/\1/;t;d' <<<"$1")
		printf '%s' "$((10#$pp + 10#$pc))"
	}

	if ! wire_hermetic_netns; then
		echo "  FAIL  netns topology could not be created"
		FAIL=$((FAIL + 1))
	else
		PASS=$((PASS + 1))
		echo "  PASS  isolated netns topology up (prober -> nft drop -> sink)"

		# B1: wire_policy_deny drop direction (PASS) — floor-sized bursts.
		wire_hermetic_drop 'udp dport 54901'
		wire_hermetic_cap wghB wghB0 pd.pass -n -vv -- udp and dst host 10.9.1.2 and '(' dst port 54901 or dst port 54902 ')'
		o1=$(ip netns exec wghA python3 "$PROBE" --dst 10.9.1.2 --probe-port 54901 --control-port 54901 --count 500 --rate 200 2>/dev/null | grep '^SENT')
		o2=$(ip netns exec wghA python3 "$PROBE" --dst 10.9.1.2 --probe-port 54902 --control-port 54902 --count 750 --rate 200 2>/dev/null | grep '^SENT')
		wire_hermetic_capend wghB wghB0
		wire_hermetic_nodrop
		po=$(( $(wire_hermetic_sent "$o1") ))
		co=$(( $(wire_hermetic_sent "$o2") ))
		pl=$(wire_count_dst_frames "$B_DIR/pd.pass" 54901)
		cb=$(wire_count_dst_frames "$B_DIR/pd.pass" 54902)
		ck=$(wire_count_bad_cksum "$B_DIR/pd.pass" 'udp|ip')
		echo "  B1 offered probe=$po control=$co | leaked=$pl control=$cb cksum=$ck"
		out="$(wire_deny_verdict "$po" "$pl" "$co" "$cb" "$ck")"
		rc=$?
		cell PASS "live drop direction: probe 0 leaked, control at floor -> PASS" "$(awk '{print $3}' <<<"$out")"
		cell 0 "…and its rc is 0" "$rc"

		# B2: wire_policy_deny leak direction (FAIL) — nothing dropped.
		wire_hermetic_cap wghB wghB0 pd.leak -n -vv -- udp and dst host 10.9.1.2 and '(' dst port 54901 or dst port 54902 ')'
		o1=$(ip netns exec wghA python3 "$PROBE" --dst 10.9.1.2 --probe-port 54901 --control-port 54901 --count 500 --rate 200 2>/dev/null | grep '^SENT')
		o2=$(ip netns exec wghA python3 "$PROBE" --dst 10.9.1.2 --probe-port 54902 --control-port 54902 --count 750 --rate 200 2>/dev/null | grep '^SENT')
		wire_hermetic_capend wghB wghB0
		po=$(( $(wire_hermetic_sent "$o1") ))
		co=$(( $(wire_hermetic_sent "$o2") ))
		pl=$(wire_count_dst_frames "$B_DIR/pd.leak" 54901)
		cb=$(wire_count_dst_frames "$B_DIR/pd.leak" 54902)
		ck=$(wire_count_bad_cksum "$B_DIR/pd.leak" 'udp|ip')
		echo "  B2 offered probe=$po control=$co | leaked=$pl control=$cb cksum=$ck"
		out="$(wire_deny_verdict "$po" "$pl" "$co" "$cb" "$ck")"
		rc=$?
		cell FAIL "live leak direction: probe frames really emerge -> FAIL" "$(awk '{print $3}' <<<"$out")"
		cell 1 "…and its rc is 1" "$rc"

		# B3: wire_hostinbound_deny deny direction (PASS) — 22/443 dropped,
		# netconf 830 admitted by a sink listener.
		wire_hermetic_drop 'tcp dport 22'
		wire_hermetic_drop 'tcp dport 443'
		ip netns exec wghB sh -c "nohup python3 $ACCEPT --port 830 --duration 120 >/dev/null 2>&1 &"
		sleep 2
		wire_hermetic_cap wghA wghA0 hi.pass -nn -tt -vv -s 0 -- host 10.9.1.2 and '(' tcp port 22 or tcp port 443 or tcp port 830 ')'
		ip netns exec wghA python3 "$PROBE" --dst 10.9.1.2 --tcp-timeout 0.2 --tcp-leg 22:1000 --tcp-leg 443:1000 --tcp-leg 830:1500 >/dev/null 2>&1
		wire_hermetic_capend wghA wghA0
		wire_hermetic_nodrop
		ca=$(wire_count_flag_replies "$B_DIR/hi.pass" 22 'S\.'); ra=$(wire_count_flag_replies "$B_DIR/hi.pass" 22 'R')
		cb2=$(wire_count_flag_replies "$B_DIR/hi.pass" 443 'S\.'); rb=$(wire_count_flag_replies "$B_DIR/hi.pass" 443 'R')
		cc=$(wire_count_flag_replies "$B_DIR/hi.pass" 830 'S\.'); rc2=$(wire_count_flag_replies "$B_DIR/hi.pass" 830 'R')
		ck=$(wire_count_bad_cksum "$B_DIR/hi.pass" 'tcp|ip')
		rf=$((ca + ra + cb2 + rb))
		cobs=$((cc + rc2))
		echo "  B3 replies 22=$ca/$ra 443=$cb2/$rb 830=$cc/$rc2 cksum=$ck"
		out="$(wire_hostinbound_verdict "$rf" 1500 "$cobs" "$ck" 2 1000 "$ca" "$ra" 1000 "$cb2" "$rb")"
		rc=$?
		cell PASS "live deny direction: zero probe replies, netconf control at floor -> PASS" "$(awk '{print $3}' <<<"$out")"
		cell 0 "…and its rc is 0" "$rc"

		# B4: wire_appmatch_twins narrowed direction (PASS) — 80/53 emerge,
		# 8080/5353 dropped, tcp/80 sink listener so handshakes complete.
		wire_hermetic_drop 'tcp dport 8080'
		wire_hermetic_drop 'udp dport 5353'
		ip netns exec wghB sh -c "nohup python3 $ACCEPT --port 80 --duration 120 >/dev/null 2>&1 &"
		sleep 2
		wire_hermetic_cap wghB wghB0 tw.pass -n -vv -- '(' tcp or udp ')' and dst host 10.9.1.2 and '(' dst port 80 or dst port 8080 or dst port 53 or dst port 5353 ')'
		ip netns exec wghA python3 "$PROBE" --dst 10.9.1.2 --tcp-timeout 0.2 --tcp-leg 80:1500 --tcp-leg 8080:1000 --leg 53:1500 --leg 5353:1000 --rate 200 >/dev/null 2>&1
		wire_hermetic_capend wghB wghB0
		wire_hermetic_teardown
		t80b=$(wire_count_dst_frames "$B_DIR/tw.pass" 80)
		t88b=$(wire_count_dst_frames "$B_DIR/tw.pass" 8080)
		u53b=$(wire_count_dst_frames "$B_DIR/tw.pass" 53)
		u35b=$(wire_count_dst_frames "$B_DIR/tw.pass" 5353)
		ck=$(wire_count_bad_cksum "$B_DIR/tw.pass" 'udp|ip|tcp')
		echo "  B4 observed 80=$t80b 8080=$t88b 53=$u53b 5353=$u35b cksum=$ck"
		out="$(wire_twins_verdict 1500 "$t80b" 1000 "$t88b" 1500 "$u53b" 1000 "$u35b" "$ck")"
		rc=$?
		cell PASS "live twins direction: permit twins emerge, deny twins zero -> PASS" "$(awk '{print $3}' <<<"$out")"
		cell 0 "…and its rc is 0" "$rc"
	fi
fi

echo "  wire-gate-hermetic selftest: $PASS passed, $FAIL failed, $SKIP skipped"
if ((FAIL > 0)); then
	exit 1
fi
if ((PASS == 0)); then
	echo "FAIL: zero cells ran" >&2
	exit 77
fi
exit 0
