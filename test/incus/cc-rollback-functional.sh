#!/usr/bin/env bash
# #1922 Item 1a live functional gate: a SERVICE-MODE (gRPC) commit
# confirmed that is NOT confirmed must auto-revert the running config AND
# re-apply it to the dataplane.
#
# Arm A (delete-allow-all): the confirmed change BLOCKS lan->wan forwarding
# (default-policy is deny-all), asserting forwarding is restored AFTER the
# timeout rollback. A store-only revert would leave the dataplane blocking,
# which is exactly the #1922 bug in the delete direction.
#
# Arm B (#9531 mirror): an unconfirmed commit ADDS a narrow lan->wan permit;
# mid-window the probe flow must FORWARD with a witnessed session, and after
# the timeout the permit must be GONE from the store, the flow BLOCKED, and
# the session evicted. A store-only revert leaves the dataplane still
# enforcing the unconfirmed permit (policy ABSENT + forwarding OK + session
# lingering) — the timer-driven withdrawal direction Arm A never exercises.
#
# Usage: cc-rollback-functional.sh [--arm a|b|both|b-enforced]  (default: both)
# Each arm prints exactly one WIRE_GATE cc-rollback-arm-<a|b> line; run each
# arm under its own `harness-result.sh run` wrapper invocation (one row per
# run), never both arms under one wrapper. b-enforced is the Arm B NEGATIVE
# CONTROL: identical steps but a plain (non-reverting) commit, so the permit
# MUST survive — expect FAIL. It proves the arm reddens when a permit
# survives the timeout (observation-path evidence, not a store/dataplane
# divergence reproduction, which needs product hooks).
#
# Runs against loss:xpf-userspace-fw0. Invoke inside the cluster lock cell.
set -uo pipefail

NODE="${NODE:-loss:xpf-userspace-fw0}"
HOST="${HOST:-loss:cluster-userspace-host}"   # lan-side container, 10.0.61.102
TARGET="${TARGET:-172.16.80.200}"        # wan-side ping target
SG="sg incus-admin -c"

run_cli() { $SG "incus exec $NODE -- bash -lc 'cli'" 2>&1; }
host_ping() { $SG "incus exec $HOST -- ping -c2 -W2 $TARGET" >/dev/null 2>&1; }
policy_present() {
	printf 'show configuration security policies from-zone lan to-zone wan\n' | run_cli | grep -q 'policy allow-all'
}

ARM="both"
for arg in "$@"; do
	case "$arg" in
	--arm) ;;
	a | b | both | b-enforced) ARM="$arg" ;;
	--arm=*) ARM="${arg#--arm=}" ;;
	-h | --help)
		sed -n '1,29p' "$0"
		exit 0
		;;
	*)
		echo "unknown argument: $arg (usage: $0 [--arm a|b|both|b-enforced])" >&2
		exit 2
		;;
	esac
done
case "$ARM" in
a | b | both | b-enforced) ;;
*)
	echo "bad --arm value: $ARM (want a|b|both|b-enforced)" >&2
	exit 2
	;;
esac

# Destructive lock cell (#1875): both arms commit config. Taken here (not by
# the caller) like the wire gates, after arg parsing so --help stays local.
_CELL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/incus/cluster-cell.sh
source "${_CELL_DIR}/cluster-cell.sh"
xpf_enter_destructive_cluster_cell "cc-rollback-functional --arm $ARM" "$0" "$@"
# ── Arm B diagnostic-preserving helpers (#9531 §5d) ──────────────────
# The Arm-A oracles (host_ping discards diagnostics; policy_present reads
# absence from failed reads) are kept byte-identical for Arm A and NOT reused
# for Arm B. Each helper below classifies BLIND explicitly; a BLIND read is a
# VOID for its assertion, never a pass contribution.
B_HOST="${B_HOST:-$HOST}"
B_SINK="${B_SINK:-172.16.80.201}"
B_SINK_REF="${B_SINK_REF:-loss:xpf-mouse-target}"
B_PORT="${B_PORT:-54911}"
B_SRC_PORT="${B_SRC_PORT:-54913}"
B_POL="armb-9531-permit"
B_APP="armb-9531-probe"
# LAN host address for session-query context (this script does not source
# cluster-env.sh; the value matches loss-userspace-cluster.env LAN_HOST_IP).
LAN_HOST_IP="${LAN_HOST_IP:-10.0.61.102}"
# run_cli_t — like run_cli but with a LOCAL timeout bound (GPT-3). Every
# remote step already has a remote `timeout(1)`; that bounds nothing when
# `incus exec` itself stalls locally (DNS outage, hung daemon socket). Arm B
# reads use this; Arm A's oracles stay on run_cli byte-identical (§6).
run_cli_t() { timeout 90 $SG "incus exec $NODE -- bash -lc 'cli'" 2>&1; }
# app_read <name> — application-marker reads over `show security
# applications <name>` (the store-backed surface; `show configuration
# applications` is NOT a valid path — live: "configuration path not found").
# Prints PRESENT|ABSENT|UNREADABLE. rc!=0 ⇒ UNREADABLE; rc==0 with an
# `Application: <name>` detail line ⇒ PRESENT, else ABSENT (empty output is
# this surface's legit absent shape).
app_read() {
	local out rc
	out=$(printf 'show security applications %s\nexit\n' "$1" | run_cli_t)
	rc=$?
	if ((rc != 0)); then
		echo "UNREADABLE"
		return 0
	fi
	if grep -q "Application: $1$" <<<"$out"; then
		echo "PRESENT"
	else
		echo "ABSENT"
	fi
}
# sink_ready — is B_PORT listening on the sink right now? A loopback connect
# from the sink itself traverses no firewall, creates no DUT session, and
# proves the listener the next probe depends on is actually up. Prints
# READY|DOWN. Local-bound; DOWN is an apparatus verdict, never a forwarding
# one. Called by b_listen/b_hold after launch AND by probe_fwd before
# connecting, so a refused connect against a verified-ready listener reads
# BLIND (listener died mid-poll), not BLOCKED.
sink_ready() {
	if timeout 15 $SG "incus exec $B_SINK_REF -- python3 -c 'import socket; s=socket.create_connection((\"127.0.0.1\", $B_PORT), timeout=5); s.close()'" >/dev/null 2>&1; then
		echo "READY"
	else
		echo "DOWN"
	fi
}

# policy_read <pattern> — VALID (rc 0 + stanza anchor present) reads only.
# Prints PRESENT|ABSENT|UNREADABLE, exactly one word.
policy_read() {
	local out rc
	out=$(printf 'show configuration security policies from-zone lan to-zone wan | display set\nexit\n' | run_cli_t)
	rc=$?
	if ((rc != 0)) || [[ -z "$out" ]]; then
		echo "UNREADABLE"
		return 0
	fi
	if ! grep -q "security policies from-zone lan to-zone wan" <<<"$out"; then
		echo "UNREADABLE"
		return 0
	fi
	if grep -q "$1" <<<"$out"; then
		echo "PRESENT"
	else
		echo "ABSENT"
	fi
}

# probe_fwd — TCP connect from the lan host to the wan listener, bound to a
# FIXED source port so the session witness can query the exact 5-tuple.
# Two-stage observation (GPT-3): the probe prints CONNECTED once the
# handshake completes and ESTABLISHED/EMPTY after the exchange, so a connect
# timeout (SYNs dropped = policy verdict) is never conflated with an
# exchange stall (app-level, listener verified ready independently).
# Prints OK (established) | BLOCKED (SYNs unanswered: CONNECT_TIMEOUT) |
# UNREACHABLE (route never reached a policy decision) | BLIND (exec failure,
# refused against a verified-ready listener, exchange stall, unparseable) |
# TIMEOUT (any timeout(1) bound fired, local or remote — with 20 s socket
# timeouts no legitimate forwarding observation takes 40 s+, so 124 is
# always an apparatus timeout, never a policy drop).
probe_fwd() {
	local out rc ready
	if ! timeout 30 $SG "incus exec $B_HOST -- sh -c 'command -v python3'" >/dev/null 2>&1; then
		echo "BLIND"
		return 0
	fi
	# Every Arm B poll runs under a listener (baseline b_listen, mid per-try
	# b_listen, post b_hold, restore re-probe b_listen), so a DOWN listener
	# means the apparatus is broken — fail fast BLIND instead of burning 20+
	# s on a probe whose refused/timeout outcome could not be read anyway.
	ready="$(sink_ready)"
	if [[ "$ready" != "READY" ]]; then
		echo "BLIND"
		return 0
	fi
	out=$(timeout 90 $SG "incus exec $B_HOST -- timeout 40 python3 -c 'import socket,time
s=socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
for _ in range(6):
    try:
        s.bind((\"\", $B_SRC_PORT))
        break
    except OSError:
        time.sleep(1)
s.settimeout(20)
try:
    s.connect((\"$B_SINK\", $B_PORT))
except TimeoutError:
    print(\"CONNECT_TIMEOUT\", flush=True)
    raise
print(\"CONNECTED\", flush=True)
s.sendall(b\"ping\")
d=s.recv(4)
s.close()
print(\"ESTABLISHED\" if d else \"EMPTY\")'" 2>&1)
	rc=$?
	if ((rc == 124)); then
		echo "TIMEOUT"
		return 0
	fi
	if grep -qiE "unreachable|no route|network is" <<<"$out"; then
		echo "UNREACHABLE"
		return 0
	fi
	if grep -q "ESTABLISHED" <<<"$out"; then
		echo "OK"
		return 0
	fi
	if grep -q "EMPTY" <<<"$out"; then
		echo "OK"
		return 0
	fi
	if grep -q "CONNECT_TIMEOUT" <<<"$out"; then
		echo "BLOCKED"
		return 0
	fi
	if grep -q "CONNECTED" <<<"$out"; then
		echo "BLIND"
		return 0
	fi
	echo "BLIND"
}

# session_list <src_ip> <src_port> <dst_ip> <dst_port> — destination-scoped
# query with a raised limit on both nodes. Prints the raw listing; callers
# check the `Total sessions:` structural marker (absent ⇒ UNREADABLE).
# NOTE: matching is destination-centered, never source-anchored. The DUT
# source-NATs lan->wan, so the listing's source tuple is post-NAT and a
# pre-NAT source match would blind the witness.
session_list() {
	printf 'show security flow session destination-prefix %s destination-port %s limit 10000\nexit\n' "$3" "$4" | run_cli_t
}

# sess_poll <src_ip> <src_port> <dst_ip> <dst_port> — bounded session query
# (GPT-4): a single listing right after traffic races session install, so
# poll the READ (not the verdict) briefly. Prints the listing; rc 0 iff the
# `Total sessions:` structural marker is present.
sess_poll() {
	local i out
	for ((i = 1; i <= 3; i++)); do
		out="$(session_list "$1" "$2" "$3" "$4")"
		if grep -q "Total sessions:" <<<"$out"; then
			printf '%s' "$out"
			return 0
		fi
		echo "session listing unreadable (try $i/3)" >&2
		sleep 5
	done
	return 1
}

# sess_count <listing> <dst_ip> <dst_port> — entries mentioning the probe
# destination (either direction). Headers carry no IPs, so every hit is a
# session line.
sess_count() {
	local n
	n=$(grep -cE "$2.*$3|$3.*$2" <<<"$1" 2>/dev/null || true)
	n=$(printf '%s' "$n" | tr -d ' \n' || true)
	[[ "$n" =~ ^[0-9]+$ ]] || n=0
	printf '%s' "$n"
}

# sess_sids <listing> <dst_ip> <dst_port> — prints "sid timeout" per entry
# whose In-line names the probe destination (GPT-4 witness tie). The listing
# renders one entry as a `Session ID:` line followed by `In:`/`Out:` lines,
# so associate by adjacency, not by global grep: a bare Timeout grep would
# attribute another session's lifetime to the probe.
sess_sids() {
	awk -v dst="$2" -v port="$3" '
		/Session ID: [0-9]+/ {
			sid = ""
			tmo = ""
			if (match($0, /Session ID: [0-9]+/)) sid = substr($0, RSTART + 12, RLENGTH - 12)
			if (match($0, /Timeout: [0-9]+/)) tmo = substr($0, RSTART + 9, RLENGTH - 9)
		}
		/^  In: / {
			if (index($0, dst) > 0 && index($0, port) > 0) print sid, tmo
		}' <<<"$1"
}

ARM_A_RC=0
ARM_B_RC=0
if [[ "$ARM" == "a" || "$ARM" == "both" ]]; then
echo "=== #1922 Item 1a commit-confirmed timeout rollback functional gate (Arm A) ==="
echo "node=$NODE host=$HOST target=$TARGET"

echo "--- baseline ---"
if policy_present; then echo "baseline policy allow-all: PRESENT"; else echo "baseline policy allow-all: MISSING (precondition)"; exit 3; fi
if host_ping; then echo "baseline forwarding lan->wan: OK"; else echo "baseline forwarding lan->wan: FAIL (precondition)"; exit 3; fi

echo "--- service-mode: delete allow-all, commit confirmed 1 (NOT confirming) ---"
printf 'configure\ndelete security policies from-zone lan to-zone wan policy allow-all\nshow | compare\ncommit confirmed 1\nexit\n' | run_cli | tail -12

sleep 5
echo "--- mid-window ---"
if policy_present; then MID_POL=PRESENT; else MID_POL=GONE; fi
echo "mid policy allow-all: $MID_POL"
if host_ping; then MID_FWD=OK; else MID_FWD=BLOCKED; fi
echo "mid forwarding lan->wan: $MID_FWD"

echo "--- waiting for 1-min commit-confirmed timeout (no confirm) ---"
sleep 80

echo "--- post-timeout ---"
if policy_present; then POST_POL=PRESENT; else POST_POL=GONE; fi
echo "post policy allow-all: $POST_POL"
POST_FWD=BLOCKED
for i in 1 2 3 4 5 6 7 8; do
	if host_ping; then POST_FWD=OK; break; fi
	sleep 3
done
echo "post forwarding lan->wan: $POST_FWD"

echo "=== VERDICT (Arm A) ==="
fail=0
[ "$MID_FWD" = "BLOCKED" ] && echo "PASS: change applied mid-window (forwarding blocked)" || { echo "FAIL: change did not apply mid-window"; fail=1; }
[ "$POST_POL" = "PRESENT" ] && echo "PASS: store reverted (allow-all policy back)" || { echo "FAIL: store NOT reverted"; fail=1; }
[ "$POST_FWD" = "OK" ] && echo "PASS: dataplane re-applied (forwarding restored)" || { echo "FAIL: forwarding still blocked (dataplane NOT re-applied = the #1922 bug)"; fail=1; }
# 0/1 flags for the arm-a ledger envelope (mid_blocked post_present post_fwd_ok).
[ "$MID_FWD" = "BLOCKED" ] && A_MID=1 || A_MID=0
[ "$POST_POL" = "PRESENT" ] && A_POST=1 || A_POST=0
[ "$POST_FWD" = "OK" ] && A_FWD=1 || A_FWD=0
if [[ "$fail" == "0" ]]; then
	printf 'WIRE_GATE cc-rollback-arm-a PASS reason=-- mid_blocked=%s post_present=%s post_fwd_ok=%s\n' "$A_MID" "$A_POST" "$A_FWD"
else
	printf 'WIRE_GATE cc-rollback-arm-a FAIL reason=-- mid_blocked=%s post_present=%s post_fwd_ok=%s\n' "$A_MID" "$A_POST" "$A_FWD"
fi
ARM_A_RC=$fail
fi

if [[ "$ARM" == "b" || "$ARM" == "both" || "$ARM" == "b-enforced" ]]; then
echo "=== #1922 mirror arm (Arm B): unconfirmed ADD must revert from the dataplane ==="
B_ENFORCED=0
if [[ "$ARM" == "b-enforced" ]]; then
	B_ENFORCED=1
	echo "=== NEGATIVE CONTROL: plain commit (no revert timer) — the permit MUST survive; expect FAIL ==="
	echo "Caveat: no auto-revert — SIGKILL mid-window LEAKS the permit; the postlude covers graceful exits only."
fi
# poll_fwd <want> <tries> — poll probe_fwd until it reads <want> (OK or
# BLOCKED). A single probe right after a commit races dataplane convergence
# (commit→snapshot→publish→helper install). BLIND/UNREACHABLE/TIMEOUT
# readings abort immediately (the path is unobservable or the apparatus
# timed out — not slow). Prints the final reading; returns 0 iff it equals
# <want>. Callers map TIMEOUT to VOID row-timeout (never to a forwarding
# verdict).
poll_fwd() {
	local want="$1" tries="$2" got="" i
	for ((i = 1; i <= tries; i++)); do
		if [[ "$want" == "OK" ]]; then
			b_listen 60
		fi
		got="$(probe_fwd)"
		if [[ "$want" == "OK" ]]; then
			b_unlisten
		fi
		echo "poll_fwd $want: try $i/$tries -> $got" >&2
		if [[ "$got" == "$want" ]]; then
			printf '%s' "$got"
			return 0
		fi
		if [[ "$got" == "BLIND" || "$got" == "UNREACHABLE" || "$got" == "TIMEOUT" ]]; then
			printf '%s' "$got"
			return 1
		fi
		sleep 5
	done
	printf '%s' "$got"
	[[ "$got" == "$want" ]]
}
b_listen() { # b_listen <seconds>
	# Self-contained bind (GLM-M3): a previous try's remote listener (local
	# wrapper reaped, remote `timeout` still running) holds the port, so a
	# bare bind EADDRINUSEs and the try probes against no listener. pkill
	# our marker, retry the bind like b_hold, then verify readiness — a
	# refused probe against a verified-ready listener reads BLIND
	# (apparatus), never BLOCKED. Local bound = remote + 60.
	timeout 30 $SG "incus exec $B_SINK_REF -- pkill -f xpf-armb-listen 2>/dev/null" >/dev/null 2>&1 || true
	sleep 1
	timeout $(( $1 + 60 )) $SG "incus exec $B_SINK_REF -- timeout $1 python3 -c '# xpf-armb-listen
import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1);
import time
for _ in range(6):
 try:
  s.bind((\"0.0.0.0\", $B_PORT)); break
 except OSError: time.sleep(2)
s.listen(5); s.settimeout($1);
end=time.time()+$1-1
while time.time()<end:
 try:
  c,a=s.accept(); c.settimeout(5); d=c.recv(64); c.sendall(b\"ok\"); c.close()
 except Exception: pass'" >/dev/null 2>&1 &
	LISTEN_PID=$!
	sleep 2
	if [[ "$(sink_ready)" != "READY" ]]; then
		echo "b_listen: listener not READY after launch (probes will read BLIND)" >&2
	fi
}
b_unlisten() {
	kill "$LISTEN_PID" 2>/dev/null || true
	wait "$LISTEN_PID" 2>/dev/null || true
}
# b_hold <seconds> — wan listener that holds every accepted connection open
# (echoing heartbeats) for the window. Thread-per-connection: the mid holder
# AND the post-timeout fresh probe share the port, and a single-connection
# listener would leave the fresh probe's exchange unanswered (its recv
# timeout reads BLOCKED — live: enforced run showed policy PRESENT yet
# forwarding BLOCKED, an app-level artifact, not a dataplane drop). Same
# port as b_listen: callers pkill xpf-armb-listen first. Backgrounded;
# reaped in b_postlude.
b_hold() {
	timeout $(( $1 + 60 )) $SG "incus exec $B_SINK_REF -- timeout $1 python3 -c '# xpf-armb-hold
import socket,time,threading
def serve(c):
 try:
  while True:
   d=c.recv(64)
   if not d: break
   c.sendall(b\"ok\")
 except Exception: pass
 try: c.close()
 except Exception: pass
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
for _ in range(6):
 try:
  s.bind((\"0.0.0.0\", $B_PORT)); break
 except OSError: time.sleep(2)
s.listen(5); s.settimeout(5)
end=time.time()+$1-1
while time.time()<end:
 try: c,a=s.accept()
 except Exception: continue
 threading.Thread(target=serve,args=(c,),daemon=True).start()'" >/dev/null 2>&1 &
	HOLD_LISTEN_PID=$!
	sleep 2
	if [[ "$(sink_ready)" != "READY" ]]; then
		echo "b_hold: listener not READY after launch (witness will read BLIND)" >&2
	fi
}
# probe_hold <seconds> — connect, exchange, then heartbeat every 10 s for the
# window, keeping the witnessed session ESTABLISHED so idle-GC cannot expire
# it mid-run (natural-expiry exclusion by construction: idle never exceeds
# ~10 s). Writes ESTABLISHED to /tmp/xpf-armb-hold.log on exchange success.
# Backgrounded; reaped in b_postlude.
probe_hold() {
	timeout $(( $1 + 60 )) $SG "incus exec $B_HOST -- timeout $1 python3 -c 'import socket,time
s=socket.socket(); s.settimeout(20)
s.connect((\"$B_SINK\", $B_PORT))
s.sendall(b\"ping\"); d=s.recv(4)
print(\"ESTABLISHED\",int(time.time()),flush=True)
end=time.time()+$1-5
while time.time()<end:
 time.sleep(10)
 try: s.sendall(b\"hb\"); s.recv(4); print(\"HB\",int(time.time()),flush=True)
 except Exception: break'" > /tmp/xpf-armb-hold.log 2>&1 &
	HOLD_CLIENT_PID=$!
}
B_FAIL=0
B_MID_PRESENT=0 B_MID_FWD=0 B_POST_GONE=0 B_POST_BLK=0 B_SESS_GONE=0
# Commit-confirmed liveness: 1 while the Arm B ADD's revert timer may still be
# pending. The EXIT postlude must not plain-commit while pending (that would
# CONFIRM the fixture); it waits out the daemon revert first. Cleared once the
# post-timeout wait has provably outlived the 60 s window.
B_CONFIRM_PENDING=0
B_CONFIRM_DEADLINE=0
# Fixture ownership (GPT-1): the postlude restores ONLY fixture state this run
# verifiably created. B_OWN_NARROW=1 once OUR preamble narrowing commit reads
# back PRESENT; B_OWN_ADD=1 once OUR ADD commit is issued. A baseline
# validation refuse leaves both unset, and the postlude then performs NO
# config mutation at all — it must never "restore" state it never captured,
# which may be another operator's live config.
B_OWN_NARROW=0
B_OWN_ADD=0
# B_BASE_APP captures the validated baseline match-application token (the
# preamble requires `any`; the postlude restores the CAPTURED token).
B_BASE_APP=""
# B_HELD_SID ties the post-timeout session check to the witnessed session
# (GPT-4), not to any same-destination entry.
B_HELD_SID=""
B_HELD_TMO=0
B_MID_EPOCH=0
B_POSTLUDE_DONE=0
B_RESTORE="clean"
B_RESTORE_COMMIT_RC=0
# Provisional verdict (GPT-2): stages RECORD via arm_b_note_* and NEVER print.
# arm_b_emit prints the single WIRE_GATE line AFTER the verified postlude.
B_PROV="NONE"
B_PROV_REASON="--"
# arm_b_note_void <slug> / arm_b_note_fail — record only. Cumulative flags
# (each set to 1 only by its stage's genuine observation) ride the eventual
# envelope, so the row says how far the arm got: all zeros died in the
# preamble/baseline, mid_present=1 died at/after mid-forwarding.
arm_b_note_void() {
	B_PROV="VOID"
	B_PROV_REASON="$1"
	ARM_B_RC=2
}
arm_b_note_fail() {
	B_PROV="FAIL"
	B_PROV_REASON="--"
	ARM_B_RC=1
}
# Postlude restores the owned fixture and VERIFIES the restoration with
# readback (GPT-1/GPT-2). Registered BEFORE the preamble commit: the
# preamble narrowing is a PLAIN commit with no daemon auto-revert, so a void
# between the preamble commit and a late trap registration would leak the
# narrowing — and every later run would then refuse "baseline is not the
# full allow-all" (env-void death spiral).
b_postlude() {
	if [[ "$B_POSTLUDE_DONE" == "1" ]]; then
		echo "postlude: already ran, skipping"
		return 0
	fi
	B_POSTLUDE_DONE=1
	# Reap held-open probe/listener wrappers first (freezes heartbeat traffic
	# before the restore; remote ends self-terminate via their own timeouts).
	# Sole owner of these PIDs: no other site kills them.
	local _pid
	for _pid in "${HOLD_CLIENT_PID:-}" "${HOLD_LISTEN_PID:-}"; do
		if [[ -n "$_pid" ]]; then kill "$_pid" 2>/dev/null || true; wait "$_pid" 2>/dev/null || true; fi
	done
	if [[ "${B_CONFIRM_PENDING:-0}" == "1" ]]; then
		echo "postlude: confirmed ADD still pending, waiting out the daemon revert"
		local remain=$(( ${B_CONFIRM_DEADLINE:-0} - SECONDS + 10 ))
		if (( remain > 0 )); then sleep "$remain"; fi
		B_CONFIRM_PENDING=0
	fi
	if [[ "$B_OWN_NARROW" != "1" && "$B_OWN_ADD" != "1" ]]; then
		echo "postlude: no fixture owned by this run — no config mutation"
		B_RESTORE="clean"
		return 0
	fi
	local restore_cli
	restore_cli='configure\n'
	if [[ "$B_OWN_ADD" == "1" ]]; then
		restore_cli="${restore_cli}delete applications application $B_APP\ndelete security policies from-zone lan to-zone wan policy $B_POL\n"
	fi
	if [[ "$B_OWN_NARROW" == "1" ]]; then
		restore_cli="${restore_cli}delete applications application armb-9531-base\ndelete security policies from-zone lan to-zone wan policy allow-all match application\nset security policies from-zone lan to-zone wan policy allow-all match application $B_BASE_APP\n"
	fi
	restore_cli="${restore_cli}commit\nexit\n"
	printf '%b' "$restore_cli" | run_cli_t >/dev/null 2>&1
	B_RESTORE_COMMIT_RC=$?
	B_RESTORE="clean"
	if ((B_RESTORE_COMMIT_RC != 0)); then
		echo "postlude: restore commit failed (rc=$B_RESTORE_COMMIT_RC)"
		B_RESTORE="dirty"
	fi
	# Config-half readback: allow-all back to the captured token.
	if [[ "$(policy_read "policy allow-all match application ${B_BASE_APP}$")" != "PRESENT" ]]; then
		echo "postlude: readback — allow-all not back to captured baseline ($B_BASE_APP)"
		B_RESTORE="dirty"
	fi
	# Marker-half readback: OUR stanzas gone (absence required; UNREADABLE
	# is dirty, never absent).
	if [[ "$B_OWN_NARROW" == "1" ]] && [[ "$(app_read "armb-9531-base")" != "ABSENT" ]]; then
		echo "postlude: readback — base narrowing application still present"
		B_RESTORE="dirty"
	fi
	if [[ "$B_OWN_ADD" == "1" ]]; then
		if [[ "$(policy_read "policy $B_POL")" != "ABSENT" ]]; then
			echo "postlude: readback — narrow permit policy still present"
			B_RESTORE="dirty"
		fi
		if [[ "$(app_read "$B_APP")" != "ABSENT" ]]; then
			echo "postlude: readback — narrow permit application still present"
			B_RESTORE="dirty"
		fi
	fi
	# Dataplane-half readback: same-path forwarding re-probe expects OK
	# (full allow-all restored). Under a listener, so refused reads BLIND
	# (apparatus) rather than masquerading as a verdict.
	b_listen 60
	B_RESTORE_FWD="$(probe_fwd)"
	b_unlisten
	if [[ "$B_RESTORE_FWD" != "OK" ]]; then
		echo "postlude: readback — same-path forwarding not restored (got $B_RESTORE_FWD)"
		B_RESTORE="dirty"
	else
		echo "postlude: restore verified (config + markers + same-path forwarding)"
	fi
}
# arm_b_emit — the single PRINT point (GPT-2). Precedence (mirrors the wire
# gates' §5b(6) table): provisional PASS + restore clean ⇒ PASS;
# provisional PASS + restore dirty ⇒ VOID env-void; provisional FAIL ⇒ FAIL
# stands (+ STALE notice if restore is also dirty); provisional VOID(r) ⇒
# VOID(r) stands (+ warning if restore is dirty). The envelope always
# prints, so the row exists in every ending.
arm_b_emit() {
	local metrics="mid_present=$B_MID_PRESENT mid_fwd_ok=$B_MID_FWD post_gone=$B_POST_GONE post_blocked=$B_POST_BLK sess_gone=$B_SESS_GONE"
	if [[ "$B_PROV" == "PASS" && "$B_RESTORE" == "clean" ]]; then
		echo "PASS: unconfirmed ADD reverted from store AND dataplane"
		printf 'WIRE_GATE cc-rollback-arm-b PASS reason=-- %s\n' "$metrics"
	elif [[ "$B_PROV" == "PASS" ]]; then
		echo "Arm B VOID: provisional PASS but restore dirty (see postlude diagnostics)"
		printf 'WIRE_GATE cc-rollback-arm-b VOID reason=env-void %s\n' "$metrics"
	elif [[ "$B_PROV" == "FAIL" ]]; then
		if [[ "$B_RESTORE" != "clean" ]]; then
			echo "STALE NOTICE: provisional FAIL and the restore is also dirty — cluster needs operator review"
		fi
		printf 'WIRE_GATE cc-rollback-arm-b FAIL reason=-- %s\n' "$metrics"
	elif [[ "$B_PROV" == "VOID" ]]; then
		if [[ "$B_RESTORE" != "clean" ]]; then
			echo "postlude warning: restore dirty after VOID($B_PROV_REASON) — cluster needs operator review"
		fi
		printf 'WIRE_GATE cc-rollback-arm-b VOID reason=%s %s\n' "$B_PROV_REASON" "$metrics"
	else
		echo "Arm B VOID: no provisional verdict recorded (internal harness bug)"
		printf 'WIRE_GATE cc-rollback-arm-b VOID reason=harness-void %s\n' "$metrics"
	fi
}
trap b_postlude EXIT
echo "--- arm B preamble: narrow baseline so the probe rests BLOCKED ---"
PRE_READ="$(policy_read 'policy allow-all')"
if [[ "$PRE_READ" != "PRESENT" ]]; then
	echo "Arm B REFUSE: cannot read baseline policy (got $PRE_READ)"
	arm_b_note_void env-void
	ARM_B_RC=3
elif ! printf 'show configuration security policies from-zone lan to-zone wan | display set\nexit\n' | run_cli_t | grep -q "policy allow-all match application any$"; then
	echo "Arm B REFUSE: baseline is not the full allow-all (a leaked narrowing may be present)"
	arm_b_note_void env-void
	ARM_B_RC=3
else
	# Capture the validated baseline token for the postlude (GPT-1): the
	# restore sets exactly what was validated, not a constant.
	B_BASE_APP="$(printf 'show configuration security policies from-zone lan to-zone wan | display set\nexit\n' | run_cli_t | grep -oE "policy allow-all match application [^ ]+" | awk '{print $NF}' | head -1)"
	if [[ "$B_BASE_APP" != "any" ]]; then
		echo "Arm B REFUSE: baseline token did not capture as any (got '$B_BASE_APP')"
		arm_b_note_void env-void
		ARM_B_RC=3
	fi
fi
if [[ "$ARM_B_RC" == "0" ]]; then
	# Stale-fixture markers (GPT-1): our ADD/narrowing stanzas must be absent
	# before we create them — otherwise this run cannot own them and a
	# SIGKILL-leaked CONFIRMED permit from an older run would silently
	# become the baseline.
	if [[ "$(policy_read "policy $B_POL")" != "ABSENT" ]]; then
		echo "Arm B REFUSE: stale narrow-permit policy present (previous run leaked?)"
		arm_b_note_void env-void
		ARM_B_RC=3
	elif [[ "$(app_read "$B_APP")" != "ABSENT" ]]; then
		echo "Arm B REFUSE: stale narrow-permit application present (previous run leaked?)"
		arm_b_note_void env-void
		ARM_B_RC=3
	elif [[ "$(app_read "armb-9531-base")" != "ABSENT" ]]; then
		echo "Arm B REFUSE: stale narrowing application present (previous run leaked?)"
		arm_b_note_void env-void
		ARM_B_RC=3
	fi
fi
if [[ "$ARM_B_RC" == "0" ]]; then
	printf 'configure\nset applications application %s protocol tcp destination-port %s\ndelete security policies from-zone lan to-zone wan policy allow-all match application\nset security policies from-zone lan to-zone wan policy allow-all match application %s\ncommit\nexit\n' \
		"armb-9531-base" "$((B_PORT + 1))" "armb-9531-base" | run_cli_t > /tmp/xpf-armb-preamble.log 2>&1
	B_PREAMBLE_RC=$?
	if ((B_PREAMBLE_RC != 0)); then
		echo "Arm B REFUSE: preamble commit failed (rc=$B_PREAMBLE_RC, log tail):"
		tail -6 /tmp/xpf-armb-preamble.log 2>/dev/null
		arm_b_note_void env-void
		ARM_B_RC=3
	fi
fi
if [[ "$ARM_B_RC" == "0" ]]; then
	sleep 5
	# The commit above reported complete, but a single store read right after
	# a commit races control-plane convergence under load (live: "commit
	# complete" followed by one absent read). Poll the read briefly — the
	# same reason poll_fwd polls the dataplane — before declaring the
	# narrowing lost.
	B_NARROW=""
	for ((i = 1; i <= 6; i++)); do
		B_NARROW="$(policy_read 'policy allow-all match application armb-9531-base')"
		if [[ "$B_NARROW" == "PRESENT" ]]; then break; fi
		echo "preamble narrowing not yet visible (try $i/6: got $B_NARROW)"
		sleep 5
	done
	if [[ "$B_NARROW" != "PRESENT" ]]; then
		echo "Arm B REFUSE: preamble narrowing did not land (commit log tail):"
		tail -6 /tmp/xpf-armb-preamble.log 2>/dev/null
		arm_b_note_void harness-void
		ARM_B_RC=3
	else
		B_OWN_NARROW=1
	fi
fi
if [[ "$ARM_B_RC" == "0" ]]; then
	# Baseline poll UNDER a listener (b_listen self-pkills stale markers,
	# retries the bind, and verifies readiness). Without one, a
	# not-yet-converged narrowing reads as refused→BLIND and aborts the
	# poll on its first try (live). With a listener, permitted reads OK
	# (retried to convergence) and only genuine infra failure stays BLIND.
	b_listen 300
	B_PRE_FWD="$(poll_fwd BLOCKED 8 || true)"
	b_unlisten
	if [[ "$B_PRE_FWD" != "BLOCKED" ]]; then
		echo "Arm B REFUSE: probe is not BLOCKED at baseline (got $B_PRE_FWD)"
		if [[ "$B_PRE_FWD" == "TIMEOUT" ]]; then
			arm_b_note_void row-timeout
		else
			arm_b_note_void env-void
		fi
		ARM_B_RC=3
	else
		echo "arm B baseline: probe BLOCKED, narrow permit absent"
	fi
fi
if [[ "$ARM_B_RC" == "0" ]]; then
	B_COMMIT_VERB="commit confirmed 1"
	if [[ "$B_ENFORCED" == "1" ]]; then
		B_COMMIT_VERB="commit"
		echo "--- NEGATIVE CONTROL: ADD via plain commit (non-reverting) ---"
	else
		echo "--- service-mode: ADD narrow permit, commit confirmed 1 (NOT confirming) ---"
	fi
	# GLM-M5 flake shape (documented, not lengthened): the 60 s confirmed
	# window bounds the ENTIRE mid phase. Under load, slow convergence can
	# push mid-polls past the revert instant — the fixture then reverts
	# mid-measurement (mid PRESENT→ABSENT flips, forwarding OK→BLOCKED) and
	# the readings go inconsistent. That shape surfaces as FAIL/VOID with
	# partial cumulative flags, never as PASS; lengthening the window would
	# lengthen every run including the enforced control's wait, so the
	# window stays 60 s and the shape stays documented here.
	printf 'configure\nset applications application %s protocol tcp destination-port %s\nset security policies from-zone lan to-zone wan policy %s match source-address any\nset security policies from-zone lan to-zone wan policy %s match destination-address any\nset security policies from-zone lan to-zone wan policy %s match application %s\nset security policies from-zone lan to-zone wan policy %s then permit\n%s\nexit\n' \
		"$B_APP" "$B_PORT" "$B_POL" "$B_POL" "$B_POL" "$B_APP" "$B_POL" "$B_COMMIT_VERB" | run_cli_t | tail -6
	B_ADD_RC=$?
	if ((B_ADD_RC != 0)); then
		echo "Arm B VOID: ADD commit failed (rc=$B_ADD_RC)"
		arm_b_note_void env-void
		ARM_B_RC=2
	else
		B_OWN_ADD=1
	fi
	if [[ "$B_ENFORCED" != "1" ]]; then
		B_CONFIRM_PENDING=1
		B_CONFIRM_DEADLINE=$(( SECONDS + 60 ))
	fi
	sleep 5
	echo "--- mid-window ---"
	if [[ "$(policy_read "policy $B_POL")" == "PRESENT" ]]; then
		B_MID_PRESENT=1
		echo "mid narrow permit: PRESENT"
	else
		echo "mid narrow permit: NOT PRESENT ($(policy_read "policy $B_POL"))"
	fi
	B_MID_FWD="$(poll_fwd OK 8 || true)"
	echo "mid forwarding: $B_MID_FWD"
	if [[ "$B_MID_FWD" == "OK" ]]; then
		B_MID_FWD=1
	elif [[ "$B_MID_FWD" == "TIMEOUT" ]]; then
		B_MID_FWD=0
		echo "Arm B VOID: mid-window probe timed out (apparatus, not a forwarding verdict)"
		arm_b_note_void row-timeout
		ARM_B_RC=2
	elif [[ "$B_MID_FWD" == "BLOCKED" ]]; then
		B_MID_FWD=0
		echo "FAIL: unconfirmed ADD did not forward mid-window"
		arm_b_note_fail
		ARM_B_RC=1
	else
		echo "Arm B VOID: mid-window probe unreadable ($B_MID_FWD)"
		B_MID_FWD=0
		arm_b_note_void harness-void
		ARM_B_RC=2
	fi
fi
# Witnessed session: destination-centered count on a valid listing (source is
# post-NAT; only the destination is stable). Nothing else uses B_PORT, so any
# entry for SINK:B_PORT in the mid window is the probe's session.
#
# Hold-open witness: the single-shot probe above closes immediately, leaving
# a close-state session (live: Timeout: 20) that can never cover the 80 s
# wait — so hold one connection ESTABLISHED with heartbeats across the whole
# window. Idle never exceeds ~10 s, so idle-GC cannot expire it mid-run:
# natural expiry is excluded by construction (the §5d lifetime threshold's
# intent) rather than by a Timeout reading. The held Timeout is still echoed
# for the record, but no verdict turns on it.
if [[ "$ARM_B_RC" == "0" ]]; then
	$SG "incus exec $B_SINK_REF -- pkill -f xpf-armb-listen 2>/dev/null" >/dev/null 2>&1 || true
	sleep 2
	b_hold 260
	# Truncate: a stale ESTABLISHED from an earlier run would false-positive
	# the grep below.
	: > /tmp/xpf-armb-hold.log
	probe_hold 240
	sleep 6
	if ! grep -q ESTABLISHED /tmp/xpf-armb-hold.log 2>/dev/null; then
		echo "Arm B VOID: held probe never established mid-window (apparatus, not a forwarding verdict)"
		arm_b_note_void harness-void
		ARM_B_RC=2
	else
		echo "held probe: ESTABLISHED (heartbeats holding the session)"
	fi
fi
if [[ "$ARM_B_RC" == "0" ]]; then
	if ! SESS_OUT="$(sess_poll "$LAN_HOST_IP" "$B_SRC_PORT" "$B_SINK" "$B_PORT")"; then
		echo "Arm B VOID: session listing unreadable mid-window"
		arm_b_note_void harness-void
		ARM_B_RC=2
	elif [[ "$(sess_count "$SESS_OUT" "$B_SINK" "$B_PORT")" == "0" ]]; then
		echo "Arm B FAIL: no session for the probe destination mid-window"
		arm_b_note_fail
		ARM_B_RC=1
	else
		echo "mid session: WITNESSED for $B_SINK:$B_PORT (held open)"
		# Tie the witness to ONE session (GPT-4): the listing may carry
		# leftover close-state entries, so select the max-Timeout entry as
		# the held one and record its ID for the post-timeout check.
		B_HELD_SID=""
		B_HELD_TMO=0
		while read -r sid tmo; do
			if [[ "$sid" =~ ^[0-9]+$ && "$tmo" =~ ^[0-9]+$ ]] && ((10#$tmo > 10#$B_HELD_TMO)); then
				B_HELD_SID="$sid"
				B_HELD_TMO="$tmo"
			fi
		done < <(sess_sids "$SESS_OUT" "$B_SINK" "$B_PORT")
		if [[ -z "$B_HELD_SID" ]]; then
			echo "Arm B VOID: session present but no ID parsed (cannot tie the witness)"
			arm_b_note_void harness-void
			ARM_B_RC=2
		else
			B_MID_EPOCH="$(date +%s)"
			echo "mid held session: ID $B_HELD_SID (timeout $B_HELD_TMO, for the record)"
		fi
	fi
fi
if [[ "$ARM_B_RC" == "0" ]]; then
	echo "--- waiting for 1-min commit-confirmed timeout (no confirm) ---"
	sleep 80
	B_CONFIRM_PENDING=0
	echo "--- post-timeout ---"
	B_POST_READ="$(policy_read "policy $B_POL")"
	if [[ "$B_POST_READ" == "ABSENT" ]]; then
		B_POST_GONE=1
		echo "post narrow permit: GONE from the store"
	elif [[ "$B_POST_READ" == "PRESENT" ]]; then
		echo "post narrow permit: STILL PRESENT (dataplane revert also suspect)"
	else
		echo "Arm B VOID: store unreadable post-timeout"
		arm_b_note_void harness-void
		ARM_B_RC=2
	fi
fi
if [[ "$ARM_B_RC" == "0" ]]; then
	B_POST_FWD="$(poll_fwd BLOCKED 10 || true)"
	echo "post forwarding: $B_POST_FWD"
	if [[ "$B_POST_FWD" == "BLOCKED" ]]; then
		B_POST_BLK=1
	elif [[ "$B_POST_FWD" == "OK" ]]; then
		echo "FAIL: probe still forwards post-timeout (stale-permit residual)"
	elif [[ "$B_POST_FWD" == "TIMEOUT" ]]; then
		echo "Arm B VOID: post-timeout probe timed out (apparatus, not a forwarding verdict)"
		arm_b_note_void row-timeout
		ARM_B_RC=2
	else
		echo "Arm B VOID: post-timeout probe unreadable ($B_POST_FWD)"
		arm_b_note_void harness-void
		ARM_B_RC=2
	fi
fi
if [[ "$ARM_B_RC" == "0" ]]; then
	# Lifetime-coverage gate: the held session's witnessed Timeout must
	# cover the elapsed mid→post span plus margin, or idle-GC could have
	# taken it and absence would be meaningless. Sound under both Timeout
	# readings (remaining or configured: configured 300 with idle ≤
	# elapsed leaves remaining ≥ margin). The pre-revert heartbeats are
	# echoed for the record — note they MUST go quiet after a successful
	# revert (packets dropped), so holder silence post-revert is expected,
	# not evidence; a staleness gate here would fail every good run by
	# construction.
	HB_NOW="$(date +%s)"
	HB_ELAPSED=$((HB_NOW - B_MID_EPOCH))
	echo "held heartbeats for the record: $(grep -cE '^HB ' /tmp/xpf-armb-hold.log 2>/dev/null || true) beats, last $(grep -oE '^HB [0-9]+' /tmp/xpf-armb-hold.log 2>/dev/null | tail -1)"
	if ((10#$B_HELD_TMO < HB_ELAPSED + 30)); then
		echo "Arm B VOID: held lifetime $B_HELD_TMO cannot cover ${HB_ELAPSED}s elapsed + margin — cannot exclude natural expiry"
		arm_b_note_void harness-void
		ARM_B_RC=2
	elif ! SESS_POST="$(sess_poll "$LAN_HOST_IP" "$B_SRC_PORT" "$B_SINK" "$B_PORT")"; then
		echo "Arm B VOID: session listing unreadable post-timeout"
		arm_b_note_void harness-void
		ARM_B_RC=2
	elif grep -q "Session ID: $B_HELD_SID[, ]" <<<"$SESS_POST"; then
		echo "FAIL: held session $B_HELD_SID lingers post-timeout"
		arm_b_note_fail
		ARM_B_RC=1
	elif [[ "$(sess_count "$SESS_POST" "$B_SINK" "$B_PORT")" != "0" ]]; then
		echo "FAIL: probe session lingers post-timeout (non-held entry)"
		arm_b_note_fail
		ARM_B_RC=1
	else
		B_SESS_GONE=1
		echo "post session: GONE (held ID $B_HELD_SID absent)"
	fi
fi
if [[ "$ARM_B_RC" == "0" ]]; then
	if [[ "$B_MID_PRESENT" == "1" && "$B_MID_FWD" == "1" && "$B_POST_GONE" == "1" && "$B_POST_BLK" == "1" && "$B_SESS_GONE" == "1" ]]; then
		B_PROV="PASS"
		B_PROV_REASON="--"
	else
		arm_b_note_fail
		ARM_B_RC=1
	fi
fi
# Verified restore, THEN the single envelope (GPT-2): the trap is removed so
# the EXIT handler cannot double-run, the postlude restores + readback-
# verifies, and arm_b_emit prints the one WIRE_GATE line per precedence.
trap - EXIT
b_postlude
arm_b_emit
fi

echo "=== COMPOSITE ==="
echo "arm-a rc=$ARM_A_RC arm-b rc=$ARM_B_RC (arms not selected score 0)"
if [[ "$ARM_A_RC" == "1" || "$ARM_B_RC" == "1" ]]; then
	exit 1
elif [[ "$ARM_A_RC" == "3" || "$ARM_B_RC" == "3" ]]; then
	exit 3
elif [[ "$ARM_A_RC" == "2" || "$ARM_B_RC" == "2" ]]; then
	exit 2
else
	exit 0
fi
