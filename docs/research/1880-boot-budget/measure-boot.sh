#!/usr/bin/env bash
# #1880 research instrumentation — measure fw0 reboot comeback time the way
# test/incus/test-failover.sh Phase 4 measures it, then attribute the wall
# time from in-VM journal forensics.
#
# Usage (inside a with-cluster.sh lock cell, under incus-admin):
#   bash docs/research/1880-boot-budget/measure-boot.sh <label>
#
# Emits a self-contained report to stdout. Does NOT deploy; the caller
# decides whether a deploy precedes the reboot.
set -u

FW0="${FW0:-loss:xpf-userspace-fw0}"
FW1="${FW1:-loss:xpf-userspace-fw1}"
LABEL="${1:-unlabeled}"
MAX_POLLS=180   # keep polling past the 60-iteration harness budget to see the real comeback

now_ms() { date +%s%3N; }

echo "##### MEASURE [$LABEL] start $(date -u +%FT%TZ)"

# Pre-reboot snapshot: confirm xpfd active + uptime
incus exec "$FW0" -- sh -c 'echo "pre-reboot: $(uptime -p), xpfd=$(systemctl is-active xpfd)"' 2>&1

T0=$(now_ms)
incus exec "$FW0" -- reboot 2>/dev/null || true
T_REBOOT_RET=$(now_ms)
echo "reboot-cmd-returned-after-ms: $((T_REBOOT_RET - T0))"

sleep 3   # harness does this

# Harness-faithful poll loop with per-iteration latency log
ACTIVE_ITER=-1
ACTIVE_MS=-1
for i in $(seq 1 "$MAX_POLLS"); do
	P0=$(now_ms)
	if incus exec "$FW0" -- systemctl is-active --quiet xpfd 2>/dev/null; then
		P1=$(now_ms)
		ACTIVE_ITER=$i
		ACTIVE_MS=$((P1 - T0))
		echo "poll $i: ACTIVE exec_ms=$((P1 - P0)) wall_since_reboot_ms=$ACTIVE_MS"
		break
	fi
	P1=$(now_ms)
	echo "poll $i: down exec_ms=$((P1 - P0)) wall_since_reboot_ms=$((P1 - T0))"
	sleep 1
done

if [[ $ACTIVE_ITER -lt 0 ]]; then
	echo "RESULT [$LABEL]: xpfd NOT active after $MAX_POLLS polls — aborting forensics"
	exit 1
fi

echo "RESULT [$LABEL]: active at iteration $ACTIVE_ITER (harness budget=60 iters), wall $((ACTIVE_MS / 1000)).$((ACTIVE_MS % 1000))s"

# ── In-VM forensics ──────────────────────────────────────────────────
echo "--- systemd-analyze time"
incus exec "$FW0" -- systemd-analyze time 2>&1 || true
echo "--- critical-chain xpfd"
incus exec "$FW0" -- systemd-analyze critical-chain xpfd.service 2>&1 || true
echo "--- blame top 12"
incus exec "$FW0" -- sh -c 'systemd-analyze blame | head -12' 2>&1 || true
echo "--- xpfd spawn (monotonic) this boot"
incus exec "$FW0" -- sh -c 'journalctl -b -u xpfd -o short-monotonic 2>/dev/null | head -3' 2>&1 || true
echo "--- incus-agent start (monotonic) this boot"
incus exec "$FW0" -- sh -c 'journalctl -b -o short-monotonic 2>/dev/null | grep -m2 -i "incus-agent" | head -2' 2>&1 || true
echo "--- this boot kernel start (unix wallclock)"
incus exec "$FW0" -- sh -c 'journalctl -b -o short-unix 2>/dev/null | head -1' 2>&1 || true
echo "--- previous boot: last journal line (shutdown end, unix wallclock)"
incus exec "$FW0" -- sh -c 'journalctl -b -1 -o short-unix 2>/dev/null | tail -1' 2>&1 || true
echo "--- previous boot: shutdown initiation + xpfd stop span"
incus exec "$FW0" -- sh -c 'journalctl -b -1 -o short-unix 2>/dev/null | grep -m1 "The system will reboot\|Stopping xpfd\|Stopped xpfd"' 2>&1 || true
incus exec "$FW0" -- sh -c 'journalctl -b -1 -u xpfd -o short-unix 2>/dev/null | tail -4' 2>&1 || true
echo "--- previous boot: slowest stop jobs (>2s gaps around Stopping/Stopped)"
incus exec "$FW0" -- sh -c 'journalctl -b -1 -o short-unix 2>/dev/null | grep -E "Stopping |Stopped |Unmounting|reboot: " | tail -25' 2>&1 || true
echo "host-reboot-epoch-ms: $T0"
echo "##### MEASURE [$LABEL] end $(date -u +%FT%TZ)"
