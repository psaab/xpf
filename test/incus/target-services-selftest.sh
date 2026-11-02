#!/usr/bin/env bash
#
# #8040 — hermetic self-test for test/incus/target-services.sh.
#
# The subject is a diagnosis tool, and a diagnosis tool that reports the wrong
# thing is worse than none: a runner acts on it. The three properties that
# matter, and the failure each one guards:
#
#   1. `check <ports>` exits NON-ZERO when any named port is closed, and ZERO
#      when they are all open. A gate that always passes is the state before
#      #8040 — every harness discovered the missing listener itself, after
#      spending a deploy and the shared cluster lock.
#   2. `check` is SCOPED: a closed port that the caller did not name must not
#      fail it. Requiring all 24 would be an over-rejection that blocks a
#      two-port smoke on an unrelated class, and a gate people learn to skip
#      is a gate that is not there.
#   3. When it DOES fail, it names every missing port — not just the first.
#      Failing on the first hole is exactly the rediscovery loop this replaces:
#      fix one port, re-run, find the next.
#
# Hermetic: `incus` is replaced by a stub on PATH that answers from a scripted
# port table, so nothing here touches a cluster.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUBJECT="${SCRIPT_DIR}/target-services.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fails=0

fail() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }
pass() { echo "ok: $*"; }

# The stub answers two shapes the subject uses: `incus list ...` (target
# instance discovery) and `incus exec ... -- bash -c <script>` / `-- ping`.
# OPEN_PORTS in the environment is the scripted truth.
make_stub() {
    cat > "${TMP}/incus" <<'STUB'
#!/usr/bin/env bash
case "$1" in
  list) exit 0 ;;                       # no instance holds the target IP
  exec) [[ -n "${STUB_EXEC_LOG:-}" ]] && echo "$2" >> "$STUB_EXEC_LOG" ;;
esac
# incus exec <remote>:<inst> -- <cmd...>
for a in "$@"; do shift; [[ "$a" == "--" ]] && break; done
case "${1:-}" in
  ping) exit 0 ;;                       # target answers ICMP
esac
# bash -c "<probe loop>" — re-derive the port list from the script text and
# answer from OPEN_PORTS rather than actually dialling anything.
script="${3:-}"
for p in $(grep -oE '\b[0-9]{4}\b' <<< "$script" | sort -u); do
  if [[ " ${OPEN_PORTS:-} " == *" $p "* ]]; then echo "$p open"; else echo "$p closed"; fi
done
STUB
    chmod +x "${TMP}/incus"
}
make_stub
export PATH="${TMP}:${PATH}"
# Force the direct-incus branch of incus_run: `id -nG` must appear to include
# incus-admin, or the stub is invoked through `sg` and never seen.
id() { if [[ "${1:-}" == "-nG" ]]; then echo "incus-admin"; else command id "$@"; fi; }
export -f id

run_check() {
    local open="$1"; shift
    OPEN_PORTS="$open" bash "$SUBJECT" check "$@" 2>&1
}
rc_of() {
    local open="$1"; shift
    OPEN_PORTS="$open" bash "$SUBJECT" check "$@" > /dev/null 2>&1
    echo $?
}

ALL="5200 5201 5202 5203 5204 5205 5206 5207 5208 5209 5210 5211 6200 6201 6202 6203 6204 6205 6206 6207 6208 6209 6210 6211"

# --- 1. the predicate ---------------------------------------------------
if [[ "$(rc_of "$ALL" 5202 6200)" != "0" ]]; then
    fail "check exits non-zero when every named port is OPEN — the gate would " \
         "block a healthy target and get skipped"
else
    pass "all-open named ports => rc 0"
fi

if [[ "$(rc_of "5200 5201" 5202 6200)" == "0" ]]; then
    fail "check exits ZERO with both named ports CLOSED. This is the state" \
         "before #8040: every harness rediscovers the missing listener itself," \
         "after spending a build, a deploy and the shared cluster lock"
else
    pass "named ports closed => rc 1"
fi

# The MIDDLE row: one of two named ports open. A gate that only fires when
# EVERYTHING is down passes cell 1 and cell 2 above and is still broken.
if [[ "$(rc_of "5202" 5202 6200)" == "0" ]]; then
    fail "check exits ZERO when ONE of two named ports is closed; a partially" \
         "provisioned target must fail, that is the case #8040 was filed about"
else
    pass "one of two named ports closed => rc 1"
fi

# --- 2. scoping ---------------------------------------------------------
# Everything EXCEPT 5207 is up; a caller naming 5202/6200 must pass.
NOT_5207="${ALL/5207 /}"
if [[ "$(rc_of "$NOT_5207" 5202 6200)" != "0" ]]; then
    fail "an unrelated closed port (5207) failed a check for 5202/6200." \
         "Requiring all 24 blocks a two-port smoke on a class it never sends" \
         "to, and a gate that over-rejects is one runners learn to skip"
else
    pass "unrelated closed port does not fail a scoped check"
fi

# The control for scoping: with NO arguments the predicate IS all 24, so the
# same target must fail. Without this, "scoped" could mean "checks nothing".
if [[ "$(rc_of "$NOT_5207")" == "0" ]]; then
    fail "a bare check passed with 5207 closed; the no-argument predicate must" \
         "be all 24 ports, or the scoping cell above is satisfied by a gate" \
         "that checks nothing at all"
else
    pass "bare check still fails on any closed port"
fi

# --- 3. the diagnosis ---------------------------------------------------
out="$(run_check "5200 5201 5202" 5203 5204 5205)"

# THE ASSERTION IS SCOPED TO THE ABORT LINE, and that is not a detail.
#
# A first version grepped the WHOLE output for "5203 5204 5205". It passed
# against a subject mutated to stop at the first missing port — because
# cmd_status's remediation hint prints
#
#     for p in 5200 5201 5202 5203 5204 5205 ...; do iperf3 -s -p $p -D; done
#
# which contains that exact substring no matter what the ABORT line says. The
# cell was satisfied by a line with nothing to do with the property, so the
# one mutation it existed to catch escaped it. Ask what an instrument would
# report if the thing were FALSE, and it reported the same thing.
abort_line="$(grep '^ABORT:' <<< "$out" | head -1)"
if [[ -z "$abort_line" ]]; then
    fail "no ABORT line in the failure output at all:
$out"
else
    for want in 5203 5204 5205; do
        grep -q "$want" <<< "$abort_line" \
            || fail "the ABORT line does not name missing port ${want}. Failing" \
                    "on the first hole is the rediscovery loop this replaces:" \
                    "fix one port, re-run, find the next. line was: ${abort_line}"
    done
    # And the negative half: it must not name a port that IS up, or a runner
    # restarts listeners that were never down.
    for open_port in 5200 5201 5202; do
        grep -q "$open_port" <<< "$abort_line" \
            && fail "the ABORT line names ${open_port}, which is OPEN: ${abort_line}"
    done
fi
[[ $fails -eq 0 ]] && pass "abort names every missing port and no open one"

# The full grid must appear on failure even though only three ports were
# NAMED — the predicate is narrow, the report is wide.
grep -q '6211' <<< "$out" \
    || fail "the failure report does not include the whole 24-port grid; a
runner fixes one port at a time instead of seeing every hole:
$out"

# --- 4. the probe VANTAGE POINT (#8164) ---------------------------------
#
# This script used to probe from `xpf-userspace-fw0`. The firewall FORWARDS
# VLAN-80 traffic and does not originate it, so its host stack cannot open TCP
# to the target even when every service is up — measured on the standing loss
# cluster, same instrument and same instant: 0/24 open from either firewall
# node, 23/24 open from the LAN source container. The gate therefore reported
# "24 of 24 target services are DOWN" against a target that was almost
# entirely healthy, and that reading is indistinguishable from the host having
# died. #7100 and #7159 were both parked for weeks on it.
#
# A wrong vantage point cannot be caught by any of the cells above: they
# script the port table directly, so the subject returns the same answer
# whichever instance it asks. The observable has to be WHICH INSTANCE the
# probe ran on, which is why the stub now records it.
EXEC_LOG="${TMP}/exec-targets"
probe_target() {
    : > "$EXEC_LOG"
    OPEN_PORTS="$ALL" STUB_EXEC_LOG="$EXEC_LOG" "$@" bash "$SUBJECT" check 5202 \
        > /dev/null 2>&1
    # The instance ref of the port probe, minus the remote prefix.
    grep -v '^$' "$EXEC_LOG" | tail -1 | sed 's/^[^:]*://'
}

got="$(probe_target env)"
# Non-vacuity first: an empty log makes every assertion below vacuously true,
# and a stub that stopped recording looks exactly like a passing subject.
if [[ -z "$got" ]]; then
    fail "the stub recorded no 'incus exec' target at all; section 4 asserts" \
         "nothing and would stay green against any vantage point"
else
    case "$got" in
        *fw0*|*fw1*)
            fail "the default probe runs on '${got}', a FIREWALL node. The" \
                 "firewall forwards VLAN-80 traffic and cannot originate TCP to" \
                 "the target, so every port reads closed and the gate blocks" \
                 "every per-class harness on a healthy target (#8164)" ;;
        *) pass "default probe vantage is not a firewall node (${got})" ;;
    esac
fi

# The env's OWN LAN host, not a literal. A subject that swapped one hardcoded
# instance name for another passes the cell above and is still wrong on every
# environment but this one.
got="$(probe_target env CLUSTER_LAN_HOST_NAME=probe-canary-host)"
if [[ "$got" != "probe-canary-host" ]]; then
    fail "with CLUSTER_LAN_HOST_NAME=probe-canary-host the probe ran on" \
         "'${got}'. The vantage must come from the cluster env's LAN_HOST" \
         "(cluster-env.sh), or the script is hardcoded to one environment"
else
    pass "probe vantage follows the cluster env's LAN host"
fi

# And the explicit override still wins, so an operator can aim the probe
# somewhere else without editing the script.
got="$(probe_target env PROBE_FROM=explicit-probe-host)"
if [[ "$got" != "explicit-probe-host" ]]; then
    fail "PROBE_FROM=explicit-probe-host was ignored; the probe ran on '${got}'"
else
    pass "explicit PROBE_FROM override is honoured"
fi
# --- summary ------------------------------------------------------------

# --- 5. the #16213 alias premise -------------------------------------------
#
# The stub above answers `incus list` with nothing, so the pre-#16213
# subject — which believed 172.16.80.200 was external hardware with no
# handle — would print that false premise forever. These cells pin the
# corrected one: when the target IS the declarative alias, `status`
# names the mouse host as its owner and `up` delegates to
# mouse-target-setup.sh (the systemd pin) instead of detached spawns.
# A subject that still calls .200 "external lab hardware", or that
# starts `iperf3 -s -D` / socat orphans on an instance-managed target,
# fails here. Hermetic: incus stays stubbed; mouse-target-setup.sh is
# replaced by a recorder on PATH-adjacent staging.
ALIAS_TMP="$(mktemp -d)"
trap 'rm -rf "$TMP" "$ALIAS_TMP"' EXIT
cat > "${ALIAS_TMP}/incus" <<'STUB2'
#!/usr/bin/env bash
case "$1" in
  list)
    # The mouse host holds .201; the .202 alias (#18576, was .200) is not
    # listed separately.
    echo "xpf-mouse-target,172.16.80.201"
    exit 0 ;;
  exec)
    [[ -n "${STUB_EXEC_LOG:-}" ]] && echo "$*" >> "$STUB_EXEC_LOG"
    for a in "$@"; do shift; [[ "$a" == "--" ]] && break; done
    case "${1:-}" in
      ping) exit 0 ;;
      bash)
        script="${3:-}"
        for p in $(grep -oE '\b[0-9]{4}\b' <<< "$script" | sort -u); do
          if [[ " ${OPEN_PORTS:-} " == *" $p "* ]]; then echo "$p open"; else echo "$p closed"; fi
        done ;;
    esac
    exit 0 ;;
esac
exit 0
STUB2
chmod +x "${ALIAS_TMP}/incus"
# Recorder standing in for the sibling mouse-target-setup.sh: `up` must
# delegate to it (with the alias env), never spawn detached listeners.
cp "$SUBJECT" "${ALIAS_TMP}/target-services.sh"
cat > "${ALIAS_TMP}/mouse-target-setup.sh" <<'REC'
#!/usr/bin/env bash
echo "mouse-setup:$* TARGET_ALIAS_V4=${TARGET_ALIAS_V4:-} MOUSE_TARGET_V4=${MOUSE_TARGET_V4:-}" >> "${STUB_SETUP_LOG:-/dev/null}"
REC
chmod +x "${ALIAS_TMP}/mouse-target-setup.sh"
SETUP_LOG="${ALIAS_TMP}/setup-log"; : > "$SETUP_LOG"
alias_env() {
    env PATH="${ALIAS_TMP}:${PATH}" OPEN_PORTS="$ALL" \
        STUB_SETUP_LOG="$SETUP_LOG" \
        TARGET_V4=172.16.80.202 TARGET_ALIAS_V4=172.16.80.202 \
        MOUSE_TARGET_V4=172.16.80.201 INCUS_REMOTE=loss \
        bash "${ALIAS_TMP}/target-services.sh" "$@"
}
out="$(alias_env status 2>&1)"
grep -q "xpf-mouse-target" <<< "$out" \
    || fail "#16213: status does not name the mouse host as the .200 alias owner:
$out"
grep -qi "external lab hardware" <<< "$out" \
    && fail "#16213: status still calls the instance-held .200 external hardware:
$out"
grep -q "172.16.80.202" <<< "$out" >/dev/null \
    && pass "#16213 alias owner is named in status"
: > "$SETUP_LOG"
alias_env up > /dev/null 2>&1
grep -q "mouse-setup:up TARGET_ALIAS_V4=172.16.80.202 MOUSE_TARGET_V4=172.16.80.201" "$SETUP_LOG" \
    || fail "#16213: up did not delegate to mouse-target-setup.sh (systemd pin); setup log:
$(cat "$SETUP_LOG")"
[[ -s "$SETUP_LOG" ]] && pass "#16213 up delegates to the systemd-pinned mouse setup"

# --- 6. the #18626 down orphan sweep -------------------------------------
#
# Listener argv is not a reliable identity: default-port iperf3 has no -p,
# and pkill -f can match the bash -c process carrying its own pattern. Model
# socket owners and their cgroups hermetically, execute the exact remote
# script emitted by down, and verify it kills only orphan socket owners while
# completing both the iperf and echo sweeps.
DOWN_TMP="$(mktemp -d)"
trap 'rm -rf "$TMP" "$ALIAS_TMP" "$DOWN_TMP"' EXIT
mkdir -p "${DOWN_TMP}/bin" "${DOWN_TMP}/proc/"{146115,2002,2003,3000,3001,3101,3201}
FAKE_LOG="${DOWN_TMP}/fake.log"
cat > "${DOWN_TMP}/bin/ss" <<'FAKE'
#!/usr/bin/env bash
port=""
has_pid_info=0
for arg in "$@"; do
    candidate="${arg##*:}"
    [[ "$candidate" =~ ^[0-9]+$ ]] && port="$candidate"
    if [[ "$arg" == -* && "$arg" == *p* ]]; then
        has_pid_info=1
    fi
done
echo "ss ${port}" >> "${FAKE_LOG:?}"
if [[ "$has_pid_info" != 1 ]]; then
    echo "LISTEN 0 4096 0.0.0.0:${port} 0.0.0.0:*"
    exit 0
fi
case "$port" in
  5201)
    if [[ "${FAKE_FAILED_IPERF:-0}" == 1 ]]; then
      echo 'LISTEN 0 4096 0.0.0.0:5201 0.0.0.0:* users:(("iperf3",pid=146115,fd=3))'
    else
      echo 'LISTEN 0 4096 0.0.0.0:5201 0.0.0.0:* users:(("iperf3",pid=146115,fd=3),("iperf3",pid=2002,fd=3),("iperf3",pid=2003,fd=4))'
    fi ;;
  6201) echo 'LISTEN 0 4096 0.0.0.0:6201 0.0.0.0:* users:(("python3",pid=3000,fd=3),("python3",pid=3001,fd=4),("evil pid=3999",pid=3101,fd=5),("x",pid=3999",pid=3201,fd=6))' ;;
esac
FAKE
cat > "${DOWN_TMP}/bin/systemctl" <<'FAKE'
#!/usr/bin/env bash
echo "systemctl $*" >> "${FAKE_LOG:?}"
case "$*" in
  *show*)
    if [[ "${FAKE_METADATA_FAIL:-0}" == 1 && "$*" == *mouse-iperf3@5201* ]]; then
      case "$*" in
        *MainPID*) echo 2002 ;;
        *ControlGroup*) echo /system.slice/mouse-iperf3@5201.service ;;
      esac
      exit 1
    fi
    if [[ "${FAKE_SYSTEMD:-1}" == 0 ]]; then
      [[ "$*" == *MainPID* ]] && echo 0
      exit 0
    fi
    case "$*" in
      *MainPID*mouse-iperf3@5201*)
        [[ "${FAKE_FAILED_IPERF:-0}" == 1 ]] && echo 0 || echo 2002
        ;;
      *ControlGroup*mouse-iperf3@5201*)
        if [[ "${FAKE_CGROUP_MISSING:-0}" != 1 && "${FAKE_FAILED_IPERF:-0}" != 1 ]]; then
          echo /system.slice/mouse-iperf3@5201.service
        fi
        ;;
      *MainPID*mouse-echo*) echo 3000 ;;
      *ControlGroup*mouse-echo*) echo /system.slice/mouse-echo.service ;;
      *MainPID*) echo 0 ;;
    esac
    ;;
esac
exit 0
FAKE
cat > "${DOWN_TMP}/bin/kill" <<'FAKE'
#!/usr/bin/env bash
kill() { echo "kill $*" >> "${FAKE_LOG:?}"; }
FAKE
cat > "${DOWN_TMP}/bin/pkill" <<'FAKE'
#!/usr/bin/env bash
# Model pkill -f's self-match: terminate the remote bash -c that contains the
# pattern, so the following (echo-listener) sweep is never reached.
echo "pkill $*" >> "${FAKE_LOG:?}"
/bin/kill -TERM "$PPID"
FAKE
chmod +x "${DOWN_TMP}/bin/"*
echo '0::/.lxc' > "${DOWN_TMP}/proc/146115/cgroup"
echo '0::/system.slice/mouse-iperf3@5201.service' > "${DOWN_TMP}/proc/2002/cgroup"
echo '0::/system.slice/mouse-iperf3@5201.service/child' > "${DOWN_TMP}/proc/2003/cgroup"
echo '0::/system.slice/mouse-echo.service' > "${DOWN_TMP}/proc/3000/cgroup"
echo '0::/system.slice/mouse-echo.service/child' > "${DOWN_TMP}/proc/3001/cgroup"
echo '0::/.lxc' > "${DOWN_TMP}/proc/3101/cgroup"
echo '0::/.lxc' > "${DOWN_TMP}/proc/3201/cgroup"
cat > "${DOWN_TMP}/incus" <<'STUB3'
#!/usr/bin/env bash
case "$1" in
  list) echo "xpf-mouse-target,${FAKE_TARGET_IP:?}"; exit 0 ;;
  exec)
    shift 2
    while [[ "${1:-}" != "--" && $# -gt 0 ]]; do shift; done
    shift
    if [[ "${1:-}" == bash && "${2:-}" == -c ]]; then
      script="${3:-}"
      script="${script//\/proc\//${FAKE_PROC_ROOT}/}"
      FAKE_LOG="$FAKE_LOG" FAKE_SYSTEMD="${FAKE_SYSTEMD:-1}" \
        FAKE_CGROUP_MISSING="${FAKE_CGROUP_MISSING:-0}" \
        FAKE_FAILED_IPERF="${FAKE_FAILED_IPERF:-0}" \
        FAKE_METADATA_FAIL="${FAKE_METADATA_FAIL:-0}" \
        BASH_ENV="${FAKE_KILL_ENV}" PATH="${FAKE_BIN}:${PATH}" bash -c "$script"
      exit $?
    fi
    exit 0 ;;
esac
exit 0
STUB3
chmod +x "${DOWN_TMP}/incus"
cp "$SUBJECT" "${DOWN_TMP}/target-services.sh"
run_down() {
    local target="$1" alias="$2" systemd="$3" \
        cgroup_missing="${4:-0}" failed_iperf="${5:-0}" metadata_fail="${6:-0}"
    : > "$FAKE_LOG"
    env PATH="${DOWN_TMP}:${PATH}" FAKE_BIN="${DOWN_TMP}/bin" \
        FAKE_KILL_ENV="${DOWN_TMP}/bin/kill" FAKE_PROC_ROOT="${DOWN_TMP}/proc" \
        FAKE_LOG="$FAKE_LOG" \
        FAKE_TARGET_IP="$target" FAKE_SYSTEMD="$systemd" \
        FAKE_CGROUP_MISSING="$cgroup_missing" \
        FAKE_FAILED_IPERF="$failed_iperf" \
        FAKE_METADATA_FAIL="$metadata_fail" \
        TARGET_V4="$target" TARGET_ALIAS_V4="$alias" \
        MOUSE_TARGET_V4=172.16.80.201 INCUS_REMOTE=loss \
        bash "${DOWN_TMP}/target-services.sh" down 2>&1
}

# The alias-owned target has systemd units. An iperf3 -s -D orphan and an
# orphan TCP echo owner are killed; each service's MainPID and cgroup child
# are spared. A self-matched shell would fail to reach ss on 6201 or the stop.
down_out="$(run_down 172.16.80.202 172.16.80.202 1)"; down_rc=$?
[[ $down_rc -eq 0 ]] || fail "#18626: alias down rc=$down_rc (possible pkill self-match): $down_out"
grep -q "stopped target services" <<< "$down_out" \
    || fail "#18626: alias down did not finish after orphan sweep: $down_out"
grep -q '^kill .*146115$' "$FAKE_LOG" \
    || fail "#18626: default-port iperf3 -s -D orphan 146115 was not killed: $(cat "$FAKE_LOG")"
grep -q '^kill .*3101$' "$FAKE_LOG" \
    || fail "#18626: echo listener orphan 3101 was not killed / second sweep did not run: $(cat "$FAKE_LOG")"
grep -q '^kill .*3201$' "$FAKE_LOG" \
    || fail "#18626: quote-comma comm owner 3201 was not killed (name-carried pid text must not hide the owner): $(cat "$FAKE_LOG")"
grep -q '^ss 6201$' "$FAKE_LOG" \
    || fail "#18626: echo listener port was not inspected (self-matched shell?): $(cat "$FAKE_LOG")"
grep -q '^systemctl stop ' "$FAKE_LOG" \
    || fail "#18626: systemd units were not stopped: $(cat "$FAKE_LOG")"

if ! awk '
    /^ss 6201$/ { echo_sweep = NR }
    /^systemctl stop / { stop_units = NR }
    END { exit !(echo_sweep && stop_units > echo_sweep) }
' "$FAKE_LOG"; then
    fail "#18626: systemd stop ran before the echo orphan sweep: $(cat "$FAKE_LOG")"
fi

if grep -Eq '^kill .* (2002|2003|3000|3001)$' "$FAKE_LOG"; then
    fail "#18626: killed a listener in its unit MainPID/cgroup: $(cat "$FAKE_LOG")"
fi
# A failed mouse unit reports MainPID=0 and no ControlGroup. Its detached
# default-port iperf3 orphan must still be removed by the alias branch.
down_out="$(run_down 172.16.80.202 172.16.80.202 1 0 1)"; down_rc=$?
[[ $down_rc -eq 0 ]] || fail "#18626: failed-unit alias down rc=$down_rc: $down_out"
grep -q '^kill .*146115$' "$FAKE_LOG" \
    || fail "#18626: failed mouse-iperf3 unit left default-port orphan 146115: $(cat "$FAKE_LOG")"
grep -q '^kill .*3101$' "$FAKE_LOG" \
    || fail "#18626: failed-unit alias down skipped the echo orphan: $(cat "$FAKE_LOG")"
if ! awk '
    /^ss 6201$/ { echo_sweep = NR }
    /^systemctl stop / { stop_units = NR }
    END { exit !(echo_sweep && stop_units > echo_sweep) }
' "$FAKE_LOG"; then
    fail "#18626: failed-unit systemd stop ran before the echo sweep: $(cat "$FAKE_LOG")"
fi

# A failed systemd metadata query cannot establish who owns an active unit's
# socket. Preserve every iperf socket PID while still completing the echo sweep.
down_out="$(run_down 172.16.80.202 172.16.80.202 1 0 0 1)"; down_rc=$?
[[ $down_rc -eq 0 ]] || fail "#18626: metadata-failure down rc=$down_rc: $down_out"
grep -q '^ss 5201$' "$FAKE_LOG" \
    || fail "#18626: metadata-failure case did not inspect the active iperf socket: $(cat "$FAKE_LOG")"
grep -Fq 'systemctl show -p MainPID --value mouse-iperf3@5201.service' "$FAKE_LOG" \
    || fail "#18626: metadata-failure case skipped the MainPID query: $(cat "$FAKE_LOG")"
grep -Fq 'systemctl show -p ControlGroup --value mouse-iperf3@5201.service' "$FAKE_LOG" \
    || fail "#18626: metadata-failure case skipped the ControlGroup query: $(cat "$FAKE_LOG")"
if grep -Eq '^kill .* (146115|2002|2003)$' "$FAKE_LOG"; then
    fail "#18626: killed an iperf socket PID after systemd metadata failed: $(cat "$FAKE_LOG")"
fi
grep -q '^kill .*3101$' "$FAKE_LOG" \
    || fail "#18626: metadata-failure case skipped the independently classified echo orphan: $(cat "$FAKE_LOG")"

# An active unit with no reported ControlGroup cannot safely classify any
# other socket PID on that port. Leave those PIDs alone, while continuing the
# echo sweep whose unit cgroup is available.
down_out="$(run_down 172.16.80.202 172.16.80.202 1 1)"; down_rc=$?
[[ $down_rc -eq 0 ]] || fail "#18626: missing-cgroup down rc=$down_rc: $down_out"
if grep -Eq '^kill .* (146115|2003)$' "$FAKE_LOG"; then
    fail "#18626: killed an iperf listener while its active unit cgroup was unavailable: $(cat "$FAKE_LOG")"
fi
grep -q '^kill .*3101$' "$FAKE_LOG" \
    || fail "#18626: missing-cgroup case skipped the independently classifiable echo orphan: $(cat "$FAKE_LOG")"
grep -q '^systemctl stop ' "$FAKE_LOG" \
    || fail "#18626: missing-cgroup case did not finish the unit stop: $(cat "$FAKE_LOG")"

# The non-alias target is provisioned without mouse systemd units; socket
# ownership still finds both orphan forms and the second sweep completes.
down_out="$(run_down 172.16.80.203 172.16.80.202 0)"; down_rc=$?
[[ $down_rc -eq 0 ]] || fail "#18626: generic down rc=$down_rc: $down_out"
grep -q '^kill .*146115$' "$FAKE_LOG" \
    || fail "#18626: generic down missed the default-port iperf orphan: $(cat "$FAKE_LOG")"
grep -q '^kill .*3101$' "$FAKE_LOG" \
    || fail "#18626: generic down missed the echo orphan / second sweep: $(cat "$FAKE_LOG")"
grep -q '^kill .*3201$' "$FAKE_LOG" \
    || fail "#18626: generic down missed the quote-comma comm owner 3201: $(cat "$FAKE_LOG")"
if grep -Eq '^kill .* 3999$' "$FAKE_LOG"; then
    fail "#18626: generic down signalled the name-carried decoy PID 3999: $(cat "$FAKE_LOG")"
fi
grep -q '^ss 6201$' "$FAKE_LOG" \
    || fail "#18626: generic down did not inspect echo listener port: $(cat "$FAKE_LOG")"
if grep -Eq '^[[:space:]]*pkill([[:space:]]|$)' "${DOWN_TMP}/target-services.sh"; then
    fail "#18626: down still invokes pkill -f and retains the self-match hazard"
fi
[[ $fails -eq 0 ]] && pass "#18626 down kills socket orphans, spares unit pids, completes"

# --- summary ------------------------------------------------------------
if [[ $fails -eq 0 ]]; then
    echo "target-services selftest: all checks passed"
    exit 0
fi
echo "target-services selftest: ${fails} check(s) FAILED" >&2
exit 1
