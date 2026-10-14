#!/usr/bin/env bash
#
# #11769 — hermetic self-test for test/incus/cos-be-contention-harness.sh.
#
# The harness is a live-cluster GATE: its four cells drive exact and
# best-effort/uncapped traffic through the shared loss cluster and read
# the running dataplane's DrainShape counters. Those measurement legs are
# LAB-ONLY and are deliberately NOT faked here — nothing in this file
# claims a throughput number about real hardware. What CAN be exercised
# without a cluster is the whole capture/validation pipeline, driven
# end-to-end through the real script:
#
#   1. A scripted `incus` answers the #8040 target-service precheck, the
#      active-firewall detection, the before/during/after status captures
#      (with a STATEFUL counter table so only queues whose generator is
#      currently running drain) and the iperf3 launches (fixture JSON).
#      The REAL cos_be_contention_validate.py then reduces the artifacts
#      and all four cells must PASS — proving the harness wires phases,
#      roles and artifacts together correctly.
#   2. A contended table where the exact class collapses under its
#      contender must FAIL — proving the gate can fail, so a pass means
#      something.
#   3. The lab-only skip pattern: on a host with no incus, the harness
#      SKIPs (exit 77) with the reason BEFORE the #8040 precheck spends
#      anything — a missing lab is not an exact-queue regression.
#
# Statefulness note: register/unregister of running generators and the
# per-capture counter bump are serialized with flock, because a contended
# phase runs two concurrent generators whose read-modify-write cycles
# otherwise clobber each other and leak an "active" port into the next
# cell (which the validator would then rightly flag as wrong-queue
# drain).
#
# Hermetic: no cluster, no network, no build. USE_SG_INCUS_ADMIN=0 (the
# harness's own knob) keeps the stub incus directly on PATH.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUBJECT="${SCRIPT_DIR}/cos-be-contention-harness.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fails=0

fail() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }
pass() { echo "ok: $*"; }

STATE="${TMP}/state"
mkdir -p "${STATE}"
BIN="${TMP}/bin"
mkdir -p "${BIN}"

# Queue table: qid <TAB> forwarding-class <TAB> sent_bytes root park.
# Base counters are non-zero so deltas, not absolutes, are what validate.
printf '0\tbest-effort\t1000\t10\t10\n2\tiperf-1g\t2000\t30\t30\n10\tiperf-24g\t3000\t50\t50\n11\tiperf-uncapped\t4000\t70\t70\n' \
  > "${STATE}/queues.tsv"
: > "${STATE}/active"

# --- the stateful stub incus ---------------------------------------------
cat > "${BIN}/incus" <<'STUB_INCUS'
#!/usr/bin/env bash
# Stateful incus stub. Registers a generator's port for the run duration
# so status captures taken mid-phase see only that queue draining.
STATE="${BE_MOCK_STATE:?BE_MOCK_STATE must be set}"
log() { printf '%s\n' "$*" >> "${STATE}/incus.log"; }
log "INCUS: $*"

PORT_QUEUE=(5200:0 5202:2 5210:10 5211:11)

register_port() {
  ( flock 9; echo "$1" >> "$STATE/active" ) 9>"${STATE}/lock"
}
unregister_port() {
  (
    flock 9
    grep -vx "$1" "$STATE/active" > "${STATE}/active.new" || true
    mv "${STATE}/active.new" "$STATE/active"
  ) 9>"${STATE}/lock"
}

bump_active_queues() {
  # Each status read adds 5000 sent bytes to every queue whose generator
  # is currently registered as running — and nothing to any other queue,
  # which is the property the validator's wrong-queue tolerance (0)
  # checks.
  local qid fc sent root park pq port
  (
    flock 9
    : > "${STATE}/queues.new"
    while IFS=$'\t' read -r qid fc sent root park; do
      [[ -z "$qid" ]] && continue
      for pq in "${PORT_QUEUE[@]}"; do
        port="${pq%%:*}"
        if [[ "${pq#*:}" == "$qid" ]] && grep -qx "$port" "$STATE/active" 2>/dev/null; then
          sent=$((sent + 5000)); root=$((root + 10)); park=$((park + 10))
        fi
      done
      printf '%s\t%s\t%s\t%s\t%s\n' "$qid" "$fc" "$sent" "$root" "$park" >> "${STATE}/queues.new"
    done < "${STATE}/queues.tsv"
    mv "${STATE}/queues.new" "${STATE}/queues.tsv"
  ) 9>"${STATE}/lock"
}

emit_status() {
  bump_active_queues
  printf '{\n  "status": {\n    "cos_interfaces": [\n      {\n        "interface_name": "reth0.80",\n        "ifindex": 9,\n        "queues": [\n'
  local first=1
  while IFS=$'\t' read -r qid fc sent root park; do
    [[ -z "$qid" ]] && continue
    [[ $first -eq 0 ]] && printf ',\n'
    first=0
    printf '          {"queue_id": %s, "forwarding_class": "%s", "drain_sent_bytes": %s, "drain_park_root_tokens": %s, "drain_park_queue_tokens": %s}' \
      "$qid" "$fc" "$sent" "$root" "$park"
  done < "${STATE}/queues.tsv"
  printf '\n        ]\n      }\n    ]\n  }\n}\n'
}

emit_iperf() {
  local port="$1" par="$2" dur="$3"
  # Register FIRST, occupy the run duration, and reduce the rate table
  # only when the end-of-run summary is due (a real iperf3 prints its
  # end summary at the END of the test, so the harness reads it after the
  # generator finishes). $BE_MOCK_BPS is the solo table; once a SECOND
  # generator is registered the $BE_MOCK_CONTENDED_BPS table wins — the
  # contended phases run two at once, so this is how a cell scripts "the
  # exact class collapses only under contention" while its solo baseline
  # stays healthy.
  local rate table
  register_port "$port"
  sleep "$dur"
  table="${BE_MOCK_BPS:-}"
  if [ -s "${BE_MOCK_CONTENDED_BPS:-}" ] \
    && [ "$(grep -c . "${STATE}/active" 2>/dev/null || echo 0)" -ge 2 ]; then
    table="${BE_MOCK_CONTENDED_BPS}"
  fi
  rate="$(awk -v p="$port" 'BEGIN{FS=":"} $1==p {print $2}' "$table" 2>/dev/null)"
  case "$port" in
    5202) rate="${rate:-0.95e9}" ;;     # exact 1g near cap
    5210) rate="${rate:-22.8e9}" ;;    # exact 24g near cap
    5200|5211) rate="${rate:-23e9}" ;; # contenders saturate the root
    *) rate="${rate:-1e9}" ;;
  esac
  unregister_port "$port"
  python3 - "$port" "$par" "$rate" <<'PY'
import json, sys, time
port, par, rate = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3])
per = rate / max(par, 1)
now = int(time.time())
intervals = [{"streams": [{"socket": s, "start": float(i), "end": float(i + 1),
                           "bits_per_second": per} for s in range(par)],
              "sum": {"omitted": False}} for i in range(3)]
print(json.dumps({
    "start": {"connected": [{"socket": s, "remote_port": port} for s in range(par)],
              "timestamp": {"timesecs": now},
              "test_start": {"protocol": "TCP", "num_streams": par, "duration": 3, "reverse": 0}},
    "intervals": intervals,
    "end": {"streams": [{"socket": s, "sender": {"bits_per_second": per, "retransmits": 0}} for s in range(par)],
            "sum_sent": {"bits_per_second": rate, "retransmits": 0},
            "sum_received": {"bits_per_second": rate, "retransmits": 0},
            "sum": {"bits_per_second": rate, "retransmits": 0},
            "cpu_utilization_percent": {"host_total": 5.0}},
}))
PY
  exit 0
}

[ "$1" = "exec" ] || exit 0
shift
HOST="$1"; shift
[ "$1" = "--" ] && shift
cmd="$1"
case "$cmd" in
  mpstat) exit 0 ;;
  iperf3)
    shift
    port=5201; par=4; dur=2
    while [ $# -gt 0 ]; do
      case "$1" in
        -p) port="$2"; shift 2 ;;
        -P) par="$2"; shift 2 ;;
        -t) dur="$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    emit_iperf "$port" "$par" "$dur" ;;
  bash|sh)
    script="$3"
    case "$script" in
      *"/dev/tcp/"*)
        # target-services probe: every named port answers open.
        printf '%s\n' "$script" | grep -o 'for p in [0-9 ]*' | sed 's/for p in //' \
          | tr ' ' '\n' | while read -r p; do [ -n "$p" ] && echo "$p open"; done
        exit 0 ;;
      *"show chassis cluster data-plane statistics"*)
        printf 'Data plane statistics:\n    Enabled:            true\n    Forwarding supported: true\n    HA groups:          rg0 active=true rg1 active=true\n'
        exit 0 ;;
      *userspace-dp.json*)
        emit_status
        exit 0 ;;
      *iperf3*)
        # start_iperf's remote_cmd: timeout -k 2 N iperf3 ... -p P -P N -t D
        port="$(printf '%s\n' "$script" | grep -o '\-p [0-9]*' | head -1 | cut -d' ' -f2)"
        par="$(printf '%s\n' "$script" | grep -o '\-P [0-9]*' | head -1 | cut -d' ' -f2)"
        dur="$(printf '%s\n' "$script" | grep -o '\-t [0-9]*' | head -1 | cut -d' ' -f2)"
        emit_iperf "${port:-5202}" "${par:-4}" "${dur:-2}" ;;
      *) exit 0 ;;
    esac ;;
  *) exit 0 ;;
esac
STUB_INCUS
chmod +x "${BIN}/incus"

run_subject() { # run_subject <out-prefix> — echoes rc
  local out="$1"
  BE_MOCK_STATE="$STATE" \
  BE_MOCK_CONTENDED_BPS="${BE_MOCK_CONTENDED_BPS:-}" \
  USE_SG_INCUS_ADMIN=0 \
  APPLY_CONFIG=0 \
  DURATION=2 \
  DURING_CAPTURE_AFTER_SEC=1 \
  BETWEEN_PHASE_SLEEP_SEC=0 \
  ARTIFACT_ROOT="${TMP}/art-$out" \
  PATH="${BIN}:$PATH" \
  bash "$SUBJECT" > "${TMP}/out-$out.txt" 2>&1
  echo $?
}

# --- 1. healthy pipeline: all four cells PASS ------------------------------
rc="$(run_subject healthy)"
if [[ "$rc" = "0" ]] \
  && ! grep -q FAIL "${TMP}/art-healthy/summary.tsv" \
  && [ "$(wc -l < "${TMP}/art-healthy/summary.tsv")" -ge 5 ]; then
  pass "scripted cluster: all four cells reduce to PASS through the real validator"
else
  fail "healthy scripted run must exit 0 with four PASS cells; got rc=$rc
$(cut -f1,5,16 "${TMP}/art-healthy/summary.tsv" 2>/dev/null)
$(sed -n '1,15p' "${TMP}/out-healthy.txt")"
fi

# The stateful counter property is load-bearing: only queues whose
# generator ran during a phase may show a drain delta. The validator
# checks it with tolerance 0, and a leaked "active" port would fail cell
# 2+ — so the four-PASS result above is also the no-leak proof.

# --- 2. exact collapse under contention: FAIL -------------------------------
# The 1g exact class delivers only 50 Mbps while contended — a 94.7% drop
# from its 950 Mbps baseline, far beyond the 15% allowance.
COLLAPSE="${TMP}/collapse.bps"
printf '5202:50e6\n' > "$COLLAPSE"
BE_MOCK_CONTENDED_BPS="$COLLAPSE"
rc="$(run_subject collapse)"
if [[ "$rc" = "1" ]] \
  && grep -q "exact throughput dropped" "${TMP}/art-collapse/summary.tsv"; then
  pass "collapsed exact class fails the drop-ratio contract"
else
  fail "a collapsed exact class must exit 1 naming the throughput drop; got rc=$rc
$(cut -f1,5,16 "${TMP}/art-collapse/summary.tsv" 2>/dev/null)
$(sed -n '1,15p' "${TMP}/out-collapse.txt")"
fi
BE_MOCK_CONTENDED_BPS=""

# --- 3. lab-only legs: no incus → SKIP 77 before the precheck ---------------
mkdir -p "${TMP}/nocluster"
for b in bash sh dirname mkdir date cat grep sed; do
  ln -sf "$(command -v "$b")" "${TMP}/nocluster/$b"
done
BE_MOCK_STATE="$STATE" \
  USE_SG_INCUS_ADMIN=0 \
  APPLY_CONFIG=0 \
  ARTIFACT_ROOT="${TMP}/art-skip" \
  PATH="${TMP}/nocluster" \
  bash "$SUBJECT" > "${TMP}/out-skip.txt" 2>&1
rc=$?
if [[ "$rc" = "77" ]] && grep -q "SKIP: incus not found" "${TMP}/out-skip.txt" \
  && grep -q "lab-only (#11769)" "${TMP}/out-skip.txt"; then
  pass "no-incus host SKIPs (exit 77) with the lab-only reason, before the precheck"
else
  fail "no-incus host must SKIP 77 with the lab-only reason; got rc=$rc
$(cat "${TMP}/out-skip.txt")"
fi

# --- summary ----------------------------------------------------------------
if [[ $fails -eq 0 ]]; then
  echo "cos-be-contention-harness-selftest: all checks passed"
  exit 0
fi
echo "cos-be-contention-harness-selftest: ${fails} check(s) FAILED" >&2
exit 1
