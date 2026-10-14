#!/usr/bin/env bash
#
# #11769 — hermetic self-test for test/incus/cos-gate1-small-four-alone.sh.
#
# The harness is a live-cluster GATE: the four small-class generators run
# on the shared loss cluster through `sg incus-admin`. Those measurement
# legs are LAB-ONLY and are deliberately NOT faked here. What CAN be
# exercised without a cluster is the verdict layer, driven end-to-end
# through the real script:
#
#   1. A healthy fixture table (each class at 100% of shape) exits 0 with
#      GATE1 PASS; the per-row %shape values are reduced from the fixture
#      iperf3 JSON by the harness's own embedded reducer.
#   2. One class below the 95% solo guarantee flips the verdict to FAIL
#      and the exit status to 1 — proving the gate can fail, so a pass
#      here means something.
#   3. The generator-health contract (#4240 V-2): a sender that crashes
#      leaves a non-zero .rc sidecar and must FAIL, not read as a pass.
#   4. The lab-only skip pattern: on a host with no incus, the harness
#      SKIPs (exit 77) with the reason instead of failing red — a missing
#      lab is not a Gate 1 regression.
#
# Hermetic: `incus` and `sg` are stubs on PATH answering fixture iperf3
# shapes from a scripted rate table. No cluster, no network, no build.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUBJECT="${SCRIPT_DIR}/cos-gate1-small-four-alone.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fails=0

fail() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }
pass() { echo "ok: $*"; }

# --- the stubs ----------------------------------------------------------
mkdir -p "${TMP}/bin"
cat > "${TMP}/bin/sg" <<'STUB_SG'
#!/usr/bin/env bash
# minimal sg: <group> -c <command>
[ "$1" = "incus-admin" ] && [ "$2" = "-c" ] || exit 2
shift 2
exec bash -c "$*"
STUB_SG
chmod +x "${TMP}/bin/sg"

# Stub incus: answer `exec <host> -- iperf3 ... -p <port>` from the
# $MOCK_GBPS rate table (port:gbps per line); a port listed in $MOCK_DEAD
# crashes its generator (exit 1, no JSON).
cat > "${TMP}/bin/incus" <<'STUB_INCUS'
#!/usr/bin/env bash
[ "$1" = "exec" ] || exit 0
shift
HOST="$1"; shift
[ "$1" = "--" ] && shift
[ "$1" = "iperf3" ] || exit 0
shift
port=5201; streams=12
while [ $# -gt 0 ]; do
  case "$1" in
    -p) port="$2"; shift 2 ;;
    -P) streams="$2"; shift 2 ;;
    *) shift ;;
  esac
done
for dead in ${MOCK_DEAD}; do
  [ "$dead" = "$port" ] && exit 1
done
gbps="$(awk -F: -v p="$port" '$1==p {print $2}' "${MOCK_GBPS:-/dev/null}" 2>/dev/null)"
[ -n "$gbps" ] || gbps=1
python3 - "$port" "$streams" "$gbps" <<'PY'
import json, sys
port, streams, gbps = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3])
total = gbps * 1e9
per = total / max(streams, 1)
print(json.dumps({
    "end": {
        "streams": [{"sender": {"bits_per_second": per, "retransmits": 0}} for _ in range(streams)],
        "sum_sent": {"bits_per_second": total, "retransmits": 0},
        "sum_received": {"bits_per_second": total, "retransmits": 0},
    },
}))
PY
exit 0
STUB_INCUS
chmod +x "${TMP}/bin/incus"

# Healthy table: all four small classes at their full shape.
HEALTHY="${TMP}/rates-healthy.txt"
cat > "$HEALTHY" <<'RATES'
5201:0.1
5202:1.0
5203:3.0
5204:6.0
RATES

# Sagging table: the 3g class at 90% of shape, below the 95% guarantee.
SAGGING="${TMP}/rates-sagging.txt"
awk -F: 'BEGIN{OFS=":"} $1==5203{$2=2.7} {print}' "$HEALTHY" > "$SAGGING"

run_subject() { # run_subject <out-prefix> [args...] — echoes rc
  local out="$1"; shift
  MOCK_GBPS="${MOCK_GBPS:-$HEALTHY}" \
  MOCK_DEAD="${MOCK_DEAD:-}" \
  PATH="${TMP}/bin:$PATH" \
  DURATION=2 ART="${TMP}/art-$out" \
  bash "$SUBJECT" "$@" > "${TMP}/out-$out.txt" 2>&1
  echo $?
}

# --- 1. healthy: GATE1 PASS ------------------------------------------------
rc="$(run_subject healthy push v4)"
if [[ "$rc" = "0" ]] && grep -q "GATE1 PASS" "${TMP}/out-healthy.txt"; then
  pass "healthy table exits 0 with GATE1 PASS"
else
  fail "healthy table must exit 0 with GATE1 PASS; got rc=$rc
$(cat "${TMP}/out-healthy.txt")"
fi

# --- 2. one class at 90%: GATE1 FAIL names the class -----------------------
MOCK_GBPS="$SAGGING"
rc="$(run_subject sagging push v4)"
if [[ "$rc" = "1" ]] && grep -q "GATE1 FAIL" "${TMP}/out-sagging.txt" \
  && grep -q "iperf-3g" "${TMP}/out-sagging.txt"; then
  pass "3g class at 90% of shape fails GATE1 naming the class"
else
  fail "a 90%-of-shape class must exit 1 naming iperf-3g; got rc=$rc
$(cat "${TMP}/out-sagging.txt")"
fi
MOCK_GBPS="$HEALTHY"

# --- 3. crashed generator: FAIL, not a silent pass (#4240 V-2) --------------
MOCK_DEAD="5202"
rc="$(run_subject dead push v4)"
if [[ "$rc" = "1" ]] && grep -q "ERR generator rc=1" "${TMP}/out-dead.txt"; then
  pass "crashed generator reports ERR and fails the gate"
else
  fail "a crashed generator must fail the gate with ERR generator rc; got rc=$rc
$(cat "${TMP}/out-dead.txt")"
fi
MOCK_DEAD=""

# --- 4. lab-only legs: no incus → SKIP 77 with the reason -------------------
mkdir -p "${TMP}/nocluster"
# A PATH carrying only the interpreter/path tools the script needs to
# REACH its own preflight — and no incus.
for b in bash sh dirname mkdir date; do
  ln -sf "$(command -v "$b")" "${TMP}/nocluster/$b"
done
PATH="${TMP}/nocluster" \
  DURATION=2 ART="${TMP}/art-skip" \
  bash "$SUBJECT" push v4 > "${TMP}/out-skip.txt" 2>&1
rc=$?
if [[ "$rc" = "77" ]] && grep -q "SKIP: incus not found" "${TMP}/out-skip.txt" \
  && grep -q "lab-only (#11769)" "${TMP}/out-skip.txt"; then
  pass "no-incus host SKIPs (exit 77) with the lab-only reason"
else
  fail "no-incus host must SKIP 77 with the lab-only reason; got rc=$rc
$(cat "${TMP}/out-skip.txt")"
fi

# --- summary --------------------------------------------------------------
if [[ $fails -eq 0 ]]; then
  echo "cos-gate1-small-four-alone-selftest: all checks passed"
  exit 0
fi
echo "cos-gate1-small-four-alone-selftest: ${fails} check(s) FAILED" >&2
exit 1
