#!/usr/bin/env bash
#
# #11769 — hermetic self-test for test/incus/cos-simul-load-smoke.sh.
#
# The harness is a live-cluster GATE: all eleven generators run on the
# shared loss cluster through `sg incus-admin`. Those measurement legs are
# LAB-ONLY and are deliberately NOT faked here. What CAN be exercised
# without a cluster is everything else, and that is what this self-test
# drives end-to-end through the real script:
#
#   1. The verdict layer: eleven fixture iperf3 transcripts are reduced by
#      the harness's own embedded reducer (gate_0 generator health, gate_1
#      divided-ceiling floors, gate_2 priority-low share, gate_3 retrans,
#      gate_8 reverse aggregate) and the verdict propagates as the exit
#      status. Both directions are pinned: a healthy table exits 0, and a
#      starved small class flips gate_1 — proving the gate can fail and is
#      not a vacuous green.
#   2. The generator-health contract (#4239 V-1): a sender that crashes
#      (non-zero .rc) must fail gate_0 BY NAME, not read as a silent pass.
#   3. The lab-only skip pattern: on a host with no incus, the harness
#      SKIPs (exit 77) with the reason instead of failing red — a missing
#      lab is not a CoS regression.
#
# Hermetic: `incus` and `sg` are stubs on PATH answering fixture iperf3 and
# mpstat shapes. No cluster, no network, no build.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUBJECT="${SCRIPT_DIR}/cos-simul-load-smoke.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fails=0

fail() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }
pass() { echo "ok: $*"; }

# --- the stubs ----------------------------------------------------------
# Stub sg: run the command directly; the group check is not under test
# here (the lab-only skip cell below covers the no-incus path, and the
# harness's own `sg incus-admin -c true` preflight probe succeeds against
# this stub on hosts that lack the real group, so the self-test is not
# lab-host-only itself).
mkdir -p "${TMP}/bin"
cat > "${TMP}/bin/sg" <<'STUB_SG'
#!/usr/bin/env bash
# minimal sg: <group> -c <command>
[ "$1" = "incus-admin" ] && [ "$2" = "-c" ] || exit 2
shift 2
exec bash -c "$*"
STUB_SG
chmod +x "${TMP}/bin/sg"

# Stub incus: answer `exec <host> -- mpstat ...` and `exec <host> --
# iperf3 ... -p <port> ...` from a scripted rate table. The table lives in
# $MOCK_GBPS (port:gbps per line, default = each class at its full shape);
# a port listed in $MOCK_DEAD crashes its generator (exit 1, no JSON).
cat > "${TMP}/bin/incus" <<'STUB_INCUS'
#!/usr/bin/env bash
log() { printf '%s\n' "$*" >> "${MOCK_LOG:-/dev/null}"; }
log "INCUS: $*"
[ "$1" = "exec" ] || exit 0
shift
HOST="$1"; shift
[ "$1" = "--" ] && shift
if [ "$1" = "mpstat" ]; then
  printf 'avg-cpu:  %%user %%nice %%system %%iowait %%steal %%idle\n         2.0   0.0    3.0      0.0    0.0   95.0\n'
  exit 0
fi
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
gbps="$(awk -F: -v p="$port" '$1==p {print $2}' "${MOCK_GBPS:-/dev/null}" 2>/dev/null)"
for dead in ${MOCK_DEAD}; do
  [ "$dead" = "$port" ] && exit 1
done
[ -n "$gbps" ] || gbps=1
python3 - "$port" "$streams" "$gbps" <<'PY'
import json, sys
port, streams, gbps = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3])
total = gbps * 1e9
per = total / max(streams, 1)
streams_out = [{"sender": {"bits_per_second": per, "retransmits": 0}} for _ in range(streams)]
print(json.dumps({
    "end": {
        "streams": streams_out,
        "sum_sent": {"bits_per_second": total, "retransmits": 0},
        "sum_received": {"bits_per_second": total, "retransmits": 0},
    },
}))
PY
exit 0
STUB_INCUS
chmod +x "${TMP}/bin/incus"

# Healthy table: every class at its full shape (uncapped 5210... 5211 at
# 10G so gate_2's 0.9G floor is exceeded without tripping anything else).
HEALTHY="${TMP}/rates-healthy.txt"
cat > "$HEALTHY" <<'RATES'
5201:0.1
5202:1.0
5203:3.0
5204:6.0
5205:9.0
5206:12.0
5207:15.0
5208:18.0
5209:21.0
5210:24.0
5211:10.0
RATES

# Starved table: the 1g class delivers 10% of shape, below its 40%
# divided-ceiling floor.
STARVED="${TMP}/rates-starved.txt"
awk -F: 'BEGIN{OFS=":"} $1==5202{$2=0.1} {print}' "$HEALTHY" > "$STARVED"

run_subject() { # run_subject <out-prefix> [args...] — echoes rc
  local out="$1"; shift
  MOCK_GBPS="${MOCK_GBPS:-$HEALTHY}" \
  MOCK_DEAD="${MOCK_DEAD:-}" \
  MOCK_LOG="${TMP}/incus.log" \
  PATH="${TMP}/bin:$PATH" \
  DURATION=2 ART="${TMP}/art-$out" \
  bash "$SUBJECT" "$@" > "${TMP}/out-$out.txt" 2>&1
  echo $?
}

# --- 1. healthy push: all gates pass ------------------------------------
MOCK_GBPS="$HEALTHY"
rc="$(run_subject push push)"
if [[ "$rc" = "0" ]] && grep -q "PASS: all gates satisfied" "${TMP}/out-push.txt"; then
  pass "healthy push table exits 0 with PASS verdict"
else
  fail "healthy push table must exit 0; got rc=$rc
$(sed -n '1,20p' "${TMP}/out-push.txt")"
fi
if python3 -c "import json,sys; d=json.load(open('${TMP}/art-push/verdict.json')); sys.exit(0 if all((g['pass'] if isinstance(g,dict) else g) for g in d['gates'].values()) else 1)" 2>/dev/null; then
  pass "verdict.json written with every gate true"
else
  fail "verdict.json missing or has a failing gate"
fi

# --- 2. starved small class: gate_1 must flip ---------------------------
MOCK_GBPS="$STARVED"
rc="$(run_subject starved push)"
if [[ "$rc" = "1" ]] && grep -q "gate_1_small_class_divided_ceiling_floor" "${TMP}/out-starved.txt"; then
  pass "starved 1g class fails gate_1 and the harness exits 1"
else
  fail "starved 1g class must exit 1 naming gate_1; got rc=$rc
$(sed -n '1,25p' "${TMP}/out-starved.txt")"
fi
MOCK_GBPS="$HEALTHY"

# --- 3. crashed generator: gate_0 names the port (#4239 V-1) -------------
MOCK_DEAD="5207"
rc="$(run_subject dead push)"
if [[ "$rc" = "1" ]] && grep -q "gate_0_generators_healthy" "${TMP}/out-dead.txt" \
  && grep -q "5207" "${TMP}/out-dead.txt"; then
  pass "crashed generator fails gate_0 naming port 5207"
else
  fail "a dead generator must exit 1 via gate_0 naming the port; got rc=$rc
$(sed -n '1,25p' "${TMP}/out-dead.txt")"
fi
MOCK_DEAD=""

# --- 4. reverse: aggregate >= 22G passes, below fails --------------------
rc="$(run_subject rev reverse)"
if [[ "$rc" = "0" ]] && grep -q "gate_8_reverse_simul_22g" "${TMP}/out-rev.txt"; then
  pass "healthy reverse run passes gate_8"
else
  fail "healthy reverse run must exit 0 via gate_8; got rc=$rc
$(sed -n '1,25p' "${TMP}/out-rev.txt")"
fi
WEAK="${TMP}/rates-weak-reverse.txt"
awk -F: 'BEGIN{OFS=":"} {print $1, $2*0.1}' "$HEALTHY" > "$WEAK"
MOCK_GBPS="$WEAK"
rc="$(run_subject weakrev reverse)"
if [[ "$rc" = "1" ]] && grep -q "gate_8_reverse_simul_22g" "${TMP}/out-weakrev.txt"; then
  pass "sub-22G reverse aggregate fails gate_8"
else
  fail "a sub-22G reverse aggregate must exit 1 via gate_8; got rc=$rc
$(sed -n '1,25p' "${TMP}/out-weakrev.txt")"
fi
MOCK_GBPS="$HEALTHY"

# --- 5. lab-only legs: no incus → SKIP 77 with the reason -----------------
mkdir -p "${TMP}/nocluster"
# A PATH carrying only the interpreter/path tools the script needs to
# REACH its own preflight — and no incus.
for b in bash sh dirname mkdir date; do
  ln -sf "$(command -v "$b")" "${TMP}/nocluster/$b"
done
MOCK_GBPS="" MOCK_LOG="${TMP}/incus.log" \
  DURATION=2 ART="${TMP}/art-skip" \
  PATH="${TMP}/nocluster" \
  bash "$SUBJECT" push > "${TMP}/out-skip.txt" 2>&1
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
  echo "cos-simul-load-smoke-selftest: all checks passed"
  exit 0
fi
echo "cos-simul-load-smoke-selftest: ${fails} check(s) FAILED" >&2
exit 1
