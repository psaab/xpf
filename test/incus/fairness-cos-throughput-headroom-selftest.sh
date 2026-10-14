#!/usr/bin/env bash
#
# #11769 — hermetic self-test for test/incus/fairness-cos-throughput-headroom.sh.
#
# The harness is a live-cluster GATE: both scenarios apply CoS fixtures to
# the shared loss cluster (through apply-cos-config.sh and the cluster
# lock) and measure it through fairness-cos-class-sweep.sh. Those
# measurement legs are LAB-ONLY and are deliberately NOT faked here. What
# CAN be exercised without a cluster is the ORCHESTRATION layer, driven
# end-to-end through the real script with a scripted sweep and apply:
#
#   1. Scenario sequencing: strict runs first, surplus-sharing second,
#      each through the sweep, and the strict fixture is RESTORED after
#      the diagnostic comparison (the leave-it-as-you-found-it contract).
#      The apply stub records every invocation, so the exact call
#      sequence — including the --symmetric direction flag the reverse
#      sweep requires (#1250) and --surplus-sharing only on the diagnostic
#      arm — is asserted, not assumed.
#   2. Aggregation: both scenarios' rows land in one summary.tsv with the
#      scenario in column 1, and summary.md renders the comparison table.
#   3. Verdict propagation: a sweep that FAILs its class must make the
#      whole comparison exit 1 even when the other scenario passes.
#   4. An apply that fails on the surplus arm must surface as a nonzero
#      exit with an ERROR row, and the strict fixture must STILL be
#      restored on the way out.
#   5. The lab-only skip pattern: with APPLY_CONFIG enabled (the default)
#      a host with no incus SKIPs (exit 77) with the reason instead of
#      failing mid-comparison.
#
# Hermetic: no cluster, no network, no build. The sweep and apply stubs
# live in a private PATH dir; no incus is ever invoked.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUBJECT="${SCRIPT_DIR}/fairness-cos-throughput-headroom.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fails=0
fail() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }
pass() { echo "ok: $*"; }

mkdir -p "${TMP}/bin"

# --- stub sweep: writes one class row and exits as scripted ----------------
cat > "${TMP}/bin/fairness-cos-class-sweep" <<'STUB_SWEEP'
#!/usr/bin/env bash
# Stand-in for fairness-cos-class-sweep.sh. ARTIFACT_ROOT is set by the
# harness; verdict/exit are scripted through the env so the FAIL cell can
# flip one scenario without touching the other.
mkdir -p "${ARTIFACT_ROOT:?}"
printf 'class\tport\tqueue_id\trate_bps\texit_status\tverdict\tmean_observed_cov\tmax_observed_cov\tstdev_observed_cov\tavg_mbps\tavg_rate_utilization\tavg_cstruct\tmean_gap\tmax_gap\tstarved_flows\tper_run_verdicts\n' > "${ARTIFACT_ROOT}/summary.tsv"
printf 'q2-iperf-1g\t5202\t2\t1000000000\t%s\t%s\t0.0\t0.0\t0.0\t1000\t1\t0.0\t%s\t%s\t0\tPASS\n' \
  "${SWEEP_EXIT:-0}" "${SWEEP_VERDICT:-PASS}" "${SWEEP_GAP:-0.0}" "${SWEEP_GAP:-0.0}" \
  >> "${ARTIFACT_ROOT}/summary.tsv"
echo "stub sweep wrote ${ARTIFACT_ROOT}/summary.tsv"
exit "${SWEEP_EXIT:-0}"
STUB_SWEEP
chmod +x "${TMP}/bin/fairness-cos-class-sweep"

# --- stub apply: records argv; can be scripted to fail on surplus ----------
cat > "${TMP}/bin/apply-cos-config" <<'STUB_APPLY'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${APPLY_LOG:?APPLY_LOG must be set}"
for arg in "$@"; do
  if [ "$arg" = "--surplus-sharing" ] && [ "${APPLY_SURPLUS_RC:-0}" != "0" ]; then
    exit "${APPLY_SURPLUS_RC}"
  fi
done
exit 0
STUB_APPLY
chmod +x "${TMP}/bin/apply-cos-config"

run_subject() { # run_subject <out-prefix> — echoes rc
  local out="$1"
  SWEEP="${TMP}/bin/fairness-cos-class-sweep" \
  APPLY_COS_CONFIG="${TMP}/bin/apply-cos-config" \
  APPLY_LOG="${TMP}/apply-$out.log" \
  ARTIFACT_ROOT="${TMP}/art-$out" \
  TARGET_VM="fake:vm" \
  PATH="${TMP}/bin:$PATH" \
  bash "$SUBJECT" > "${TMP}/out-$out.txt" 2>&1
  echo $?
}

# --- 1. sequencing + restore + aggregation ---------------------------------
rc="$(run_subject happy)"
apply_log="$(cat "${TMP}/apply-happy.log" 2>/dev/null)"
if [[ "$rc" = "0" ]] && grep -q "fairness-cos-throughput-headroom: wrote" "${TMP}/out-happy.txt"; then
  pass "healthy scripted comparison exits 0"
else
  fail "healthy scripted comparison must exit 0; got rc=$rc
$(cat "${TMP}/out-happy.txt")"
fi
n_apply="$(wc -l < "${TMP}/apply-happy.log" 2>/dev/null || echo 0)"
if [[ "$n_apply" = "3" ]] \
  && sed -n '1p' <<<"$apply_log" | grep -q -- "--symmetric fake:vm" \
  && ! sed -n '1p' <<<"$apply_log" | grep -q -- "--surplus-sharing" \
  && sed -n '2p' <<<"$apply_log" | grep -q -- "--symmetric --surplus-sharing fake:vm" \
  && sed -n '3p' <<<"$apply_log" | grep -q -- "--symmetric fake:vm" \
  && ! sed -n '3p' <<<"$apply_log" | grep -q -- "--surplus-sharing"; then
  pass "apply sequence is strict → surplus-sharing → strict restore, all --symmetric"
else
  fail "the apply call sequence must be strict, surplus, strict-restore with --symmetric; got (${n_apply} calls):
${apply_log}"
fi
rows="$(tail -n +2 "${TMP}/art-happy/summary.tsv" 2>/dev/null)"
if [ "$(wc -l <<<"$rows")" = "2" ] \
  && awk -F'\t' 'NR==1 && $1=="strict" && $7=="PASS" {next}
                 NR==2 && $1=="surplus-sharing" && $7=="PASS" {next}
                 {bad=1} END{exit bad}' <<<"$rows"; then
  pass "both scenarios aggregate into summary.tsv with the scenario column"
else
  fail "summary.tsv must carry one PASS row per scenario; got:
${rows}"
fi
if grep -q "^| strict | q2-iperf-1g | 2 | PASS |" "${TMP}/art-happy/summary.md" 2>/dev/null \
  && grep -q "^| surplus-sharing | q2-iperf-1g | 2 | PASS |" "${TMP}/art-happy/summary.md" 2>/dev/null; then
  pass "summary.md renders the strict-vs-surplus comparison table"
else
  fail "summary.md must render a row per scenario; got:
$(sed -n '1,12p' "${TMP}/art-happy/summary.md" 2>/dev/null)"
fi

# --- 2. sweep FAIL on the strict arm propagates -----------------------------
# SWEEP_FAIL_SCENARIO selects which scenario's stub sweep run fails.
cat > "${TMP}/bin/fairness-cos-class-sweep" <<'STUB_SWEEP2'
#!/usr/bin/env bash
mkdir -p "${ARTIFACT_ROOT:?}"
printf 'class\tport\tqueue_id\trate_bps\texit_status\tverdict\tmean_observed_cov\tmax_observed_cov\tstdev_observed_cov\tavg_mbps\tavg_rate_utilization\tavg_cstruct\tmean_gap\tmax_gap\tstarved_flows\tper_run_verdicts\n' > "${ARTIFACT_ROOT}/summary.tsv"
scenario=pass
if [ -n "${SWEEP_FAIL_SCENARIO:-}" ] \
  && [ "${ARTIFACT_ROOT%/sweep}" = "${SWEEP_FAIL_SCENARIO}" ]; then
  scenario=fail
fi
if [ "$scenario" = "fail" ]; then
  printf 'q2-iperf-1g\t5202\t2\t1000000000\t1\tFAIL\t0.0\t0.0\t0.0\t400\t0.4\t0.0\t0.6\t0.7\t0\tFAIL,FAIL\n' >> "${ARTIFACT_ROOT}/summary.tsv"
  exit 1
fi
printf 'q2-iperf-1g\t5202\t2\t1000000000\t0\tPASS\t0.0\t0.0\t0.0\t1000\t1\t0.0\t0.0\t0.0\t0\tPASS\n' >> "${ARTIFACT_ROOT}/summary.tsv"
exit 0
STUB_SWEEP2
chmod +x "${TMP}/bin/fairness-cos-class-sweep"
export SWEEP_FAIL_SCENARIO="${TMP}/art-failstrict/strict"
rc="$(run_subject failstrict)"
if [[ "$rc" = "1" ]] \
  && grep -q "^strict	q2-iperf-1g	5202	2	1000000000	1	FAIL" "${TMP}/art-failstrict/summary.tsv" \
  && grep -q "^surplus-sharing	q2-iperf-1g	5202	2	1000000000	0	PASS" "${TMP}/art-failstrict/summary.tsv"; then
  pass "strict-arm sweep FAIL propagates to exit 1 while surplus still runs"
else
  fail "a failing strict sweep must exit 1 with both rows present; got rc=$rc
$(tail -n +2 "${TMP}/art-failstrict/summary.tsv" 2>/dev/null)
$(sed -n '1,12p' "${TMP}/out-failstrict.txt")"
fi
unset SWEEP_FAIL_SCENARIO

# --- 3. surplus apply failure: ERROR row + strict still restored -------------
export APPLY_SURPLUS_RC=3
rc="$(run_subject applyfail)"
if [[ "$rc" != "0" ]] \
  && grep -q "^surplus-sharing	.*	3	ERROR" "${TMP}/art-applyfail/summary.tsv"; then
  pass "failing surplus apply surfaces a nonzero exit and an ERROR row"
else
  fail "a failing surplus apply must exit nonzero with an ERROR row; got rc=$rc
$(tail -n +2 "${TMP}/art-applyfail/summary.tsv" 2>/dev/null)
$(sed -n '1,12p' "${TMP}/out-applyfail.txt")"
fi
apply_log="$(cat "${TMP}/apply-applyfail.log" 2>/dev/null)"
if [ "$(wc -l <<<"$apply_log")" = "3" ] \
  && sed -n '3p' <<<"$apply_log" | grep -q -- "--symmetric fake:vm" \
  && ! sed -n '3p' <<<"$apply_log" | grep -q -- "--surplus-sharing"; then
  pass "strict fixture is restored even after the surplus apply failed"
else
  fail "the strict restore must still run after a failed surplus apply; got:
${apply_log}"
fi
APPLY_SURPLUS_RC=0

# --- 4. lab-only legs: APPLY_CONFIG + no incus → SKIP 77 ---------------------
mkdir -p "${TMP}/nocluster"
for b in bash sh dirname mkdir date cat grep sed awk tail head wc; do
  ln -sf "$(command -v "$b")" "${TMP}/nocluster/$b" 2>/dev/null || true
done
ln -sf "${TMP}/bin/fairness-cos-class-sweep" "${TMP}/nocluster/fairness-cos-class-sweep"
ln -sf "${TMP}/bin/apply-cos-config" "${TMP}/nocluster/apply-cos-config"
SWEEP="${TMP}/nocluster/fairness-cos-class-sweep" \
APPLY_COS_CONFIG="${TMP}/nocluster/apply-cos-config" \
APPLY_LOG="${TMP}/apply-skip.log" \
ARTIFACT_ROOT="${TMP}/art-skip" \
TARGET_VM="fake:vm" \
PATH="${TMP}/nocluster" \
bash "$SUBJECT" > "${TMP}/out-skip.txt" 2>&1
rc=$?
if [[ "$rc" = "77" ]] && grep -q "SKIP: incus not found" "${TMP}/out-skip.txt" \
  && grep -q "lab-only (#11769)" "${TMP}/out-skip.txt"; then
  pass "no-incus host SKIPs (exit 77) with the lab-only reason"
else
  fail "no-incus host must SKIP 77 with the lab-only reason; got rc=$rc
$(cat "${TMP}/out-skip.txt")"
fi

# --- summary ------------------------------------------------------------------
if [[ $fails -eq 0 ]]; then
  echo "fairness-cos-throughput-headroom-selftest: all checks passed"
  exit 0
fi
echo "fairness-cos-throughput-headroom-selftest: ${fails} check(s) FAILED" >&2
exit 1
