#!/usr/bin/env bash
# One result envelope for every gate run, appended to a tracked ledger.
#
# Sourced as a library, or executed:
#
#   ./test/incus/harness-result.sh run --gate test-failover --adapter ha-smoke \
#       --env loss-userspace-cluster --cluster --node loss:xpf-userspace-fw0 \
#       -- ./test/incus/test-failover.sh
#
# and it writes exactly one JSON row to test/results/ledger.d/<run_id>.json.
#
# ── Why the verdict is a STRING and never an exit code ────────────────
#
# The tree's own measurement tools already disagree about what `exit 1` means,
# and the disagreement is not cosmetic:
#
#   newflow_ceiling_analyze.py:764   {VALID:0, INCONCLUSIVE:2, else 1}
#                                    exit 1 == "the run did not measure what it
#                                    claims to" (INVALID)
#   mouse_latency_aggregate.py:353   "0 = PASS, 1 = measured FAIL (gate
#                                    violated), 2 = insufficient evidence" --
#                                    exit 1 == "this is a regression"
#   iperf-throughput-lib.sh          PASS/FAIL only. It has NO void state at
#                                    all: "the run produced no measurement at
#                                    all" is emitted as a FAIL.
#   run-selftests.sh                 PASS/FAIL, plus 77 == SKIP from a leg.
#
# So the same integer means "did not measure" in one tool and "measured a
# regression" in another, and the direction of a mis-file is expensive both
# ways: a void read as a regression burns a bisect, a regression read as a void
# is ignored. mouse_latency_aggregate.py's docstring records that this already
# shipped once -- C175-HC-029, a real latency FAIL painted green.
#
# This layer therefore does NOT invent a convention and hope the tools converge
# on it. Every source gets an explicit row in the adapter table below, the
# verdict travels as one of the three STRINGS PASS / FAIL / VOID, and the
# mapping is exercised by test/incus/harness-result-selftest.sh -- including
# the case iperf-throughput-lib.sh cannot express, where "no measurement at
# all" is recovered from its FAIL text and recorded as a VOID.
#
# ── Falsifiability of this file, as a whole ───────────────────────────
#
# If the property under test is FALSE:      the adapter maps it to FAIL and the
#                                           row records the metric that moved.
# If the measurement did not happen:        VOID plus a non-empty reason. The
#                                           emitter REFUSES a VOID without a
#                                           reason and a PASS/FAIL with one, so
#                                           "we don't know" cannot be written
#                                           down as an answer.
# On an empty set (no output at all):       VOID -- an absent summary line is
#                                           never a pass. A gate that cannot say
#                                           which of the three it is writes NO
#                                           ROW, and an absent row is visibly
#                                           absent to ledger_compare.py, whereas
#                                           a defaulted row is not.

# Guard against double-sourcing (the run wrapper sources deploy-lib.sh, which a
# caller may also have sourced).
[[ -n "${_HARNESS_RESULT_SH_LOADED:-}" ]] && return 0 2>/dev/null
_HARNESS_RESULT_SH_LOADED=1

HARNESS_RESULT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Row schema version. Bump when a field's MEANING changes; add a new field
# rather than redefining one, because old rows stay in the ledger forever and a
# redefinition silently changes what they said.
HARNESS_RESULT_SCHEMA=1

# The adapter table. A source not listed here is REFUSED, never defaulted.
HARNESS_ADAPTERS="ha-smoke smoke-cells newflow-ceiling mouse-latency selftest iperf-throughput wire-gate"

harness_result_root() {
	if [[ -n "${XPF_REPO_ROOT:-}" ]]; then
		printf '%s\n' "$XPF_REPO_ROOT"
		return 0
	fi
	git -C "$HARNESS_RESULT_DIR" rev-parse --show-toplevel 2>/dev/null ||
		printf '%s\n' "$(cd "$HARNESS_RESULT_DIR/../.." && pwd)"
}

# The ledger is a DIRECTORY of one <run_id>.json per run (#8346), not an
# appended file. Two writers never touch the same path, so concurrent lanes
# cannot conflict and no merge driver is involved -- which matters because this
# repo's .git/config shadowed git's built-in `union` with a no-op for months
# (#8348) and silently dropped three real rows. XPF_LEDGER still overrides, and
# now names the DIRECTORY.
harness_ledger_path() {
	if [[ -n "${XPF_LEDGER:-}" ]]; then
		printf '%s\n' "$XPF_LEDGER"
	else
		printf '%s/test/results/ledger.d\n' "$(harness_result_root)"
	fi
}

_hr_warn() { printf 'harness-result: %s\n' "$*" >&2; }

# ─────────────────────────────────────────────────────────────────────
# Adapters
#
# Every adapter is a PURE function of (rc, log text). No cluster, no node, no
# clock -- which is what lets harness-result-selftest.sh drive the entire
# verdict matrix from fixtures.
#
# Each prints exactly five TAB-separated fields on one line:
#
#   verdict <TAB> void_reason <TAB> headline_metric <TAB> direction <TAB> metrics
#
# `metrics` is a space-separated k=v list of NUMERIC scalars. `direction` is
# higher-better / lower-better / neither, and it is a property of the metric,
# not of the run -- ledger_compare.py needs it to tell IMPROVED from
# REGRESSION and refuses to guess.
# ─────────────────────────────────────────────────────────────────────

# harness_adapt <adapter> <rc> <logfile>
harness_adapt() {
	local adapter="${1:-}" rc="${2:-}" log="${3:-}"
	case " $HARNESS_ADAPTERS " in
	*" $adapter "*) ;;
	*)
		_hr_warn "unknown adapter '$adapter' (known: $HARNESS_ADAPTERS)"
		return 2
		;;
	esac
	if [[ ! -f "$log" ]]; then
		_hr_warn "adapter $adapter: log '$log' does not exist"
		return 2
	fi
	"harness_adapt_${adapter//-/_}" "$rc" "$log"
}

# ── ha-smoke / smoke-cells ─────────────────────────────────────────────
#
# The two HA-smoke adapters share one summary parse and differ ONLY in the
# headline (#9922 F-155). Five smokes emit an iperf3 throughput cell
# (failover, double, stress, chained, active-active) and keep ha-smoke;
# eight emit cells only (connectivity, wire-properties, ha-crash,
# persistent-nat, dhcp-lease, private-rg, restart-connectivity, wg-interop)
# smoke-cells. The Makefile mapping is census-checked against "calls
# iperf_throughput_verdict" in harness-result-selftest.sh, so a future
# mis-mapping reds there instead of silently switching headline families.
#
# Match the NUMERIC TAIL, never the label prefix. The prefixes differ --
# "Failover test:", "HA crash test:", "Double failover test:", "Stress
# failover:", "Chained crash test:", "Restart connectivity:" and a bare
# "Results:" on two of them -- so a prefix-anchored adapter silently covers six
# of eight while looking complete. Nor may the regex be anchored at end of
# line: test-connectivity.sh appends ", $SKIP skipped" after the pair, and a
# `failed$` anchor drops it. harness-result-selftest.sh derives its fixtures
# from the real summary lines in those files, so either mistake goes red there.
#
# The VOID row is the one that pays for itself. A smoke that dies at `set -e`
# before its summary prints no pair at all; today that is indistinguishable
# from a clean run to anything reading only the tail. Here it is a VOID with a
# reason, which is the one thing it must never be confused with.
_ha_smoke_summary() {
	local log="$1" rc="$2"
	local line p f skipped=""
	# LAST match: a smoke that prints an intermediate tally must not have it
	# read as the result.
	line=$(grep -oE '[0-9]+ passed, [0-9]+ failed' "$log" | tail -1)
	if [[ -z "$line" ]]; then
		printf 'VOID\tno "<n> passed, <n> failed" summary line in the output (rc=%s) — the smoke aborted before reaching its summary\t\t\t\n' "$rc"
		return 1
	fi
	p=${line%% passed,*}
	f=${line##*, }
	f=${f%% failed*}
	# 10# forces base 10: a zero-padded count ("08") is OCTAL to bash and
	# errors out mid-adapter, which would surface as a missing row.
	p=$((10#$p))
	f=$((10#$f))
	if ((p + f == 0)); then
		printf 'VOID\tsummary reports 0 passed and 0 failed — the smoke reached its summary but ran no assertions\t\t\t\n'
		return 1
	fi
	skipped=$(grep -oE '[0-9]+ passed, [0-9]+ failed, [0-9]+ skipped' "$log" | tail -1 |
		sed -E 's/.*, ([0-9]+) skipped/\1/')
	printf '%s %s %s' "$p" "$f" "$skipped"
}
harness_adapt_ha_smoke() {
	local rc="$1" log="$2"
	local summary p f skipped=""
	if ! summary=$(_ha_smoke_summary "$log" "$rc"); then
		printf '%s\n' "$summary"
		return 0
	fi
	read -r p f skipped <<<"$summary"
	# ANCHORED iperf extraction: Gbps comes ONLY from a pass()/fail() cell
	# line -- `^[[:space:]]*(PASS|FAIL)[[:space:]]+iperf3 throughput` --
	# LAST match; the figure is the FIRST `<n> Gbps` on it. Floor prose
	# ("iperf3 throughput floor 5 Gbps") has no cell prefix and data-transfer
	# prose ("iperf3 data transfer completed (2.5 Gbps)") has neither the
	# prefix nor the phrase; both used to become banded measurements.
	local cell="" gbps=""
	cell=$(grep -E '^[[:space:]]*(PASS|FAIL)[[:space:]]+iperf3 throughput' "$log" | tail -1)
	if [[ -n "$cell" ]]; then
		gbps=$(grep -oE '([0-9]+\.[0-9]+|[0-9]+) Gbps' <<<"$cell" | head -1 | sed 's/ Gbps//')
	fi
	# Invariant metrics beside the headline. The iperf3 throughput cell is the
	# only continuous scalar these smokes produce; the cell counts are the
	# discrete invariants that say whether a headline move came with a
	# behaviour change (regression candidate) or alone (flake candidate).
	local metrics="cells_passed=$p cells_failed=$f"
	[[ -n "$skipped" ]] && metrics="$metrics cells_skipped=$skipped"
	[[ -n "$gbps" ]] && metrics="$metrics throughput_gbps=$gbps"
	if ((f > 0)); then
		# FAIL headlines are diagnostic-only: FAIL rows never enter bands,
		# so the FAIL shape keeps throughput-when-present, cells otherwise.
		if [[ -n "$gbps" ]]; then
			printf 'FAIL\t\tthroughput_gbps\thigher-better\t%s\n' "$metrics"
		else
			printf 'FAIL\t\tcells_passed\thigher-better\t%s\n' "$metrics"
		fi
		return 0
	fi
	# 0 failed but the process still failed: the summary and the exit status
	# disagree, so we do not know what happened. That is a VOID, not a pass --
	# and not a FAIL either, because no cell reported one.
	if [[ "$rc" != "0" ]]; then
		printf 'VOID\tsummary reports 0 failed but the smoke exited rc=%s — the summary and the exit status disagree\t\t\t\n' "$rc"
		return 0
	fi
	# A PASS summary with no anchored figure is a pass the throughput band
	# cannot see -- VOID, never a cells-headlined PASS that would silently
	# switch headline families mid-history.
	if [[ -z "$gbps" ]]; then
		printf 'VOID\tPASS summary but no anchored "PASS|FAIL iperf3 throughput" cell line carrying "<n> Gbps" — the iperf measurement is missing\t\t\t\n'
		return 0
	fi
	printf 'PASS\t\tthroughput_gbps\thigher-better\t%s\n' "$metrics"
}
harness_adapt_smoke_cells() {
	local rc="$1" log="$2"
	local summary p f skipped=""
	if ! summary=$(_ha_smoke_summary "$log" "$rc"); then
		printf '%s\n' "$summary"
		return 0
	fi
	read -r p f skipped <<<"$summary"
	# NO iperf extraction by design: these smokes emit no throughput cell,
	# so the headline is FIXED and iperf-looking prose is ignored.
	local metrics="cells_passed=$p cells_failed=$f"
	[[ -n "$skipped" ]] && metrics="$metrics cells_skipped=$skipped"
	if ((f > 0)); then
		printf 'FAIL\t\tcells_passed\thigher-better\t%s\n' "$metrics"
		return 0
	fi
	if [[ "$rc" != "0" ]]; then
		printf 'VOID\tsummary reports 0 failed but the smoke exited rc=%s — the summary and the exit status disagree\t\t\t\n' "$rc"
		return 0
	fi
	printf 'PASS\t\tcells_passed\thigher-better\t%s\n' "$metrics"
}

# ── newflow-ceiling ──────────────────────────────────────────────────
#
# newflow_ceiling_analyze.py --json. VALID -> PASS; INVALID and INCONCLUSIVE
# are both VOID, carrying the analyzer's own reasons. It never maps to FAIL: it
# reports a RATE, not a gate, so there is no threshold for it to violate. A
# rate that fell is caught by ledger_compare.py's band, which is the correct
# layer for it -- a gate here would need a threshold nobody has measured.
harness_adapt_newflow_ceiling() {
	local rc="$1" log="$2"
	python3 - "$log" "$rc" <<'PY'
import json, re, sys

path, rc = sys.argv[1], sys.argv[2]
raw = open(path, encoding="utf-8", errors="replace").read()

# The harness log may carry prose around the JSON document; take the last
# well-formed top-level object that has a "verdict" key.
doc = None
for m in re.finditer(r"\{", raw):
    frag = raw[m.start():]
    try:
        cand, _ = json.JSONDecoder().raw_decode(frag)
    except ValueError:
        continue
    if isinstance(cand, dict) and "verdict" in cand:
        doc = cand

def emit(verdict, reason="", headline="", direction="", metrics=""):
    print("\t".join((verdict, reason, headline, direction, metrics)))
    raise SystemExit(0)

if doc is None:
    emit("VOID", f"no analyzer JSON document with a verdict in the output (rc={rc}) "
                 "— newflow_ceiling_analyze.py did not run to completion")

v = doc.get("verdict")
if v != "VALID":
    reasons = "; ".join(str(r) for r in doc.get("reasons") or []) or "no reason given"
    emit("VOID", f"analyzer verdict {v} — {reasons}")

m = {}
def num(key, out=None):
    x = doc.get(key)
    if isinstance(x, (int, float)):
        m[out or key] = x

num("new_flows_per_sec")
num("offered_flows_per_sec")
num("accept_ratio")
num("elapsed_s")
num("replication_queue_depth_mean")
num("replication_fanout")
num("active_workers")
num("max_worker_share")
m["saturated_sites"] = len(doc.get("culprits") or [])
if "new_flows_per_sec" not in m:
    emit("VOID", "analyzer reported VALID but no numeric new_flows_per_sec — "
                 "the headline metric is missing from the document")
# #9922 F-160: a VALID document from a FAILED process is a summary the exit
# status contradicts — VOID, not a pass. The ha-smoke adapter already encodes
# this policy (0 failed + rc != 0 → VOID); a harness that analyzes fine and
# then fails teardown must not bank a PASS for a run the gate itself failed.
if rc != "0":
    emit("VOID", f"analyzer reported VALID but the harness exited rc={rc} — "
                 "the document and the exit status disagree")
emit("PASS", "", "new_flows_per_sec", "higher-better",
     " ".join(f"{k}={v}" for k, v in m.items()))
PY
}

# ── mouse-latency ────────────────────────────────────────────────────
#
# mouse_latency_aggregate.py: PASS / FAIL / INSUFFICIENT-DATA. This is the one
# tool whose exit 1 genuinely means "measured, gate violated", so its FAIL is a
# FAIL. INSUFFICIENT-DATA and any unexpected verdict are VOID.
harness_adapt_mouse_latency() {
	local rc="$1" log="$2"
	local verdict ratio loaded idle
	verdict=$(grep -oE '\*\*Verdict:\*\* [A-Z-]+' "$log" | tail -1 | awk '{print $2}')
	if [[ -z "$verdict" ]]; then
		printf 'VOID\tno "**Verdict:**" line in the aggregate output (rc=%s) — mouse_latency_aggregate.py did not run to completion\t\t\t\n' "$rc"
		return 0
	fi
	ratio=$(grep -oE 'ratio = [0-9]+\.[0-9]+' "$log" | tail -1 | awk '{print $3}')
	loaded=$(grep -oE 'loaded [0-9]+(\.[0-9]+)? us' "$log" | tail -1 | awk '{print $2}')
	idle=$(grep -oE 'idle [0-9]+(\.[0-9]+)? us' "$log" | tail -1 | awk '{print $2}')
	local metrics=""
	[[ -n "$ratio" ]] && metrics="$metrics ratio=$ratio"
	[[ -n "$loaded" ]] && metrics="$metrics loaded_us=$loaded"
	[[ -n "$idle" ]] && metrics="$metrics idle_us=$idle"
	metrics="${metrics# }"
	case "$verdict" in
	PASS | FAIL)
		if [[ -z "$ratio" ]]; then
			printf 'VOID\taggregate reported %s but printed no ratio — the headline metric is missing from the report\t\t\t\n' "$verdict"
			return 0
		fi
		printf '%s\t\tratio\tlower-better\t%s\n' "$verdict" "$metrics"
		;;
	*)
		printf 'VOID\taggregate verdict %s — no confident measurement (rc=%s)\t\t\t\n' "$verdict" "$rc"
		;;
	esac
}

# ── selftest ─────────────────────────────────────────────────────────
#
# scripts/run-selftests.sh: "  passed=N  skipped=N  failed=N".
harness_adapt_selftest() {
	local rc="$1" log="$2"
	local line p s f
	line=$(grep -oE 'passed=[0-9]+ +skipped=[0-9]+ +failed=[0-9]+' "$log" | tail -1)
	if [[ -z "$line" ]]; then
		printf 'VOID\tno "passed=N skipped=N failed=N" summary in the output (rc=%s) — the runner did not reach its summary\t\t\t\n' "$rc"
		return 0
	fi
	p=$((10#$(sed -E 's/.*passed=([0-9]+).*/\1/' <<<"$line")))
	s=$((10#$(sed -E 's/.*skipped=([0-9]+).*/\1/' <<<"$line")))
	f=$((10#$(sed -E 's/.*failed=([0-9]+).*/\1/' <<<"$line")))
	if ((p + f == 0)); then
		printf 'VOID\trunner summary reports 0 passed and 0 failed — it swept an empty set\t\t\t\n'
		return 0
	fi
	local metrics="legs_passed=$p legs_skipped=$s legs_failed=$f"
	if ((f > 0)); then
		printf 'FAIL\t\tlegs_failed\tlower-better\t%s\n' "$metrics"
	else
		printf 'PASS\t\tlegs_passed\thigher-better\t%s\n' "$metrics"
	fi
}

# ── iperf-throughput ─────────────────────────────────────────────────
#
# iperf_throughput_verdict (test/incus/iperf-throughput-lib.sh) prints exactly
# one "PASS <msg>" or "FAIL <msg>" line and has NO void state -- "the run
# produced no measurement at all" and "unparseable" are both emitted as FAIL.
# This adapter RECOVERS the missing third state from that text, which is the
# entire reason the mapping is a table and not an exit-code convention.
harness_adapt_iperf_throughput() {
	local rc="$1" log="$2"
	local line gbps
	line=$(grep -E '^(PASS|FAIL) iperf3 throughput' "$log" | tail -1)
	if [[ -z "$line" ]]; then
		printf 'VOID\tno "PASS|FAIL iperf3 throughput" verdict line in the output (rc=%s)\t\t\t\n' "$rc"
		return 0
	fi
	case "$line" in
	*"no measurement at all"* | *"unparseable"*)
		printf 'VOID\tiperf-throughput-lib reported FAIL for a NON-measurement: %s\t\t\t\n' "${line#* }"
		return 0
		;;
	esac
	gbps=$(grep -oE '([0-9]+\.[0-9]+|[0-9]+) Gbps' <<<"$line" | head -1 | sed 's/ Gbps//')
	if [[ -z "$gbps" ]]; then
		printf 'VOID\tverdict line carries no "<n> Gbps" figure: %s\t\t\t\n' "$line"
		return 0
	fi
	case "$line" in
	PASS*) printf 'PASS\t\tthroughput_gbps\thigher-better\tthroughput_gbps=%s\n' "$gbps" ;;
	*) printf 'FAIL\t\tthroughput_gbps\thigher-better\tthroughput_gbps=%s\n' "$gbps" ;;
	esac
}

# ── wire-gate ────────────────────────────────────────────────────────
#
# #9531 frame-count wire gates (wire_policy_deny, wire_appmatch_twins,
# test-host-inbound matrix + failover, cc-rollback arms). Each harness prints
# exactly one final line per wrapper invocation:
#
#   WIRE_GATE <gate-id> <PASS|FAIL|VOID> reason=<slug> <k=v numeric...>
#
# `reason` is `--` on PASS/FAIL and a design-doc-§8 closed slug on VOID
# (env-void, row-timeout, no-prober, harness-void, capture-blind,
# under-sampled, uncalibrated, dut-void). This adapter TRANSCRIBES verdicts;
# it never re-derives one from metrics. Metrics serve bands and display only.
# A pre-measurement early VOID (refused precondition) carries an EMPTY metrics
# map, which the emitter permits on VOID rows; PASS/FAIL always carry the
# complete per-gate map.
harness_adapt_wire_gate() {
	local rc="$1" log="$2"
	local line gate verdict rest reason
	line=$(grep -E '^WIRE_GATE [A-Za-z0-9_.-]+ (PASS|FAIL|VOID) ' "$log" | tail -1)
	if [[ -z "$line" ]]; then
		printf 'VOID\tharness-void: no "WIRE_GATE <gate> <PASS|FAIL|VOID> reason=<slug> ..." verdict line in the output (rc=%s)\t\t\t\n' "$rc"
		return 0
	fi
	# Two lines naming DIFFERENT gates in one log: one wrapper invocation
	# carries one arm, so guessing would mis-attribute. Loud VOID instead.
	local ngates
	ngates=$(grep -Eo '^WIRE_GATE [A-Za-z0-9_.-]+' "$log" | sort -u | wc -l)
	if ((ngates > 1)); then
		printf 'VOID\tharness-void: %s distinct WIRE_GATE gate IDs in one log — one wrapper invocation carries one arm\t\t\t\n' "$ngates"
		return 0
	fi
	gate=$(awk '{print $2}' <<<"$line")
	verdict=$(awk '{print $3}' <<<"$line")
	rest=$(sed -E 's/^WIRE_GATE [A-Za-z0-9_.-]+ (PASS|FAIL|VOID) //' <<<"$line")
	# The reason token is mandatory and first: without it a VOID has nowhere
	# legal to put its slug (the emitter refuses VOID without one) and a
	# PASS/FAIL has no way to prove it carries none.
	local firsttok=${rest%% *}
	case "$firsttok" in
	reason=*)
		reason=${firsttok#reason=}
		if [[ "$rest" == *" "* ]]; then
			rest=${rest#* }
		else
			rest=""
		fi
		;;
	*)
		printf 'VOID\tharness-void: WIRE_GATE line for %s has no leading reason=<slug> token\t\t\t\n' "$gate"
		return 0
		;;
	esac
	# Verdict-dependent reason handling: ONLY a VOID populates --void-reason.
	# A PASS/FAIL carrying a real slug has no valid translation (the emitter
	# refuses PASS/FAIL with a reason), so it is a contract violation, loud.
	if [[ "$verdict" != "VOID" ]]; then
		if [[ "$reason" != "--" ]]; then
			printf 'VOID\tharness-void: WIRE_GATE %s %s carries reason=%s — PASS/FAIL must carry reason=--\t\t\t\n' "$gate" "$verdict" "$reason"
			return 0
		fi
	else
		local closed_reasons=" env-void row-timeout no-prober harness-void capture-blind under-sampled uncalibrated dut-void "
		case "$closed_reasons" in
		*" $reason "*) ;;
		*)
			printf 'VOID\tharness-void: WIRE_GATE %s VOID carries unknown slug reason=%s (design §8 closed taxonomy)\t\t\t\n' "$gate" "$reason"
			return 0
			;;
		esac
	fi
	# Split the metrics map, keeping only well-formed numeric pairs. A corrupt
	# pair is never repaired by invention: on PASS/FAIL it voids the row
	# below via the required-keys rule; on VOID the true reason wins and the
	# map ships with just its valid pairs (possibly empty — emitter-legal).
	local metrics="" tok k v badpair=""
	for tok in $rest; do
		case "$tok" in
		[A-Za-z0-9_.-]*=*)
			k=${tok%%=*}
			v=${tok#*=}
			if [[ "$k" == "reason" ]]; then
				badpair="$tok"
				break
			fi
			case "$v" in
			- | *[!0-9.+-]* | "" | *.*.*) badpair="$tok"; break ;;
			esac
			# Reject lone signs/dots and trailing/leading dots that the
			# character class above still admits.
			case "$v" in
			+ | - | . | +.* | -.* | *. | *..*) badpair="$tok"; break ;;
			esac
			metrics="${metrics:+$metrics }$k=$v"
			;;
		*)
			badpair="$tok"
			break
			;;
		esac
	done
	# Required keys + headline per gate. An unknown gate is REFUSED, never
	# defaulted: inventing a headline would fabricate the row's meaning.
	local required headline direction
	case "$gate" in
	wire_policy_deny)
		required="probe_offered probe_leaked control_offered control_observed"
		headline="probe_leaked"
		direction="lower-better"
		;;
	wire_appmatch_twins)
		required="tcp80_offered tcp80_observed tcp8080_offered tcp8080_observed udp53_offered udp53_observed udp5353_offered udp5353_observed deny_leaked permit_missing"
		headline="deny_leaked"
		direction="lower-better"
		;;
	wire_zone_matrix)
		required="cells_measured cells_failed deny_cells permit_cells deny_leaked permit_missing control_missing duplicate_frames permit64_offered permit64_observed permit1400_offered permit1400_observed"
		headline="cells_failed"
		direction="lower-better"
		;;
	wire_hostinbound_deny)
		required="cells_measured syn_offered handshake_completed refused_total exposed_total reply_frames ctrl_offered ctrl_observed"
		headline="exposed_total"
		direction="lower-better"
		;;
	wire_conntrack_lifecycle)
		required="created witnessed evicted stale_present exp_offered exp_leaked fresh_offered fresh_leaked syn_offered syn_observed ctrl_sess lifecycle_bad"
		headline="lifecycle_bad"
		direction="lower-better"
		;;
	test-host-inbound | test-host-inbound-failover)
		required="cells_passed cells_failed"
		headline="cells_failed"
		direction="lower-better"
		;;
	cc-rollback-arm-a)
		required="mid_blocked post_present post_fwd_ok"
		headline="post_fwd_ok"
		direction="higher-better"
		;;
	cc-rollback-arm-b)
		required="mid_present mid_fwd_ok post_gone post_blocked sess_gone"
		headline="sess_gone"
		direction="higher-better"
		;;
	*)
		printf 'VOID\tharness-void: WIRE_GATE names unknown gate %s — no headline table entry, refusing to guess\t\t\t\n' "$gate"
		return 0
		;;
	esac
	if [[ -n "$badpair" ]]; then
		if [[ "$verdict" == "VOID" ]]; then
			printf 'VOID\t%s\t\t\t\n' "$reason"
		else
			printf 'VOID\tharness-void: WIRE_GATE %s %s carries malformed metric %s\t\t\t\n' "$gate" "$verdict" "$badpair"
		fi
		return 0
	fi
	if [[ "$verdict" != "VOID" || -n "$metrics" ]]; then
		local missing=""
		local rk
		for rk in $required; do
			case " $metrics " in
			*" $rk="*) ;;
			*) missing="${missing:+$missing,}$rk" ;;
			esac
		done
		if [[ -n "$missing" ]]; then
			if [[ "$verdict" == "VOID" ]]; then
				printf 'VOID\t%s\t\t\t\n' "$reason"
			else
				printf 'VOID\tharness-void: WIRE_GATE %s %s is missing required metrics: %s\t\t\t\n' "$gate" "$verdict" "$missing"
			fi
			return 0
		fi
	fi
	# Exit-code disagreement (ha-smoke precedent): a PASS whose process failed
	# is a summary the exit status contradicts — VOID, not a pass. A FAIL
	# stands whatever rc; a VOID is already the absence of a measurement.
	if [[ "$verdict" == "PASS" && "$rc" != "0" ]]; then
		printf 'VOID\tharness-void: WIRE_GATE %s reports PASS but exited rc=%s — summary and exit status disagree\t\t\t\n' "$gate" "$rc"
		return 0
	fi
	if [[ "$verdict" == "VOID" ]]; then
		printf 'VOID\t%s\t\t\t%s\n' "$reason" "$metrics"
	elif [[ "$verdict" == "PASS" ]]; then
		printf 'PASS\t\t%s\t%s\t%s\n' "$headline" "$direction" "$metrics"
	else
		printf 'FAIL\t\t%s\t%s\t%s\n' "$headline" "$direction" "$metrics"
	fi
}

# ─────────────────────────────────────────────────────────────────────
# Provenance: which build actually produced this measurement
# ─────────────────────────────────────────────────────────────────────
#
# Recording the checkout's HEAD alone is NOT enough. The checkout is routinely
# a different tree from what is running on the node, which is exactly the
# failure deploy-lib.sh already dies on (#2176, "the node is running STALE
# code"). A row is only a measurement OF a build if it can name that build.
#
# Three fields, because two of them are different KINDS of value and comparing
# them directly would be meaningless:
#
#   build_git_sha       provenance of the TREE (plus "-dirty" when the tree has
#                       uncommitted changes -- a dirty tree's sha does not
#                       identify a binary, and saying so is the point)
#   build_exe_sha256    sha256 of the locally built xpfd from that tree
#   running_exe_sha256  sha256 of the LIVE process image on the node, read back
#                       through deploy_running_xpfd_sha256() -- the one
#                       readback in the tree, extracted from
#                       deploy_verify_running_xpfd so there is not a second one
#                       free to disagree with it
#
# exe_check is the comparable, and it has FOUR values so that "we could not
# check" is not spelled the same as "checked and fine":
#
#   MATCH           build_exe_sha256 == running_exe_sha256
#   MISMATCH        they differ -- the node is running some other build
#   UNAVAILABLE     the readback did not happen (no MainPID, no local binary,
#                   incus unreachable)
#   NOT-APPLICABLE  a hermetic gate; there is no deployed binary to check
#
# The emitter REFUSES a non-VOID verdict carrying MISMATCH or UNAVAILABLE, so
# the rule cannot be forgotten by a future caller: a measurement of an unknown
# binary is not a result.

# harness_build_git_sha [root]
#
# HEAD, with a "-dirty" suffix when the tree carries uncommitted changes,
# because a dirty tree's sha does not identify a binary and saying so is the
# point.
#
# The ledger itself is EXCLUDED from that dirtiness test -- both the shard
# directory (#8346) and the legacy single file, because a checkout mid-
# transition can carry either. It is this emitter's own output, so counting it
# would pin every row to "-dirty" forever --
# including rows produced from an otherwise pristine checkout, since the row
# being written is what makes the file differ. A flag that is always on carries
# no information, and the one thing this flag has to do is distinguish the two
# cases.
harness_build_git_sha() {
	local root="${1:-$(harness_result_root)}" sha dirt
	sha=$(git -C "$root" rev-parse HEAD 2>/dev/null) || return 1
	# -uall so untracked files are listed INDIVIDUALLY. Without it git
	# collapses an untracked directory to a single "?? test/results/" entry,
	# the path filter below does not match it, and the exclusion silently does
	# nothing on exactly the case it exists for -- a fresh checkout writing its
	# first row.
	dirt=$(git -C "$root" status --porcelain -uall 2>/dev/null |
		grep -vE 'test/results/ledger\.(d/.*\.json|jsonl)$' || true)
	if [[ -n "$dirt" ]]; then
		printf '%s-dirty\n' "$sha"
	else
		printf '%s\n' "$sha"
	fi
}

# harness_exe_check <build_exe_sha> <running_exe_sha> <mode>
# mode: cluster | hermetic
harness_exe_check() {
	local build="${1:-}" running="${2:-}" mode="${3:-cluster}"
	if [[ "$mode" == "hermetic" ]]; then
		printf 'NOT-APPLICABLE\n'
		return 0
	fi
	if [[ -z "$build" || -z "$running" ]]; then
		printf 'UNAVAILABLE\n'
		return 0
	fi
	if [[ "$build" == "$running" ]]; then
		printf 'MATCH\n'
	else
		printf 'MISMATCH\n'
	fi
}

# harness_exe_scope <mode> <peer_node> <peer_running_sha>
#
# #9044: how much of the cluster this row's executable attestation actually
# covers. The row could not previously express "I attested ONE of the two nodes
# this gate used", so a single-node attestation read as a whole-cluster MATCH —
# and on an HA gate, which fails over by definition, the unattested node is the
# one the result depends on.
#
#   n/a         hermetic run: there is no deployed binary to attest.
#   both        this node AND the peer were read back.
#   local-only  the peer could not be read. NOT a void: the crash gates
#               force-stop a node and may leave it down, so voiding here would
#               red exactly the gates whose job is to kill a node. It is a
#               SCOPE statement, and its whole purpose is that a reader can
#               tell it apart from `both` instead of both spelling MATCH.
harness_exe_scope() {
	local mode="${1:-cluster}" peer_node="${2:-}" peer_sha="${3:-}"
	if [[ "$mode" == "hermetic" ]]; then
		printf 'n/a\n'
		return 0
	fi
	if [[ -n "$peer_node" && -n "$peer_sha" ]]; then
		printf 'both\n'
	else
		printf 'local-only\n'
	fi
}

# ─────────────────────────────────────────────────────────────────────
# The emitter
# ─────────────────────────────────────────────────────────────────────
#
# Refuses (rc 2, NO row written) when:
#   * verdict is not exactly one of PASS / FAIL / VOID
#   * VOID with an empty reason, or PASS/FAIL with a non-empty one
#   * exe_check is not one of the four values
#   * exe_check is MISMATCH or UNAVAILABLE on a non-VOID verdict
#   * a PASS/FAIL with an empty metrics map
#   * a PASS/FAIL whose headline_metric is absent from its own metrics map
#   * a metric value that is not a number
#   * an empty gate or env
#
# Refusing is the falsifiable behaviour: a gate that cannot say which of the
# three it is writes nothing, and an absent row is visibly absent to
# ledger_compare.py's coverage, whereas a defaulted row is not.
harness_result_emit() {
	local gate="" env="" verdict="" void_reason="" headline="" direction=""
	local metrics="" build_git_sha="" build_exe="" running_exe="" exe_check=""
	local duration_s="" artifacts="" adapter="" ledger="" node="" ts=""
	local node_peer="" running_exe_peer="" exe_scope=""
	while (($#)); do
		case "$1" in
		--gate) gate="$2"; shift 2 ;;
		--env) env="$2"; shift 2 ;;
		--verdict) verdict="$2"; shift 2 ;;
		--void-reason) void_reason="$2"; shift 2 ;;
		--headline-metric) headline="$2"; shift 2 ;;
		--headline-direction) direction="$2"; shift 2 ;;
		--metrics) metrics="$2"; shift 2 ;;
		--build-git-sha) build_git_sha="$2"; shift 2 ;;
		--build-exe-sha256) build_exe="$2"; shift 2 ;;
		--running-exe-sha256) running_exe="$2"; shift 2 ;;
		--exe-check) exe_check="$2"; shift 2 ;;
		--duration-s) duration_s="$2"; shift 2 ;;
		--artifacts) artifacts="$2"; shift 2 ;;
		--adapter) adapter="$2"; shift 2 ;;
		--node) node="$2"; shift 2 ;;
		--node-peer) node_peer="$2"; shift 2 ;;
		--running-exe-sha256-peer) running_exe_peer="$2"; shift 2 ;;
		--exe-scope) exe_scope="$2"; shift 2 ;;
		--ledger) ledger="$2"; shift 2 ;;
		--ts) ts="$2"; shift 2 ;;
		*) _hr_warn "emit: unknown argument '$1'"; return 2 ;;
		esac
	done

	case "$verdict" in
	PASS | FAIL | VOID) ;;
	*) _hr_warn "REFUSED: verdict must be PASS, FAIL or VOID (got '${verdict}')"; return 2 ;;
	esac
	if [[ -z "$gate" || "$gate" =~ [[:space:]] ]]; then
		_hr_warn "REFUSED: --gate must be a non-empty whitespace-free name (got '${gate}')"
		return 2
	fi
	if [[ -z "$env" ]]; then
		_hr_warn "REFUSED: --env is required (a band is only comparable within one env)"
		return 2
	fi
	if [[ "$verdict" == "VOID" && -z "$void_reason" ]]; then
		_hr_warn "REFUSED: a VOID row must carry a --void-reason; 'we do not know' is not an answer"
		return 2
	fi
	if [[ "$verdict" != "VOID" && -n "$void_reason" ]]; then
		_hr_warn "REFUSED: a $verdict row must not carry a void reason (got '${void_reason}')"
		return 2
	fi
	case "$exe_check" in
	MATCH | MISMATCH | UNAVAILABLE | NOT-APPLICABLE) ;;
	*) _hr_warn "REFUSED: --exe-check must be MATCH, MISMATCH, UNAVAILABLE or NOT-APPLICABLE (got '${exe_check}')"; return 2 ;;
	esac
	if [[ "$verdict" != "VOID" && ( "$exe_check" == "MISMATCH" || "$exe_check" == "UNAVAILABLE" ) ]]; then
		_hr_warn "REFUSED: exe_check=$exe_check on a $verdict row — a measurement of a binary we cannot name is a VOID, not a result (#2176)"
		return 2
	fi
	if [[ -z "$build_git_sha" ]]; then
		_hr_warn "REFUSED: --build-git-sha is required"
		return 2
	fi
	if [[ "$verdict" != "VOID" ]]; then
		if [[ -z "$metrics" ]]; then
			_hr_warn "REFUSED: a $verdict row must carry at least one metric"
			return 2
		fi
		if [[ -z "$headline" ]]; then
			_hr_warn "REFUSED: a $verdict row must name its --headline-metric"
			return 2
		fi
		case "$direction" in
		higher-better | lower-better | neither) ;;
		*) _hr_warn "REFUSED: --headline-direction must be higher-better, lower-better or neither (got '${direction}')"; return 2 ;;
		esac
	fi

	[[ -z "$ledger" ]] && ledger="$(harness_ledger_path)"
	# Milliseconds, not seconds (#8346). Under one file per run the ledger's
	# file order no longer encodes write order, so `ts` is the only thing that
	# does -- and at second granularity two runs finishing in the same second
	# tie, leaving "which is newest" to a tie-break rather than to the data.
	# The comparator's tie-break is deterministic either way; this is what keeps
	# it from being needed. String sort still orders these correctly, and older
	# second-granularity rows remain comparable.
	[[ -z "$ts" ]] && ts="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"

	# The helper writes the shard and echoes its path; capturing the path (not
	# the row) is what makes a write failure a non-zero rc here.
	local shard
	shard=$(
		HR_SCHEMA="$HARNESS_RESULT_SCHEMA" HR_TS="$ts" HR_GATE="$gate" HR_ENV="$env" \
			HR_VERDICT="$verdict" HR_VOID_REASON="$void_reason" HR_HEADLINE="$headline" \
			HR_DIRECTION="$direction" HR_METRICS="$metrics" HR_GITSHA="$build_git_sha" \
			HR_BUILD_EXE="$build_exe" HR_RUN_EXE="$running_exe" HR_EXE_CHECK="$exe_check" \
			HR_DURATION="$duration_s" HR_ARTIFACTS="$artifacts" HR_ADAPTER="$adapter" \
			HR_NODE="$node" HR_NODE_PEER="$node_peer" \
			HR_RUN_EXE_PEER="$running_exe_peer" HR_EXE_SCOPE="$exe_scope" \
			HR_LEDGER="$ledger" \
			python3 - <<'PY'
import json, os, pathlib, sys

def num(s):
    try:
        return int(s)
    except ValueError:
        return float(s)

metrics = {}
for tok in os.environ.get("HR_METRICS", "").split():
    if "=" not in tok:
        print(f"REFUSED: metric token '{tok}' is not k=v", file=sys.stderr)
        raise SystemExit(2)
    k, v = tok.split("=", 1)
    if not k:
        print(f"REFUSED: metric token '{tok}' has an empty key", file=sys.stderr)
        raise SystemExit(2)
    try:
        metrics[k] = num(v)
    except ValueError:
        # A non-numeric metric cannot be banded. Accepting it would put a row
        # in the ledger that ledger_compare.py must skip, and a silently
        # skipped row is one that does not count toward K while looking like
        # it does.
        print(f"REFUSED: metric '{k}' has non-numeric value '{v}'", file=sys.stderr)
        raise SystemExit(2)

verdict = os.environ["HR_VERDICT"]
headline = os.environ.get("HR_HEADLINE", "")
if verdict != "VOID" and headline not in metrics:
    print(f"REFUSED: headline metric '{headline}' is absent from the metrics map "
          f"{sorted(metrics)}", file=sys.stderr)
    raise SystemExit(2)

def opt(name):
    v = os.environ.get(name, "")
    return v if v else None

duration = os.environ.get("HR_DURATION", "")
row = {
    "schema": int(os.environ["HR_SCHEMA"]),
    # A per-run identity, so no two rows are ever byte-identical.
    #
    # This is what makes `merge=union` on the ledger safe. docs/log/README.md
    # measured union SILENTLY FUSING two _Log.md entries whose `- **Timestamp**`
    # lines aligned, and says the driver should not be added for that file. The
    # ledger differs -- a row is one self-contained line with no shared prefix
    # -- but the residual hazard is real: two lanes emitting a byte-identical
    # row would give union a line it could align. A random run_id removes the
    # possibility rather than arguing it away, and ledger_compare.py dedupes on
    # it (and flags a repeated run_id whose payload DIFFERS, which is
    # corruption rather than a merge artifact).
    "run_id": os.urandom(8).hex(),
    "ts": os.environ["HR_TS"],
    "gate": os.environ["HR_GATE"],
    "env": os.environ["HR_ENV"],
    "verdict": verdict,
    "void_reason": os.environ.get("HR_VOID_REASON", ""),
    "headline_metric": headline,
    "headline_direction": os.environ.get("HR_DIRECTION", ""),
    "metrics": metrics,
    "build_git_sha": os.environ["HR_GITSHA"],
    "build_exe_sha256": os.environ.get("HR_BUILD_EXE", ""),
    "running_exe_sha256": os.environ.get("HR_RUN_EXE", ""),
    "exe_check": os.environ["HR_EXE_CHECK"],
    "duration_s": num(duration) if duration else None,
    "artifacts": opt("HR_ARTIFACTS"),
    "adapter": opt("HR_ADAPTER"),
    "node": opt("HR_NODE"),
    # #9044: the PEER half of the executable attestation, and how much of the
    # cluster it covers. Additive: a reader of an older row sees neither key,
    # which is exactly the state those rows were emitted in — a single-node
    # attestation that could not say so.
    "node_peer": opt("HR_NODE_PEER"),
    "running_exe_sha256_peer": opt("HR_RUN_EXE_PEER"),
    "exe_scope": opt("HR_EXE_SCOPE"),
}
# separators without spaces and ensure_ascii=False keep the row compact; json
# escapes every newline, so a row is always exactly one physical line even when
# a void_reason contains one.
line = json.dumps(row, separators=(",", ":"), ensure_ascii=False)
assert "\n" not in line

# Write the shard HERE rather than handing the line back to the shell: this is
# where the run_id exists, and the filename must BE that id. A shard whose name
# and payload disagree breaks both properties the layout exists for --
# conflict-freedom, and reading the run-id set off a git tree without parsing.
#
# Written under a temp name in the SAME directory and renamed, so a reader
# globbing the directory while a gate finishes never sees a half-written shard.
# rename(2) within one directory is atomic; an append never was, which is why
# the old single-file path needed flock and why this one needs no lock at all.
ledger_dir = pathlib.Path(os.environ["HR_LEDGER"])
ledger_dir.mkdir(parents=True, exist_ok=True)
target = ledger_dir / f"{row['run_id']}.json"
tmp = ledger_dir / f".{row['run_id']}.tmp"
tmp.write_text(line + "\n", encoding="utf-8")
os.replace(tmp, target)
print(target)
PY
	) || return 2
	# Echo the shard path so a caller (and the self-test) can point at the file
	# this run produced rather than re-deriving it from the run_id, which only
	# the helper knows.
	printf '%s\n' "$shard"
	return 0
}

# ─────────────────────────────────────────────────────────────────────
# The run wrapper
# ─────────────────────────────────────────────────────────────────────
#
# Runs a gate, adapts its output, records provenance, emits one row, and
# propagates a truthful exit status.
#
# Exit status contract (documented because §0.1 is the whole problem):
#   0   the gate passed AND a verdict was reached
#   1   FAIL -- measured, and the gate is violated
#   2   VOID -- the measurement did not happen
# A non-zero rc from the wrapped command is propagated as-is when it is not
# already covered above, so `make test-failover` keeps failing the way it did.
# The one CHANGE in behaviour is deliberate and in the safe direction: a gate
# that exits 0 without reaching its summary now exits 2 instead of 0.
#
# A failure to WRITE the row demotes a PASS to 2 ("passed but unrecorded") and
# prints a loud NO ROW WRITTEN marker; a measured FAIL keeps its rc (#9922
# F-087). The old contract held that reddening a 30-minute smoke for a write
# failure was worse than the missing row; the cohort reverses it, because every
# refusal mode that degrades to 'gate exits normally, nothing recorded, all
# aggregates green' is exactly the failure the assurance layer exists to catch.
# The ledger-coverage census reads the absence either way.
harness_result_run() {
	local gate="" adapter="" env="" mode="cluster" node="" build_exe="" artifacts="" ledger=""
	local peer_node_arg=""
	while (($#)); do
		case "$1" in
		--gate) gate="$2"; shift 2 ;;
		--adapter) adapter="$2"; shift 2 ;;
		--env) env="$2"; shift 2 ;;
		--cluster) mode="cluster"; shift ;;
		--hermetic) mode="hermetic"; shift ;;
		--node) node="$2"; shift 2 ;;
		# #9044: the peer is normally resolved from cluster-env.sh like --node
		# is; the flag exists so a caller (and the self-test) can name it
		# explicitly, the same reason --node exists.
		--node-peer) peer_node_arg="$2"; shift 2 ;;
		--build-exe) build_exe="$2"; shift 2 ;;
		--artifacts) artifacts="$2"; shift 2 ;;
		--ledger) ledger="$2"; shift 2 ;;
		--) shift; break ;;
		*) _hr_warn "run: unknown argument '$1'"; return 2 ;;
		esac
	done
	if (($# == 0)); then
		_hr_warn "run: no command given after --"
		return 2
	fi
	[[ -n "$gate" ]] || { _hr_warn "run: --gate is required"; return 2; }
	[[ -n "$adapter" ]] || { _hr_warn "run: --adapter is required"; return 2; }
	[[ -n "$env" ]] || { _hr_warn "run: --env is required"; return 2; }

	local root log t0 t1 rc
	root="$(harness_result_root)"
	log=$(mktemp "${TMPDIR:-/var/tmp}/xpf-harness-log.XXXXXX")
	t0=$(date +%s)
	# tee so the operator still sees the gate's output live; PIPESTATUS[0] is
	# the gate's own status, not tee's.
	local had_pipefail=0
	[[ -o pipefail ]] && had_pipefail=1
	set -o pipefail
	"$@" 2>&1 | tee "$log"
	rc=${PIPESTATUS[0]}
	((had_pipefail)) || set +o pipefail
	t1=$(date +%s)

	local adapted verdict void_reason headline direction metrics
	if ! adapted=$(harness_adapt "$adapter" "$rc" "$log"); then
		_hr_warn "NO ROW WRITTEN: adapter '$adapter' refused to classify this run"
		rm -f "$log"
		return $((rc == 0 ? 2 : rc))
	fi
	# `read -r` with IFS=$'\t' is WRONG here and the bug it produces is silent:
	# tab is an IFS *whitespace* character, so bash collapses the two adjacent
	# tabs of an empty void_reason field into one delimiter and every field
	# shifts left by one. The visible symptom was not a parse error -- it was
	# the emitter refusing "a PASS row must not carry a void reason" and NO ROW
	# BEING WRITTEN, i.e. a green gate that silently records nothing. cut(1)
	# does not collapse a delimiter.
	verdict=$(cut -f1 <<<"$adapted")
	void_reason=$(cut -f2 <<<"$adapted")
	headline=$(cut -f3 <<<"$adapted")
	direction=$(cut -f4 <<<"$adapted")
	metrics=$(cut -f5 <<<"$adapted")

	local build_git_sha build_exe_sha running_exe_sha exe_check
	# Initialised explicitly: the run wrapper executes under `set -u`, and a
	# value-less `local` makes the first `[[ -z "$peer_node" ]]` an unbound-
	# variable error rather than a false test (#9044).
	local peer_node="$peer_node_arg" peer_running_exe_sha="" exe_scope=""
	build_git_sha=$(harness_build_git_sha "$root" || echo "unknown")
	if [[ "$mode" == "cluster" ]]; then
		[[ -z "$build_exe" ]] && build_exe="$root/xpfd"
		[[ -f "$build_exe" ]] && build_exe_sha=$(sha256sum "$build_exe" | awk '{print $1}')
		# #9044: the PEER, resolved the same way. An HA gate fails over BY
		# DEFINITION, so the node a single-node attestation does not cover is
		# the node the test's outcome depends on.
		if [[ -z "$peer_node" ]]; then
			peer_node=$(
				# shellcheck disable=SC1091
				source "$HARNESS_RESULT_DIR/cluster-env.sh" >/dev/null 2>&1 &&
					printf '%s' "${FW1:-}"
			) || peer_node=""
		fi
		if [[ -z "$node" ]]; then
			# Resolve the node the same way every HA smoke does, rather than
			# re-deriving it in each Makefile recipe. cluster-env.sh is a
			# sourced library that reads $BPFRX_CLUSTER_ENV and exports FW0.
			# Runs in a subshell so nothing it sets leaks into the gate we
			# already ran.
			node=$(
				# shellcheck disable=SC1091
				source "$HARNESS_RESULT_DIR/cluster-env.sh" >/dev/null 2>&1 &&
					printf '%s' "${FW0:-}"
			) || node=""
		fi
		if [[ -n "$node" ]]; then
			# The single readback in the tree, extracted from
			# deploy_verify_running_xpfd so there is not a second one.
			#
			# It deliberately does NOT take the shared cluster lock: the gate
			# has already finished and released it, and `systemctl show` +
			# `sha256sum /proc/PID/exe` are read-only.
			#
			# It USED to read node 0 only, on the stated ground that "both
			# nodes carry the same build after a `cluster-deploy`, so one
			# readback is the attribution point for the run". That premise is
			# not a property of the system -- it is a property of ONE way of
			# invoking it. `Makefile:NODE ?= all` is a plain override and
			# `cluster-setup.sh deploy [0|1|all]` accepts the scope, so
			#
			#     make cluster-deploy NODE=0 && make test-failover
			#
			# is two ordinary lines. And the failure is ASYMMETRIC: `NODE=1`
			# fails safe (fw0 holds the old build, MISMATCH, the row is VOID),
			# while `NODE=0` is the dangerous direction -- fw0 matches, fw1
			# silently runs a different build, and the row records a clean
			# MATCH for a gate that failed over onto the unattested node. An
			# HA smoke fails over by definition, so that is the node the
			# result depends on (#9044).
			# shellcheck source=deploy-lib.sh
			[[ -n "${_XPF_DEPLOY_LIB_LOADED:-}" ]] || {
				# deploy-lib.sh documents that it depends on the SOURCING
				# script defining info/warn/die. Supply them only when the
				# caller has not -- clobbering a smoke's own die() would
				# turn its fatal path into a return.
				declare -F info >/dev/null || info() { :; }
				declare -F warn >/dev/null || warn() { printf 'harness-result: %s\n' "$*" >&2; }
				declare -F die >/dev/null || die() { printf 'harness-result: %s\n' "$*" >&2; return 1; }
				# shellcheck disable=SC1091
				source "$HARNESS_RESULT_DIR/deploy-lib.sh" 2>/dev/null || true
				_XPF_DEPLOY_LIB_LOADED=1
			}
			if declare -F deploy_running_xpfd_sha256 >/dev/null; then
				running_exe_sha=$(deploy_running_xpfd_sha256 "$node" "${XPF_EXE_READBACK_TRIES:-3}" || true)
				# #9044: and the peer, when there is one to read.
				[[ -n "$peer_node" && "$peer_node" != "$node" ]] &&
					peer_running_exe_sha=$(deploy_running_xpfd_sha256 "$peer_node" "${XPF_EXE_READBACK_TRIES:-3}" || true)
			else
				# Fails SAFE (exe_check becomes UNAVAILABLE -> the row is a
				# VOID), but say so out loud: a silent degradation here would
				# look identical to a node that is genuinely unreadable.
				_hr_warn "deploy_running_xpfd_sha256 is not available (deploy-lib.sh did not load from $HARNESS_RESULT_DIR) — the running binary cannot be read back"
			fi
		fi
	fi
	exe_check=$(harness_exe_check "${build_exe_sha:-}" "${running_exe_sha:-}" "$mode")
	exe_scope=$(harness_exe_scope "$mode" "${peer_node:-}" "${peer_running_exe_sha:-}")

	# #9044: fold the PEER into the verdict, and do it ASYMMETRICALLY on
	# purpose.
	#
	# A peer that READ BACK a DIFFERENT binary is the whole finding: the gate
	# failed over onto a node running something other than the build under
	# test, so the row is no more attributable than a local mismatch and
	# becomes a VOID by the same #2176 rule.
	#
	# A peer that could not be read is NOT a void. `test-ha-crash`,
	# `test-chained-crash` and `test-double-failover` force-stop a node and may
	# legitimately leave it down when the gate ends, so treating an unreadable
	# peer as UNAVAILABLE would VOID exactly the gates whose job is to kill a
	# node -- a loop layer breaking the gates it measures, which is the same
	# mistake the exit-status note above refuses to make. That case is recorded
	# as a PARTIAL scope instead, which is the fact ("I attested one of the two
	# nodes this gate used") the row previously could not express at all.
	if [[ "$exe_check" == "MATCH" && -n "${peer_running_exe_sha:-}" &&
		"${peer_running_exe_sha}" != "${build_exe_sha:-}" ]]; then
		exe_check="MISMATCH"
	fi

	# A measurement of a binary we cannot name is a VOID *IN THE LEDGER*, not a
	# result. The emitter refuses the other spelling, so this downgrade is not
	# optional -- it is where the refusal is satisfied.
	#
	# It downgrades the ROW ONLY. The gate's own exit status is computed from
	# $gate_verdict, captured before this point, so `make test-failover` keeps
	# exiting exactly as it did: a smoke that passed still exits 0 even on a
	# host where ./xpfd was never built. Degrading the exit status here would
	# red the mandatory HA gate for a provenance problem that says nothing
	# about the firewall -- a loop layer that breaks the gate it is measuring
	# is worse than no loop layer.
	local gate_verdict="$verdict"
	if [[ "$verdict" != "VOID" && ( "$exe_check" == "MISMATCH" || "$exe_check" == "UNAVAILABLE" ) ]]; then
		void_reason="exe_check=$exe_check: the running binary could not be confirmed to be the build under test (build_exe_sha256=${build_exe_sha:-<none>} running_exe_sha256=${running_exe_sha:-<none>} peer=${peer_node:-<none>} peer_running_exe_sha256=${peer_running_exe_sha:-<none>} exe_scope=${exe_scope:-<none>}) — the gate reported $verdict but of an unknown build (#2176/#9044)"
		verdict="VOID"
		headline=""
		direction=""
		metrics=""
		_hr_warn "$gate gate verdict was $gate_verdict but exe_check=$exe_check — the row is recorded VOID (unattributable), the gate's own exit status is unchanged"
	fi

	local ledger_arg=()
	[[ -n "$ledger" ]] && ledger_arg=(--ledger "$ledger")
	# #9922 F-087: a PASS whose row cannot be written is "passed but
	# unrecorded", not a pass. Exit 0 claims "passed AND recorded"; 2 claims
	# "could not record", which is the true one — every refusal mode that
	# degrades to 'gate exits normally, nothing recorded, all aggregates
	# green' is the defect. A measured FAIL is never demoted (rc preserved,
	# mirroring the adapter-refusal path); only the PASS branch moves, and
	# only from 0 to 2.
	local emit_failed=0
	if ! harness_result_emit \
		--gate "$gate" --env "$env" --verdict "$verdict" \
		--void-reason "$void_reason" --headline-metric "$headline" \
		--headline-direction "$direction" --metrics "$metrics" \
		--build-git-sha "$build_git_sha" --build-exe-sha256 "${build_exe_sha:-}" \
		--running-exe-sha256 "${running_exe_sha:-}" --exe-check "$exe_check" \
		--duration-s "$((t1 - t0))" --artifacts "$artifacts" --adapter "$adapter" \
		--node "$node" --node-peer "${peer_node:-}" \
		--running-exe-sha256-peer "${peer_running_exe_sha:-}" \
		--exe-scope "$exe_scope" "${ledger_arg[@]}"; then
		_hr_warn "NO ROW WRITTEN for gate '$gate' (verdict was $verdict)"
		emit_failed=1
	else
		printf 'harness-result: recorded %s %s verdict=%s\n' "$gate" "$env" "$verdict" >&2
	fi
	rm -f "$log"

	# Exit on the GATE's verdict, never the row's.
	case "$gate_verdict" in
	VOID) return 2 ;;
	FAIL) return $((rc == 0 ? 1 : rc)) ;;
	*) ((emit_failed)) && return $((rc == 0 ? 2 : rc)); return "$rc" ;;
	esac
}

# ── executable entry point ───────────────────────────────────────────
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
	sub="${1:-}"
	shift || true
	case "$sub" in
	run) harness_result_run "$@" ;;
	emit) harness_result_emit "$@" ;;
	adapt) harness_adapt "$@" ;;
	adapters) IFS=' ' read -r -a adapters <<<"$HARNESS_ADAPTERS"; printf '%s\n' "${adapters[@]}" ;;
	*)
		cat >&2 <<USAGE
usage: harness-result.sh <run|emit|adapt|adapters> ...
  run     --gate G --adapter A --env E [--cluster|--hermetic] [--node INST]
          [--build-exe PATH] [--artifacts DIR] [--ledger PATH] -- cmd...
  emit    --gate G --env E --verdict PASS|FAIL|VOID ... (see harness_result_emit)
  adapt   <adapter> <rc> <logfile>
  adapters
USAGE
		exit 2
		;;
	esac
fi
