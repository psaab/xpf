#!/usr/bin/env bash

# ha_metrics_gate <metrics_file>
# Status 0: validated metrics; stdout is shell VAR=value assignments.
# Status 2: VOID; stdout is empty and the reason is written to stderr.
ha_metrics_gate() {
	if [[ $# -ne 1 ]]; then
		printf 'metrics file: expected one path\n' >&2
		return 2
	fi

	if python3 - "$1" <<'PY'
import json
import math
import pathlib
import shlex
import sys

path = pathlib.Path(sys.argv[1])

def void(reason):
    print(reason, file=sys.stderr)
    raise SystemExit(2)

def reject_constant(value):
    raise ValueError(f"non-standard JSON constant {value}")

def finite_number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except (OverflowError, TypeError, ValueError):
        return False

def reject_nonfinite(value, location="$"):
    if type(value) in (int, float) and not finite_number(value):
        void(f"metrics JSON: non-finite number at {location}")
    if isinstance(value, dict):
        for key, item in value.items():
            reject_nonfinite(item, f"{location}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            reject_nonfinite(item, f"{location}[{index}]")
try:
    text = path.read_text(encoding="utf-8")
except FileNotFoundError:
    void(f"metrics file {path}: absent")
except (OSError, UnicodeError) as exc:
    void(f"metrics file {path}: unreadable ({exc})")

try:
    metrics = json.loads(text, parse_constant=reject_constant)
except (json.JSONDecodeError, ValueError, RecursionError) as exc:
    void(f"metrics file {path}: invalid JSON ({exc})")

if not isinstance(metrics, dict):
    void(f"metrics file {path}: invalid JSON (top-level value is not an object)")

# Rule 2: check the status marker before trusting any metric field.
if type(metrics.get("ok")) is not bool or metrics["ok"] is not True:
    error = metrics.get("error", "absent")
    void(f"metrics ok=false: {error}")

# Rule 3: the error field is a required, empty string, even when ok is true.
error = metrics.get("error")
if not isinstance(error, str):
    void("metrics error: malformed")
if error:
    void(f"metrics error: {error}")

# Rule 4: this is the consumer's full-interval evidence, not a producer default.
intervals = metrics.get("interval_gbps")
if not isinstance(intervals, list) or not intervals:
    void("no full iperf3 intervals")
full_interval_count = len(intervals)

reject_nonfinite(metrics)
for index, value in enumerate(intervals):
    if not finite_number(value):
        void(f"metrics field interval_gbps[{index}]: malformed")
# Rule 5: JSON booleans are not numbers, and integer fields must be exact ints.
required_types = {
    "avg_gbps": "number",
    "zero_intervals_total": "int",
    "stream_zero_intervals_total": "int",
    "zero_streams_total": "int",
    "retransmits": "int",
    "collapse_detected": "bool",
    "collapse_reason": "string",
    "completed": "bool",
    "observed_end_sec": "number",
}
for name, expected in required_types.items():
    if name not in metrics:
        void(f"metrics field {name}: absent")
    value = metrics[name]
    if expected == "number":
        valid = finite_number(value)
    elif expected == "int":
        valid = type(value) is int and finite_number(value)
    elif expected == "bool":
        valid = type(value) is bool
    else:
        valid = isinstance(value, str)
    if not valid:
        void(f"metrics field {name}: malformed")

# Keep this list aligned with required_types and the N6 handoff contract.
validated = (
    "avg_gbps",
    "zero_intervals_total",
    "stream_zero_intervals_total",
    "zero_streams_total",
    "retransmits",
    "collapse_detected",
    "collapse_reason",
    "completed",
    "observed_end_sec",
)
print(f"full_interval_count={full_interval_count}")
for name in validated:
    value = metrics[name]
    if isinstance(value, bool):
        shell_value = "true" if value else "false"
    else:
        shell_value = str(value)
    print(f"{name}={shlex.quote(shell_value)}")
PY
	then
		return 0
	fi
	return 2
}
# Pure parser and verdict APIs shared by the legacy and reached HA validators.
# Parse/value helpers print a value and return 0, or return 2 with a VOID reason
# on stderr. Verdict helpers return 0=PASS, 1=measured FAIL, 2=VOID.

ha_status_summary_value() {
	if [[ $# -ne 2 ]]; then
		printf 'status summary: expected <file> <label>\n' >&2
		return 2
	fi
	if python3 - "$1" "$2" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
label = sys.argv[2]
try:
    text = path.read_text(encoding="utf-8")
except (OSError, UnicodeError) as exc:
    print(f"status summary {path}: unreadable ({exc})", file=sys.stderr)
    raise SystemExit(2)

pattern = re.compile(r"^\s*" + re.escape(label) + r":\s*(.*)$")
matches = [match.group(1) for line in text.splitlines() if (match := pattern.match(line))]
if len(matches) != 1:
    reason = "missing" if not matches else "ambiguous"
    print(f"status summary {path}: {label!r} {reason}", file=sys.stderr)
    raise SystemExit(2)
match = re.match(r"^(\d+)(?:\s|$)", matches[0])
if not match:
    print(f"status summary {path}: {label!r} malformed", file=sys.stderr)
    raise SystemExit(2)
print(match.group(1))
PY
	then
		return 0
	fi
	return 2
}

ha_sync_stats_value() {
	if [[ $# -ne 3 ]]; then
		printf 'sync statistics: expected <file> <service> <sent|received>\n' >&2
		return 2
	fi
	if python3 - "$1" "$2" "$3" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
service = sys.argv[2]
column = sys.argv[3]
if column not in ("sent", "received"):
    print(f"sync statistics: unsupported column {column!r}", file=sys.stderr)
    raise SystemExit(2)
try:
    lines = path.read_text(encoding="utf-8").splitlines()
except (OSError, UnicodeError) as exc:
    print(f"sync statistics {path}: unreadable ({exc})", file=sys.stderr)
    raise SystemExit(2)

capture = False
found_section = False
matches = []
for line in lines:
    if line.strip() == "Services Synchronized:":
        if found_section:
            print(f"sync statistics {path}: duplicate Services Synchronized section", file=sys.stderr)
            raise SystemExit(2)
        capture = found_section = True
        continue
    if capture and not line.strip():
        capture = False
    if not capture or not line.strip().startswith(service):
        continue
    suffix = line.strip()[len(service):]
    values = re.findall(r"\d+", suffix)
    if len(values) < 2:
        print(f"sync statistics {path}: {service!r} row malformed", file=sys.stderr)
        raise SystemExit(2)
    matches.append(values[0 if column == "sent" else 1])
if not found_section:
    print(f"sync statistics {path}: Services Synchronized section missing", file=sys.stderr)
    raise SystemExit(2)
if len(matches) != 1:
    reason = "missing" if not matches else "ambiguous"
    print(f"sync statistics {path}: {service!r} row {reason}", file=sys.stderr)
    raise SystemExit(2)
print(matches[0])
PY
	then
		return 0
	fi
	return 2
}

# One sample of the legacy 3-consecutive-idle rule. Endpoint names and both
# files are explicit; callers must not derive direction from ambient globals.
ha_session_sync_idle_sample() {
	if [[ $# -ne 4 ]]; then
		printf 'session sync sample: expected <source-node> <target-node> <source-stats> <target-stats>\n' >&2
		return 2
	fi
	local source_node="$1"
	local target_node="$2"
	local source_path="$3"
	local target_path="$4"
	local sent received pending drained
	if ! sent="$(ha_sync_stats_value "$source_path" "Session create" sent)"; then return 2; fi
	if ! received="$(ha_sync_stats_value "$target_path" "Session create" received)"; then return 2; fi
	if ! pending="$(ha_status_summary_value "$target_path" "Session delta pending")"; then return 2; fi
	if ! drained="$(ha_status_summary_value "$target_path" "Session delta drained")"; then return 2; fi
	: "$drained" # Required and parseable, informational only.
	if [[ "$sent" == "$received" && "$pending" == "0" ]]; then
		return 0
	fi
	printf 'session sync %s->%s not idle: source sent=%s, target received=%s, pending=%s\n' \
		"$source_node" "$target_node" "$sent" "$received" "$pending" >&2
	return 1
}

ha_interface_packets_value() {
	if [[ $# -ne 3 ]]; then
		printf 'interface counters: expected <file> <interface-regex> <rx|tx>\n' >&2
		return 2
	fi
	if python3 - "$1" "$2" "$3" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
try:
    iface_regex = re.compile(sys.argv[2])
except re.error as exc:
    print(f"interface counters: invalid interface regex ({exc})", file=sys.stderr)
    raise SystemExit(2)
direction = sys.argv[3]
if direction not in ("rx", "tx"):
    print(f"interface counters: unsupported direction {direction!r}", file=sys.stderr)
    raise SystemExit(2)
try:
    lines = path.read_text(encoding="utf-8").splitlines()
except (OSError, UnicodeError) as exc:
    print(f"interface counters {path}: unreadable ({exc})", file=sys.stderr)
    raise SystemExit(2)

in_bindings = False
found_section = False
skip_header = False
matched = False
total = 0
packet_indexes = (10, 11)
for raw in lines:
    stripped = raw.strip()
    if stripped == "Userspace bindings:":
        if found_section:
            print(f"interface counters {path}: duplicate Userspace bindings section", file=sys.stderr)
            raise SystemExit(2)
        in_bindings = found_section = True
        skip_header = True
        continue
    if in_bindings and not stripped:
        in_bindings = False
        continue
    if not in_bindings:
        continue
    if skip_header:
        skip_header = False
        continue
    parts = stripped.split()
    if len(parts) < 20:
        print(f"interface counters {path}: malformed bindings row", file=sys.stderr)
        raise SystemExit(2)
    counters = []
    for index in packet_indexes:
        value = parts[index]
        if not re.fullmatch(r"\d+", value):
            print(f"interface counters {path}: malformed packet counter {value!r}", file=sys.stderr)
            raise SystemExit(2)
        counters.append(int(value))
    if iface_regex.fullmatch(parts[19]):
        matched = True
        total += counters[0 if direction == "rx" else 1]
if not found_section:
    print(f"interface counters {path}: Userspace bindings section missing", file=sys.stderr)
    raise SystemExit(2)
if not matched:
    print(f"interface counters {path}: no interface matches /{iface_regex.pattern}/", file=sys.stderr)
    raise SystemExit(2)
print(total)
PY
	then
		return 0
	fi
	return 2
}

ha_status_fabric_tx_packets() {
	if [[ $# -ne 1 ]]; then
		printf 'fabric counters: expected <interfaces-file>\n' >&2
		return 2
	fi
	if python3 - "$1" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
try:
    lines = path.read_text(encoding="utf-8").splitlines()
except (OSError, UnicodeError) as exc:
    print(f"fabric counters {path}: unreadable ({exc})", file=sys.stderr)
    raise SystemExit(2)

parents = set()
bindings = []
section = None
skip_header = False
seen = set()
for raw in lines:
    stripped = raw.strip()
    if stripped in ("Userspace fabric links:", "Userspace bindings:"):
        name = "fabric" if stripped == "Userspace fabric links:" else "bindings"
        if name in seen:
            print(f"fabric counters {path}: duplicate {stripped} section", file=sys.stderr)
            raise SystemExit(2)
        seen.add(name)
        section = name
        skip_header = True
        continue
    if section and not stripped:
        section = None
        continue
    if not section:
        continue
    if skip_header:
        skip_header = False
        continue
    parts = stripped.split()
    if section == "fabric":
        if len(parts) < 2:
            print(f"fabric counters {path}: malformed fabric link row", file=sys.stderr)
            raise SystemExit(2)
        parents.add(parts[1])
        continue
    if len(parts) < 20 or not re.fullmatch(r"\d+", parts[11]):
        print(f"fabric counters {path}: malformed bindings row/TX counter", file=sys.stderr)
        raise SystemExit(2)
    bindings.append((parts[19], int(parts[11])))
if "fabric" not in seen:
    print(f"fabric counters {path}: Userspace fabric links section missing", file=sys.stderr)
    raise SystemExit(2)
if "bindings" not in seen:
    print(f"fabric counters {path}: Userspace bindings section missing", file=sys.stderr)
    raise SystemExit(2)
if not parents:
    print(f"fabric counters {path}: no fabric parents", file=sys.stderr)
    raise SystemExit(2)
if not bindings:
    print(f"fabric counters {path}: no bindings rows", file=sys.stderr)
    raise SystemExit(2)
total = sum(packets for interface, packets in bindings if interface in parents)
if not any(interface in parents for interface, _ in bindings):
    print(f"fabric counters {path}: no bindings use a fabric parent", file=sys.stderr)
    raise SystemExit(2)
print(total)
PY
	then
		return 0
	fi
	return 2
}

ha_nondecreasing_delta() {
	if [[ $# -ne 2 ]]; then
		printf 'counter delta: expected <baseline> <post>\n' >&2
		return 2
	fi
	if python3 - "$1" "$2" <<'PY'
import re
import sys

baseline_text, post_text = sys.argv[1:]
if not re.fullmatch(r"\d+", baseline_text) or not re.fullmatch(r"\d+", post_text):
    print(f"counter values malformed: {baseline_text!r} {post_text!r}", file=sys.stderr)
    raise SystemExit(2)
baseline = int(baseline_text)
post = int(post_text)
if post < baseline:
    print(f"counter decreased from {baseline} to {post}", file=sys.stderr)
    raise SystemExit(2)
print(post - baseline)
PY
	then
		return 0
	fi
	return 2
}

# Verify the provenance header emitted by the reached caller before parsing any
# counters. A snapshot is one slice/phase/node/RG tuple, never interchangeable.
ha_snapshot_identity_verdict() {
	if [[ $# -ne 5 ]]; then
		printf 'snapshot identity: expected <file> <slice> <phase> <node> <rg>\n' >&2
		return 2
	fi
	if python3 - "$@" <<'PY'
import pathlib
import sys

path, slice_name, phase, node, rg = sys.argv[1:]
try:
    lines = pathlib.Path(path).read_text(encoding="utf-8").splitlines()
except (OSError, UnicodeError) as exc:
    print(f"snapshot identity {path}: unreadable ({exc})", file=sys.stderr)
    raise SystemExit(2)

identity_lines = [line for line in lines if line.startswith("HA capture identity:")]
if len(identity_lines) != 1:
    reason = "missing" if not identity_lines else "ambiguous"
    print(f"snapshot identity {path}: {reason}", file=sys.stderr)
    raise SystemExit(2)
expected = (
    f"HA capture identity: slice={slice_name} phase={phase} "
    f"node={node} rg={rg}"
)
if identity_lines[0] != expected:
    print(
        f"snapshot identity {path}: expected {expected!r}, got {identity_lines[0]!r}",
        file=sys.stderr,
    )
    raise SystemExit(2)
if not any(line.strip() for line in lines[1:]):
    print(f"snapshot identity {path}: capture body is empty", file=sys.stderr)
    raise SystemExit(2)
PY
	then
		return 0
	fi
	return 2
}

# Both node queries must independently report the exact requested RG owner.
# Well-formed but unsettled/wrong ownership is measured FAIL; blind status or
# provenance is VOID.
ha_rg_owner_verdict() {
	if [[ $# -ne 5 ]]; then
		printf 'RG owner: expected <node0|node1> <rg> <phase> <node0-status> <node1-status>\n' >&2
		return 2
	fi
	local expected_node="$1" rg="$2" phase="$3"
	if [[ "$expected_node" != node0 && "$expected_node" != node1 ]] \
		|| [[ ! "$rg" =~ ^[0-9]+$ ]]; then
		printf 'RG owner: malformed expected node or RG\n' >&2
		return 2
	fi
	if ! ha_snapshot_identity_verdict "$4" manual-rg1-failback "$phase" node0 "$rg"; then
		return 2
	fi
	if ! ha_snapshot_identity_verdict "$5" manual-rg1-failback "$phase" node1 "$rg"; then
		return 2
	fi
	if python3 - "$expected_node" "$rg" "$4" "$5" <<'PY'
import pathlib
import re
import sys

expected_node, rg_text, *paths = sys.argv[1:]
rg = int(rg_text)
header_re = re.compile(r"^Redundancy group:\s*(\d+)\s*,")
row_re = re.compile(
    r"^node([01])\s+\d+\s+(primary|secondary-hold|secondary|hold|disabled|lost)\b",
    re.IGNORECASE,
)

def read_rg_owner(path):
    try:
        lines = pathlib.Path(path).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        print(f"RG owner {path}: unreadable ({exc})", file=sys.stderr)
        raise SystemExit(2)
    current_rg = None
    matches = []
    for line in lines:
        header = header_re.match(line)
        if header:
            current_rg = int(header.group(1))
            continue
        if current_rg != rg:
            continue
        row = row_re.match(line)
        if row:
            matches.append((f"node{row.group(1)}", row.group(2).lower()))
    states = dict(matches)
    if len(matches) != 2 or set(states) != {"node0", "node1"}:
        print(f"RG owner {path}: RG{rg} status rows missing, malformed, or ambiguous", file=sys.stderr)
        raise SystemExit(2)
    return states

statuses = [read_rg_owner(path) for path in paths]
peer = "node1" if expected_node == "node0" else "node0"
if all(status[expected_node] == "primary" and status[peer] == "secondary" for status in statuses):
    raise SystemExit(0)
details = "; ".join(
    f"query{index}: node0={status['node0']} node1={status['node1']}"
    for index, status in enumerate(statuses, 1)
)
print(f"RG{rg} has not settled with {expected_node} primary: {details}", file=sys.stderr)
raise SystemExit(10)
PY
	then
		return 0
	else
		local status=$?
		if (( status == 10 )); then return 1; fi
	fi
	return 2
}

ha_counter_at_most_verdict() {
	if [[ $# -ne 3 ]]; then
		printf 'counter budget: expected <value> <limit> <label>\n' >&2
		return 2
	fi
	local value="$1" limit="$2" label="$3"
	if [[ ! "$value" =~ ^[0-9]+$ || ! "$limit" =~ ^[0-9]+$ ]]; then
		printf '%s counter or limit is malformed (%s, limit %s)\n' "$label" "$value" "$limit" >&2
		return 2
	fi
	if (( value <= limit )); then return 0; fi
	printf '%s delta %s exceeds limit %s\n' "$label" "$value" "$limit" >&2
	return 1
}

ha_snapshot_counter_delta() {
	if [[ $# -ne 8 ]]; then
		printf 'snapshot counter delta: expected <slice> <rg> <node> <label> <before-phase> <before-file> <after-phase> <after-file>\n' >&2
		return 2
	fi
	local slice="$1" rg="$2" node="$3" label="$4"
	local before_phase="$5" before_file="$6" after_phase="$7" after_file="$8"
	local before_value after_value
	if ! ha_snapshot_identity_verdict "$before_file" "$slice" "$before_phase" "$node" "$rg"; then return 2; fi
	if ! ha_snapshot_identity_verdict "$after_file" "$slice" "$after_phase" "$node" "$rg"; then return 2; fi
	if ! before_value="$(ha_status_summary_value "$before_file" "$label")"; then return 2; fi
	if ! after_value="$(ha_status_summary_value "$after_file" "$label")"; then return 2; fi
	ha_nondecreasing_delta "$before_value" "$after_value"
}

ha_pair_counter_budget_verdict() {
	if [[ $# -ne 10 ]]; then
		printf 'paired counter budget: expected <limit> <label> <slice> <rg> <before-phase> <after-phase> <node0-before> <node1-before> <node0-after> <node1-after>\n' >&2
		return 2
	fi
	local limit="$1" label="$2" slice="$3" rg="$4" before_phase="$5" after_phase="$6"
	local node0_delta node1_delta total
	if ! node0_delta="$(ha_snapshot_counter_delta "$slice" "$rg" node0 "$label" \
		"$before_phase" "$7" "$after_phase" "$9")"; then return 2; fi
	if ! node1_delta="$(ha_snapshot_counter_delta "$slice" "$rg" node1 "$label" \
		"$before_phase" "$8" "$after_phase" "${10}")"; then return 2; fi
	if [[ ! "$limit" =~ ^[0-9]+$ ]]; then
		printf '%s counter limit is malformed: %s\n' "$label" "$limit" >&2
		return 2
	fi
	total=$((node0_delta + node1_delta))
	if (( total <= limit )); then return 0; fi
	printf '%s paired delta %s (node0=%s node1=%s) exceeds limit %s\n' \
		"$label" "$total" "$node0_delta" "$node1_delta" "$limit" >&2
	return 1
}

ha_snapshot_interface_delta() {
	if [[ $# -ne 9 ]]; then
		printf 'snapshot interface delta: expected <slice> <rg> <node> <regex> <direction> <before-phase> <before-file> <after-phase> <after-file>\n' >&2
		return 2
	fi
	local slice="$1" rg="$2" node="$3" regex="$4" direction="$5"
	local before_phase="$6" before_file="$7" after_phase="$8" after_file="$9"
	local before_value after_value
	if ! ha_snapshot_identity_verdict "$before_file" "$slice" "$before_phase" "$node" "$rg"; then return 2; fi
	if ! ha_snapshot_identity_verdict "$after_file" "$slice" "$after_phase" "$node" "$rg"; then return 2; fi
	if ! before_value="$(ha_interface_packets_value "$before_file" "$regex" "$direction")"; then return 2; fi
	if ! after_value="$(ha_interface_packets_value "$after_file" "$regex" "$direction")"; then return 2; fi
	ha_nondecreasing_delta "$before_value" "$after_value"
}

ha_snapshot_interface_budget_verdict() {
	if [[ $# -ne 11 ]]; then
		printf 'snapshot interface budget: expected <limit> <regex> <direction> <label> <slice> <rg> <node> <before-phase> <before-file> <after-phase> <after-file>\n' >&2
		return 2
	fi
	local delta
	if ! delta="$(ha_snapshot_interface_delta "$5" "$6" "$7" "$2" "$3" "$8" "$9" "${10}" "${11}")"; then
		return 2
	fi
	ha_counter_at_most_verdict "$delta" "$1" "$4"
}

ha_snapshot_fabric_tx_delta() {
	if [[ $# -ne 7 ]]; then
		printf 'snapshot fabric delta: expected <slice> <rg> <node> <before-phase> <before-file> <after-phase> <after-file>\n' >&2
		return 2
	fi
	local before_value after_value
	if ! ha_snapshot_identity_verdict "$5" "$1" "$4" "$3" "$2"; then return 2; fi
	if ! ha_snapshot_identity_verdict "$7" "$1" "$6" "$3" "$2"; then return 2; fi
	if ! before_value="$(ha_status_fabric_tx_packets "$5")"; then return 2; fi
	if ! after_value="$(ha_status_fabric_tx_packets "$7")"; then return 2; fi
	ha_nondecreasing_delta "$before_value" "$after_value"
}

ha_fabric_activity_verdict() {
	if [[ $# -ne 5 ]]; then
		printf 'fabric activity: expected <fabric-delta> <old-owner-churn> <minimum> <trigger> <required>\n' >&2
		return 2
	fi
	local fabric="$1" churn="$2" minimum="$3" trigger="$4" required="$5"
	if [[ ! "$fabric" =~ ^[0-9]+$ || ! "$churn" =~ ^[0-9]+$ \
		|| ! "$minimum" =~ ^[0-9]+$ || ! "$trigger" =~ ^[0-9]+$ \
		|| ( "$required" != 0 && "$required" != 1 ) ]]; then
		printf 'fabric activity: malformed counter, threshold, or required flag\n' >&2
		return 2
	fi
	if [[ "$required" != 1 ]] || (( fabric >= minimum )); then return 0; fi
	if (( churn >= trigger )); then
		printf 'fabric TX delta %s is below %s with old-owner churn %s at/above trigger %s\n' \
			"$fabric" "$minimum" "$churn" "$trigger" >&2
		return 1
	fi
	printf 'fabric TX delta %s is below %s; old-owner churn %s is below trigger %s\n' \
		"$fabric" "$minimum" "$churn" "$trigger" >&2
	return 0
}

ha_transition_path_verdict() {
	if [[ $# -ne 8 ]]; then
		printf 'transition path: expected <lan-rx> <old-fabric-tx> <new-fabric-rx> <new-wan-tx> <trigger> <min-fabric-tx> <min-fabric-rx> <min-wan-tx>\n' >&2
		return 2
	fi
	local lan_rx="$1" old_fabric_tx="$2" new_fabric_rx="$3" new_wan_tx="$4"
	local trigger="$5" min_fabric_tx="$6" min_fabric_rx="$7" min_wan_tx="$8"
	local value
	for value in "$@"; do
		if [[ ! "$value" =~ ^[0-9]+$ ]]; then
			printf 'transition path: malformed counter or threshold %s\n' "$value" >&2
			return 2
		fi
	done
	if (( lan_rx < trigger )); then
		printf 'old-owner LAN RX %s below trigger %s\n' "$lan_rx" "$trigger" >&2
		return 0
	fi
	if (( old_fabric_tx < min_fabric_tx || new_fabric_rx < min_fabric_rx || new_wan_tx < min_wan_tx )); then
		printf 'transition path below minimum: LAN RX=%s old fabric TX=%s (min %s) new fabric RX=%s (min %s) new WAN TX=%s (min %s)\n' \
			"$lan_rx" "$old_fabric_tx" "$min_fabric_tx" "$new_fabric_rx" "$min_fabric_rx" "$new_wan_tx" "$min_wan_tx" >&2
		return 1
	fi
	return 0
}

ha_rg_standby_status_verdict() {
	if [[ $# -ne 5 ]]; then
		printf 'RG standby status: expected <file> <slice> <phase> <node> <rg>\n' >&2
		return 2
	fi
	if ! ha_snapshot_identity_verdict "$1" "$2" "$3" "$4" "$5"; then return 2; fi
	ha_standby_status_verdict "$1" "$5"
}

ha_sample_window_max() {
	if (( $# < 15 )); then
		printf 'sample maximum: expected <slice> <rg> <node> <label>, ten statistics files, and <phase-pre baseline>\n' >&2
		return 2
	fi
	local slice="$1" rg="$2" node="$3" label="$4" index phase path value maximum="" baseline previous
	local -a args=("$@")
	baseline="${args[14]}"
	if [[ ! "$baseline" =~ ^[0-9]+$ ]]; then
		printf 'sample maximum: baseline is not an unsigned counter\n' >&2
		return 2
	fi
	previous="$baseline"
	for ((index = 0; index < 10; index++)); do
		phase=$(printf 'sample-%02d' "$((index + 1))")
		path="${args[index + 4]}"
		if ! ha_snapshot_identity_verdict "$path" "$slice" "$phase" "$node" "$rg"; then return 2; fi
		if ! value="$(ha_status_summary_value "$path" "$label")"; then return 2; fi
		if [[ ! "$value" =~ ^[0-9]+$ ]]; then
			printf 'sample maximum: %s is not an unsigned counter in %s\n' "$label" "$path" >&2
			return 2
		fi
		if (( value < previous )); then
			printf 'sample maximum: %s counter rewound from %s to %s at %s\n' "$label" "$previous" "$value" "$phase" >&2
			return 2
		fi
		previous="$value"
		if [[ -z "$maximum" ]] || (( value > maximum )); then maximum="$value"; fi
	done
	printf '%s\n' "$maximum"
}

ha_sample_window_interface_max() {
	if (( $# < 16 )); then
		printf 'sample interface maximum: expected <slice> <rg> <node> <regex> <direction>, ten interface files, and <phase-pre baseline>\n' >&2
		return 2
	fi
	local slice="$1" rg="$2" node="$3" regex="$4" direction="$5"
	local index phase path value maximum="" baseline previous
	local -a args=("$@")
	baseline="${args[15]}"
	if [[ ! "$baseline" =~ ^[0-9]+$ ]]; then
		printf 'sample interface maximum: baseline is not an unsigned counter\n' >&2
		return 2
	fi
	previous="$baseline"
	for ((index = 0; index < 10; index++)); do
		phase=$(printf 'sample-%02d' "$((index + 1))")
		path="${args[index + 5]}"
		if ! ha_snapshot_identity_verdict "$path" "$slice" "$phase" "$node" "$rg"; then return 2; fi
		if ! value="$(ha_interface_packets_value "$path" "$regex" "$direction")"; then return 2; fi
		if [[ ! "$value" =~ ^[0-9]+$ ]]; then
			printf 'sample interface maximum: malformed counter in %s\n' "$path" >&2
			return 2
		fi
		if (( value < previous )); then
			printf 'sample interface maximum: counter rewound from %s to %s at %s\n' "$previous" "$value" "$phase" >&2
			return 2
		fi
		previous="$value"
		if [[ -z "$maximum" ]] || (( value > maximum )); then maximum="$value"; fi
	done
	printf '%s\n' "$maximum"
}


ha_standby_status_verdict() {
	if [[ $# -ne 2 ]]; then
		printf 'standby status: expected <statistics-file> <rg>\n' >&2
		return 2
	fi
	local result
	if python3 - "$1" "$2" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
rg = sys.argv[2]
if not re.fullmatch(r"\d+", rg):
    print(f"standby status: malformed redundancy group {rg!r}", file=sys.stderr)
    raise SystemExit(2)
try:
    lines = path.read_text(encoding="utf-8").splitlines()
except (OSError, UnicodeError) as exc:
    print(f"standby status {path}: unreadable ({exc})", file=sys.stderr)
    raise SystemExit(2)

patterns = {
    "Enabled": re.compile(r"^\s*Enabled:\s*(true|false)\s*$"),
    "Forwarding armed": re.compile(r"^\s*Forwarding armed:\s*(true|false)\s*$"),
    f"rg{rg} active": re.compile(rf"^\s*rg{re.escape(rg)} active=(true|false)\s*$"),
    "Ready bindings": re.compile(r"^\s*Ready bindings:\s*(\d+)/(\d+)\s*$"),
}
values = {}
for key, pattern in patterns.items():
    matches = [pattern.match(line) for line in lines]
    matches = [match for match in matches if match]
    if len(matches) != 1:
        reason = "missing" if not matches else "ambiguous"
        print(f"standby status {path}: {key} field {reason}", file=sys.stderr)
        raise SystemExit(2)
    values[key] = matches[0].groups()

ready, total = (int(value) for value in values["Ready bindings"])
if int(total) <= 0 or int(ready) > int(total):
    print(f"standby status {path}: Ready bindings field malformed", file=sys.stderr)
    raise SystemExit(2)
failures = []
if values["Enabled"][0] != "true":
    failures.append("Enabled is not true")
if values["Forwarding armed"][0] != "true":
    failures.append("Forwarding armed is not true")
if values[f"rg{rg} active"][0] != "false":
    failures.append(f"rg{rg} is active")
if ready <= 0:
    failures.append("no ready bindings")
if failures:
    print(f"standby status {path}: " + "; ".join(failures), file=sys.stderr)
    raise SystemExit(10)
PY
	then
		return 0
	else
		result=$?
	fi
	if (( result == 10 )); then return 1; fi
	return 2
}

ha_ttl_output_verdict() {
	if [[ $# -ne 2 ]]; then
		printf 'TTL probe: expected <command-status> <output>\n' >&2
		return 2
	fi
	local command_status="$1"
	local output="$2"
	if [[ ! "$command_status" =~ ^[0-9]+$ ]] || (( command_status > 1 )) || [[ -z "${output//[[:space:]]/}" ]]; then
		printf 'TTL probe: capture unavailable or command failed (status=%s)\n' "$command_status" >&2
		return 2
	fi
	if [[ "$output" =~ Time[[:space:]]to[[:space:]]live[[:space:]]exceeded|Time[[:space:]]exceeded:[[:space:]]Hop[[:space:]]limit|Time[[:space:]]exceeded ]]; then
		return 0
	fi
	printf 'TTL probe: valid capture did not contain time-exceeded evidence\n' >&2
	return 1
}

ha_ping_reply_verdict() {
	if [[ $# -ne 2 ]]; then
		printf 'ping reply: expected <command-status> <output>\n' >&2
		return 2
	fi
	local verdict_status
	if python3 - "$1" "$2" <<'PY'
import re
import sys

status_text, output = sys.argv[1:]
if not re.fullmatch(r"\d+", status_text) or int(status_text) > 1 or not output.strip():
    print(f"ping reply: capture unavailable (status={status_text})", file=sys.stderr)
    raise SystemExit(2)
match = re.search(r"\b(\d+)\s+(?:packets?\s+)?received\b", output, re.IGNORECASE)
if not match:
    print("ping reply: valid output has no parseable received count", file=sys.stderr)
    raise SystemExit(2)
received = int(match.group(1))
if received:
    raise SystemExit(0)
print("ping reply: valid probe received zero packets", file=sys.stderr)
raise SystemExit(10)
PY
	then
		return 0
	else
		verdict_status=$?
	fi
	if (( verdict_status == 10 )); then return 1; fi
	return 2
}


ha_external_ping_verdict() {
	if [[ $# -ne 2 ]]; then
		printf 'external ping: expected <command-status> <output>\n' >&2
		return 2
	fi
	local command_status="$1" output="$2"
	if [[ ! "$command_status" =~ ^[0-9]+$ ]] || (( command_status > 1 )) \
		|| [[ -z "${output//[[:space:]]/}" ]]; then
		printf 'external ping: capture unavailable or command failed (status=%s)\n' "$command_status" >&2
		return 2
	fi
	if [[ "$output" =~ bytes[[:space:]]from ]]; then return 0; fi
	printf 'external ping: valid capture contains no bytes from %s\n' "${output%%$'\n'*}" >&2
	return 1
}
ha_target_reachability_verdict() {
	if [[ $# -ne 4 ]]; then
		printf 'target reachability: expected <ping-status> <ping-output> <tcp-status> <tcp-output>\n' >&2
		return 2
	fi
	local ping_status="$1"
	local ping_output="$2"
	local tcp_status="$3"
	local tcp_output="$4"
	local ping_verdict
	if ha_ping_reply_verdict "$ping_status" "$ping_output" 2>/dev/null; then
		return 0
	else
		ping_verdict=$?
	fi
	if (( ping_verdict == 2 )); then
		printf 'target reachability: ping capture unavailable\n' >&2
		return 2
	fi
	if [[ ! "$tcp_status" =~ ^[0-9]+$ ]] || (( tcp_status == 127 )); then
		printf 'target reachability: TCP fallback command unavailable (status=%s)\n' "$tcp_status" >&2
		return 2
	fi
	if [[ "$tcp_status" == "0" ]]; then
		return 0
	fi
	if (( tcp_status == 124 )); then
		printf 'target reachability: TCP fallback timed out\n' >&2
		return 1
	fi
	if [[ -z "${tcp_output//[[:space:]]/}" ]] || (( tcp_status > 1 )); then
		printf 'target reachability: TCP fallback capture unavailable (status=%s)\n' "$tcp_status" >&2
		return 2
	fi
	printf 'target reachability: ping and TCP fallback both failed\n' >&2
	return 1
}

ha_route_device() {
	if [[ $# -ne 1 ]]; then
		printf 'route device: expected <route-output>\n' >&2
		return 2
	fi
	if python3 - "$1" <<'PY'
import sys

output = sys.argv[1]
lines = [line.split() for line in output.splitlines() if line.strip()]
if len(lines) != 1:
    print("route device: route output missing or ambiguous", file=sys.stderr)
    raise SystemExit(2)
tokens = lines[0]
device_positions = [index for index, token in enumerate(tokens) if token == "dev"]
if len(device_positions) != 1:
    print("route device: route output has no unique device", file=sys.stderr)
    raise SystemExit(2)
position = device_positions[0]
if position + 1 == len(tokens):
    print("route device: device name is missing", file=sys.stderr)
    raise SystemExit(2)
device = tokens[position + 1]
if (
    device in {".", ".."}
    or "/" in device
    or any(character.isspace() for character in device)
    or len(device.encode()) > 15
):
    print("route device: malformed interface name", file=sys.stderr)
    raise SystemExit(2)
print(device)
PY
	then
		return 0
	fi
	return 2
}

ha_route_lookup_verdict() {
	if [[ $# -ne 2 ]]; then
		printf 'route lookup: expected <command-status> <route-output>\n' >&2
		return 2
	fi
	local verdict_status
	if python3 - "$1" "$2" <<'PY'
import re
import sys

status_text, output = sys.argv[1:]
if status_text != "0" or not output.strip():
    print(f"route lookup: capture unavailable (status={status_text})", file=sys.stderr)
    raise SystemExit(2)
lines = [line.split() for line in output.splitlines() if line.strip()]
if len(lines) != 1:
    print("route lookup: route output missing or ambiguous", file=sys.stderr)
    raise SystemExit(2)
tokens = lines[0]
if any(token == "local" for token in tokens) or any(
    tokens[index] == "dev" and tokens[index + 1] == "lo"
    for index in range(len(tokens) - 1)
):
    print("route lookup: destination resolves locally or through loopback", file=sys.stderr)
    raise SystemExit(10)
devices = [tokens[index + 1] for index, token in enumerate(tokens[:-1]) if token == "dev"]
if len(devices) != 1 or not devices[0]:
    print("route lookup: route output has no unique device", file=sys.stderr)
    raise SystemExit(2)
PY
	then
		return 0
	else
		verdict_status=$?
	fi
	if (( verdict_status == 10 )); then return 1; fi
	return 2
}

ha_neighbor_identity_verdict() {
	if [[ $# -ne 4 ]]; then
		printf 'neighbor identity: expected <v4-route-device> <v4-neighbor-output> <v6-route-device> <v6-neighbor-output>\n' >&2
		return 2
	fi
	local verdict_status
	if python3 - "$@" <<'PY'
import re
import sys

v4_device, v4_output, v6_device, v6_output = sys.argv[1:]
usable = {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"}
unusable = {"FAILED", "INCOMPLETE", "NOARP", "NONE"}
if not v4_device or not v6_device:
    print("neighbor identity: route device missing", file=sys.stderr)
    raise SystemExit(2)
if v4_device != v6_device:
    print(f"neighbor identity: route devices differ ({v4_device} vs {v6_device})", file=sys.stderr)
    raise SystemExit(10)

def parse_neighbor(label, expected_device, output):
    lines = [line.split() for line in output.splitlines() if line.strip()]
    if not lines:
        print(f"neighbor identity: {label} entry missing", file=sys.stderr)
        raise SystemExit(2)
    if len(lines) != 1:
        print(f"neighbor identity: {label} output ambiguous", file=sys.stderr)
        raise SystemExit(2)
    tokens = lines[0]
    devices = [tokens[index + 1] for index, token in enumerate(tokens[:-1]) if token == "dev"]
    if len(devices) > 1:
        print(f"neighbor identity: {label} device field ambiguous", file=sys.stderr)
        raise SystemExit(2)
    device = devices[0] if devices else expected_device
    if device != expected_device:
        print(f"neighbor identity: {label} device {device} differs from route device {expected_device}", file=sys.stderr)
        raise SystemExit(10)
    states = [token.upper() for token in tokens if token.upper() in usable | unusable]
    if len(states) != 1:
        print(f"neighbor identity: {label} NUD state missing or ambiguous", file=sys.stderr)
        raise SystemExit(2)
    state = states[0]
    if state in unusable:
        print(f"neighbor identity: {label} state {state} is unusable", file=sys.stderr)
        raise SystemExit(10)
    if "lladdr" not in tokens:
        print(f"neighbor identity: {label} MAC missing", file=sys.stderr)
        raise SystemExit(2)
    mac_index = tokens.index("lladdr") + 1
    if mac_index >= len(tokens) or not tokens[mac_index].strip():
        print(f"neighbor identity: {label} MAC malformed", file=sys.stderr)
        raise SystemExit(2)
    return device, tokens[mac_index].lower()

v4 = parse_neighbor("IPv4", v4_device, v4_output)
v6 = parse_neighbor("IPv6", v6_device, v6_output)
if v4[0] != v6[0]:
    print(f"neighbor identity: devices differ ({v4[0]} vs {v6[0]})", file=sys.stderr)
    raise SystemExit(10)
if v4[1] != v6[1]:
    print(f"neighbor identity: MAC addresses differ ({v4[1]} vs {v6[1]})", file=sys.stderr)
    raise SystemExit(10)
PY
	then
		return 0
	else
		verdict_status=$?
	fi
	if (( verdict_status == 10 )); then return 1; fi
	return 2
}

ha_recent_interval_metric() {
	if [[ $# -ne 4 || ! "$2" =~ ^[1-9][0-9]*$ || ! "$4" =~ ^[1-9][0-9]*$ ]]; then
		printf 'recent iperf3 metrics: expected <jsonl-file> <interval-count> <metric> <stream-count>\n' >&2
		return 2
	fi
	if python3 - "$@" <<'PY'
import json
import math
import pathlib
import sys

path_text, interval_count_text, metric, stream_count_text = sys.argv[1:]
interval_count = int(interval_count_text)
expected_stream_count = int(stream_count_text)

def blind(reason):
    print(f"recent iperf3 event stream: {reason}", file=sys.stderr)
    raise SystemExit(2)

def reject_constant(value):
    raise ValueError(f"non-standard JSON constant {value}")

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member {key!r}")
        result[key] = value
    return result

def finite_number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except (OverflowError, TypeError, ValueError):
        return False

def reject_nonfinite(value):
    if type(value) in (int, float) and not finite_number(value):
        raise ValueError("non-finite JSON number")
    if isinstance(value, dict):
        for item in value.values():
            reject_nonfinite(item)
    elif isinstance(value, list):
        for item in value:
            reject_nonfinite(item)

try:
    lines = pathlib.Path(path_text).read_text(encoding="utf-8").splitlines()
except (OSError, UnicodeError) as exc:
    blind(f"capture unavailable ({exc})")

intervals = []
for line_number, raw in enumerate(lines, 1):
    raw = raw.strip()
    if not raw:
        continue
    try:
        event = json.loads(
            raw,
            parse_constant=reject_constant,
            object_pairs_hook=unique_object,
        )
        reject_nonfinite(event)
    except (ValueError, json.JSONDecodeError, RecursionError) as exc:
        blind(f"malformed JSON line {line_number} ({exc})")
    if not isinstance(event, dict) or not isinstance(event.get("event"), str):
        blind(f"malformed event on line {line_number}")
    if event["event"] != "interval":
        continue
    data = event.get("data")
    summary = data.get("sum") if isinstance(data, dict) else None
    streams = data.get("streams") if isinstance(data, dict) else None
    if not isinstance(summary, dict) or not isinstance(streams, list):
        blind(f"malformed interval event on line {line_number}")
    start = summary.get("start")
    end = summary.get("end")
    aggregate_bps = summary.get("bits_per_second")
    if (
        not finite_number(start)
        or not finite_number(end)
        or end <= start
        or not 0.5 <= end - start <= 1.5
        or not finite_number(aggregate_bps)
        or aggregate_bps < 0
        or len(streams) != expected_stream_count
    ):
        blind(f"malformed interval fields on line {line_number}")
    stream_ids = set()
    validated_streams = []
    for stream in streams:
        if not isinstance(stream, dict):
            blind(f"malformed stream interval on line {line_number}")
        stream_bps = stream.get("bits_per_second")
        stream_id = stream.get("socket", stream.get("id"))
        if (
            not finite_number(stream_bps)
            or stream_bps < 0
            or isinstance(stream_id, bool)
            or not isinstance(stream_id, (str, int))
            or not str(stream_id)
        ):
            blind(f"malformed stream fields on line {line_number}")
        stream_id = str(stream_id)
        if stream_id in stream_ids:
            blind(f"duplicate stream identity on line {line_number}")
        stream_ids.add(stream_id)
        validated_streams.append((stream_id, stream_bps))
    intervals.append((aggregate_bps, validated_streams))

if len(intervals) < interval_count:
    blind(f"only {len(intervals)} full interval(s), expected {interval_count}")
selected = intervals[-interval_count:]
stream_zero_total = 0
zero_streams = set()
aggregate_zero_total = 0
for aggregate_bps, streams in selected:
    if aggregate_bps == 0:
        aggregate_zero_total += 1
    for stream_id, stream_bps in streams:
        if stream_bps == 0:
            stream_zero_total += 1
            zero_streams.add(stream_id)

if metric == "dead_streams":
    value = sum(stream_bps == 0 for _, stream_bps in selected[-1][1])
elif metric == "zero_intervals":
    value = aggregate_zero_total + stream_zero_total
elif metric == "stream_zero_intervals":
    value = stream_zero_total
elif metric == "zero_streams":
    value = len(zero_streams)
else:
    blind(f"unsupported metric {metric!r}")
print(value)
PY
	then
		return 0
	fi
	return 2
}
