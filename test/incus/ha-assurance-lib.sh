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
    "stream_zero_intervals_outside_events_total": "int",
    "zero_streams_outside_events_total": "int",
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
    "stream_zero_intervals_outside_events_total",
    "zero_streams_outside_events_total",
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

# One sample of the N-samples-at-the-floor rule. Endpoint names and both
# files are explicit; callers must not derive direction from ambient globals.
#
# THE PROPERTY (#18632): idle = N samples at an unchanged floor, the
# latest of them included, with no create outstanding beyond that floor
# and nothing pending at those reads (the target's helper delta queue and
# the source's helper delta buffer), and no source delta dropped since the
# wait began. Per sample, with D = source "Session create" sent - target
# "Session create" received: outstanding beyond the floor is D - D_floor,
# where D_floor is the lowest D the wait has observed (the baseline pair
# the caller passes). The N samples need not be consecutive: a sample
# above the floor neither counts nor resets the count. On loss under a
# steady mirror sweep (~4 creates/s), a create landed between the two
# reads in pairs every ~4 samples, so floor readings never came 3 in a row
# and the consecutive rule FAILed a healthy pair (#18632 live run 2). Each
# counted sample is still an exact reading at the floor; a new floor or a
# rewind restarts the count. A source drop does not restart it: that sample
# is not idle, and because the caller keeps the drop baseline no later
# sample can count either, so the wait FAILs.
#
# Why a floor, not absolute equality (#16289): the two daemons do not
# count from the same epoch. Bulk-sync frames are counted by the receiver
# only, and a restart zeroes one side, so sent == received is not the
# caught-up state (loss: sent 22047 vs received 129487 while caught up).
#
# Why the caller captures the TARGET before the SOURCE (#18632): a create
# the target has counted was enqueued on the source before the target's
# read, and the source counts it as sent right after the enqueue
# (queueMessage: the channel send, then sentCounter.Add). So a source read
# taken after the target read includes it, unless the source stalled
# between those two statements for longer than the gap between the reads
# (about 0.4 s). That stall would read D one LOW, set a floor below the
# real one and FAIL the wait; it cannot PASS one falsely. Otherwise D can
# only read high (a create enqueued between the reads, or one in flight).
# Source-first capture let a create enqueued between the reads and
# delivered before the target read be counted as received but not as
# sent: a baseline taken on that sample sat one below the floor, and every
# later quiet sample read as one create outstanding for the whole wait
# (both waits of the #18627 loss run: sent-received -107440 at the
# baseline, then -107439 on all 49 later samples). The old
# (sent == received) escape (#16500) only rescued that when both counters
# shared an epoch; it is gone, because under target-first capture it could
# only mask creates that really are outstanding.
#
# Why the floor moves only DOWN: what a baseline can absorb is its D minus
# the true floor (creates in flight at it). Moving to a lower D shrinks
# that and never grows it, and removes an inflated first sample (a burst
# at the start of the wait). The floor never moves UP, so a create lost
# AFTER the wait has seen a sample at the true floor (nothing in flight)
# keeps D above it forever and the wait FAILs. A new floor resets the
# streak, so a backlog that is still draining (D falling every sample)
# never reads idle; the old fixed baseline passed it.
#
# Known blind spots (counters alone; the pre-#18632 predicate shares
# them; closing them needs a per-create epoch or sequence, not counts):
# - Drain plus loss: creates in flight at every sample so far mask a
#   create lost before they land. Two in flight at the first sample, a
#   third sent and never received: when the two land, D falls to one
#   above the true floor, that becomes the new floor, and the wait PASSes.
#   Pinned by a selftest cell so a change to it is deliberate.
# - Constant lag: if at least one create is in flight at every sample,
#   the lag is the floor and the wait PASSes. A GROWING lag is caught.
# - Varying background creates: a create in EVERY read window at a steady
#   rate is a constant offset the floor absorbs, so the wait PASSes. A
#   healthy pair FAILs only when the per-window count varies and the
#   minimum is rarely seen again. On loss the mirror sweep left about half
#   the samples at the floor (#18632 run 2).
# - Stale stability evidence: samples above the floor neither count nor
#   reset, so a lag that clears for one sample can PASS on earlier counted
#   samples as old as the wait itself (up to ~28 attempts). The PASS sample
#   is still exact, so this is not a lost create.
# - A rewind (daemon or helper restart) re-baselines everything, including
#   the source dropped count, so a drop seen before it is forgotten.
# - A create sent after the last idle sample.
# - Source-side loss on the event-stream path. The source checks below
#   read the helper's per-binding RPC-fallback delta buffer ("Session
#   delta pending/dropped"). In event-stream mode, session deltas reach
#   the daemon over the event stream instead; its loss latches an owner-RG
#   resync, and the CLI's "Event stream producer: dropped=" mixes rate-
#   limited log events with HA deltas, so it is not gated here (#18635
#   tracks exposing an HA-delta loss counter).
#
# Verdicts: 0 idle at the floor (D == D_floor, both pendings 0, no new
# source drop); 1 not idle (D above the floor, a pending delta, or the
# source dropped a delta since the baseline; baseline kept, so a drop
# keeps every later sample not idle); 4 new floor (D < D_floor; the caller
# re-baselines to this sample and resets the streak); 3 counter rewind (a
# daemon or helper restarted; the caller re-baselines); 2 VOID
# (blind/malformed evidence or a malformed baseline). The first sample of
# a wait (all three baselines empty) only establishes the floor and
# returns 1. Target "drained" is required and parseable, informational
# only. Every evidence field is parsed before any baseline branch, so
# blind evidence is VOID even on the baseline-establishing sample and even
# on a rewound sample.
ha_session_sync_idle_sample() {
	if [[ $# -ne 7 ]]; then
		printf 'session sync sample: expected <source-node> <target-node> <source-stats> <target-stats> <baseline-sent> <baseline-received> <baseline-source-dropped>\n' >&2
		return 2
	fi
	local source_node="$1"
	local target_node="$2"
	local source_path="$3"
	local target_path="$4"
	local baseline_sent="$5"
	local baseline_received="$6"
	local baseline_dropped="$7"
	local sent received pending drained source_pending source_dropped parse_status=0
	# Parse every evidence field before any baseline branch, so blind or
	# malformed evidence is VOID (2) even on the baseline-establishing
	# sample and even when the counters have rewound.
	parse_status=0
	sent="$(ha_sync_stats_value "$source_path" "Session create" sent)" || parse_status=2
	received="$(ha_sync_stats_value "$target_path" "Session create" received)" || parse_status=2
	pending="$(ha_status_summary_value "$target_path" "Session delta pending")" || parse_status=2
	drained="$(ha_status_summary_value "$target_path" "Session delta drained")" || parse_status=2
	source_pending="$(ha_status_summary_value "$source_path" "Session delta pending")" || parse_status=2
	source_dropped="$(ha_status_summary_value "$source_path" "Session delta dropped")" || parse_status=2
	: "$drained" # Required and parseable, informational only.
	if (( parse_status == 2 )); then return 2; fi
	if [[ -z "$baseline_sent" && -z "$baseline_received" && -z "$baseline_dropped" ]]; then
		# First sample of a wait: it only establishes the baseline. It is
		# never idle by itself, so the N-samples rule still requires
		# later samples to prove nothing sent since is unreceived.
		printf 'session sync %s->%s baseline: source sent=%s, target received=%s, pending=%s\n' \
			"$source_node" "$target_node" "$sent" "$received" "$pending" >&2
		return 1
	fi
	if [[ ! "$baseline_sent" =~ ^[0-9]+$ || ! "$baseline_received" =~ ^[0-9]+$ || ! "$baseline_dropped" =~ ^[0-9]+$ ]]; then
		printf 'session sync %s->%s malformed baseline: sent=%s received=%s source dropped=%s\n' \
			"$source_node" "$target_node" "$baseline_sent" "$baseline_received" "$baseline_dropped" >&2
		return 2
	fi
	if (( sent < baseline_sent || received < baseline_received )); then
		printf 'session sync %s->%s not idle: counters rewound since baseline (source sent=%s baseline=%s, target received=%s baseline=%s, pending=%s); re-baseline required\n' \
			"$source_node" "$target_node" "$sent" "$baseline_sent" "$received" "$baseline_received" "$pending" >&2
		return 3
	fi
	if (( source_dropped < baseline_dropped )); then
		printf 'session sync %s->%s not idle: source session delta dropped counter rewound (dropped=%s baseline=%s; the helper restarted); re-baseline required\n' \
			"$source_node" "$target_node" "$source_dropped" "$baseline_dropped" >&2
		return 3
	fi
	if (( source_dropped > baseline_dropped )); then
		printf 'session sync %s->%s not idle: the source dropped %s session delta(s) since the baseline (dropped=%s baseline=%s); a dropped delta never becomes a sent create\n' \
			"$source_node" "$target_node" "$(( source_dropped - baseline_dropped ))" "$source_dropped" "$baseline_dropped" >&2
		return 1
	fi
	local outstanding=$(( (sent - received) - (baseline_sent - baseline_received) ))
	if (( outstanding < 0 )); then
		printf 'session sync %s->%s new floor: source sent=%s, target received=%s is %s below the baseline (sent=%s received=%s), pending=%s; re-baseline\n' \
			"$source_node" "$target_node" "$sent" "$received" "$(( -outstanding ))" "$baseline_sent" "$baseline_received" "$pending" >&2
		return 4
	fi
	if (( outstanding == 0 )) && [[ "$pending" == "0" ]]; then
		if [[ "$source_pending" == "0" ]]; then
			return 0
		fi
		printf 'session sync %s->%s not idle: at the floor, but the source holds %s undrained session delta(s)\n' \
			"$source_node" "$target_node" "$source_pending" >&2
		return 1
	fi
	printf 'session sync %s->%s not idle: source sent=%s (baseline %s), target received=%s (baseline %s), outstanding beyond floor=%s, pending=%s\n' \
		"$source_node" "$target_node" "$sent" "$baseline_sent" "$received" "$baseline_received" "$outstanding" "$pending" >&2
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

# Both node queries must independently report the expected owner as primary
# and its peer as non-owning (`secondary` or `secondary-hold`). A
# non-committal manual failover can legitimately leave the peer in
# `secondary-hold`. Well-formed but unsettled/wrong ownership is measured FAIL;
# blind status or provenance is VOID.
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
if all(
    status[expected_node] == "primary"
    and status[peer] in {"secondary", "secondary-hold"}
    for status in statuses
):
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

# #18670 report-only (#18681): append the helper `PID:` line from a
# data-plane statistics capture to a `show security flow statistics` capture,
# so the flow-statistics delta can be read with ha_snapshot_counter_delta.
# Prints nothing; never fails the caller (a missing PID line just leaves the
# flow capture without one).
ha_flowstats_append_helper_pid() {
	if [[ $# -ne 2 ]]; then
		printf 'flowstats pid append: expected <dp-stats-file> <flowstats-file>\n' >&2
		return 2
	fi
	grep -E -m1 '^[[:space:]]*PID:' "$1" >>"$2" 2>/dev/null || true
	return 0
}

# #18670 report-only (#18681): the `Host-inbound denies` delta per node across
# the RG1 failback window, as "node0=<n|unavailable> node1=<n|unavailable>".
# This value is xpfd's GlobalCtrHostInboundDeny mirror, refreshed at its 1 s
# status poll with safeDelta absorbing helper resets, so it trails the helper by
# up to a second and a helper restart does not rewind it; the helper-PID guard
# that ha_snapshot_counter_delta applies is therefore stricter than this
# counter needs and is not a guard on xpfd. Report-only until #18681 adds an
# xpfd-side guard and allows for the poll lag.
ha_host_inbound_denies_report() {
	if [[ $# -ne 4 ]]; then
		printf 'host-inbound report: expected <node0-pre> <node1-pre> <node0-post> <node1-post>\n' >&2
		return 2
	fi
	local -a pre=("$1" "$2") post=("$3" "$4")
	local i delta line=""
	for i in 0 1; do
		if delta=$(ha_snapshot_counter_delta manual-rg1-failback 1 "node${i}" "Host-inbound denies" \
			phase-pre "${pre[$i]}" phase-post "${post[$i]}" 2>/dev/null); then
			line+="${line:+ }node${i}=${delta}"
		else
			line+="${line:+ }node${i}=unavailable"
		fi
	done
	printf '%s\n' "$line"
}

# #18670: a counter delta between two helper-status captures is only a
# delta when both captures read the SAME helper process. A helper restart
# inside the window zeroes the counters and regrows them past the baseline,
# which reads as an ordinary (small) delta. The captures carry the helper's
# `PID:` line: when either capture has one, both must, and they must agree;
# anything else is VOID. Captures with no `PID:` line at all (fixtures, older
# formats) carry no process identity and are not judged here.
ha_snapshot_same_helper_verdict() {
	if [[ $# -ne 3 ]]; then
		printf 'snapshot helper identity: expected <before-file> <after-file> <node>\n' >&2
		return 2
	fi
	local before_file="$1" after_file="$2" node="$3" before_pid after_pid
	if ! grep -Eq '^[[:space:]]*PID:' "$before_file" 2>/dev/null \
		&& ! grep -Eq '^[[:space:]]*PID:' "$after_file" 2>/dev/null; then
		return 0
	fi
	if ! before_pid="$(ha_status_summary_value "$before_file" "PID")"; then return 2; fi
	if ! after_pid="$(ha_status_summary_value "$after_file" "PID")"; then return 2; fi
	if [[ "$before_pid" != "$after_pid" ]]; then
		printf '%s: helper restarted inside the window (PID %s -> %s); its counters do not span it\n' \
			"$node" "$before_pid" "$after_pid" >&2
		return 2
	fi
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
	if ! ha_snapshot_same_helper_verdict "$before_file" "$after_file" "$node"; then return 2; fi
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

# ha_wan_claim_verdict <conf-own-mac-prefix> <address> <gateway> <probe-output>
#
# #18558: is the cluster's WAN IPv4 address claimed on its segment by a host
# OUTSIDE xpf? A duplicate address makes every external IPv4 cell
# unattributable: the upstream gateway's ARP entry for the address flips
# between the RG owner and the other host, so replies go to whichever of the
# two ARPed the gateway last. tcp's 172.16.50.10 was held by a lab device
# (18:e8:29:2c:13:7a) for exactly this reason.
#
# <probe-output> is what ha_wan_claim_check assembled:
#   iface <name> <mac>             the probing interface (ha_wan_claim_probe)
#   reply <ip> <mac> probe|other   one per ARP reply; "probe" = addressed to
#                                  our MAC with target IP 0.0.0.0, i.e. an
#                                  answer to OUR RFC 5227 probe (measured: the
#                                  lab gateway and the lab device both answer
#                                  that way)
#   own <mac>                      a MAC of either node of this cluster
#                                  (current and permanent addresses)
# Other lines are ignored.
#
# Own-cluster identity: <conf-own-mac-prefix> is 02:bf:72:<cluster-id>: from
# CLUSTER_CONF (may be empty). The probing interface's own MAC, when it is a
# RETH virtual MAC (02:bf:72:<cid>:<rg>:<n>, pkg/config/reth_virtual_mac_8340.go),
# gives the LIVE cluster id. A conf/live mismatch is VOID: the docs conf has
# drifted from the running cluster and "own" cannot be decided.
#
# Claimant classes for <address>: this cluster's RETH prefix or an "own" MAC
# = own; any other 02:bf:72: MAC = ANOTHER xpf cluster's RETH; anything else
# = foreign (non-xpf).
#
# Status 0: the gateway answered our probe (the probe can hear) and every
#           claimant is own.
# Status 1: a non-xpf MAC claims <address>: a duplicate address the product
#           did not cause. stderr names the MAC(s).
# Status 3: another xpf cluster's RETH MAC claims <address>. That is an xpf
#           defect (for example a stale VIP, #18573), never an excuse;
#           stderr names the other cluster id(s). Wins over status 1.
# Status 2: VOID: no claimant outside own AND no gateway answer to our probe,
#           or own-cluster identity could not be decided.
ha_wan_claim_verdict() {
	if [[ $# -ne 4 ]]; then
		printf 'wan claim: expected <conf-own-mac-prefix> <address> <gateway> <probe-output>\n' >&2
		return 2
	fi
	local conf_own="${1,,}" addr="$2" gw="$3" output="$4"
	local line kind ip mac flag rest own="" live="" iface_mac="" foreign="" xpf_other="" xpf_ids="" gw_seen=0
	local -A own_macs=()
	if [[ -n "$conf_own" && ! "$conf_own" =~ ^02:bf:72:[0-9a-f]{2}:$ ]]; then
		printf 'wan claim: conf own MAC prefix %q is not 02:bf:72:<cluster-id>:\n' "$1" >&2
		return 2
	fi
	if [[ -z "$addr" || -z "$gw" || "$addr" == "$gw" ]]; then
		printf 'wan claim: need distinct address and gateway (got %q and %q)\n' "$addr" "$gw" >&2
		return 2
	fi
	while IFS= read -r line; do
		read -r kind ip mac rest <<<"$line"
		case "$kind" in
		iface)
			mac="${mac,,}"
			[[ "$mac" =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]] && iface_mac="$mac"
			[[ "$mac" =~ ^(02:bf:72:[0-9a-f]{2}:) ]] && live="${BASH_REMATCH[1]}"
			;;
		own)
			ip="${ip,,}"
			[[ "$ip" =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]] && own_macs[$ip]=1
			;;
		esac
	done <<<"$output"
	if [[ -n "$conf_own" && -n "$live" && "$conf_own" != "$live" ]]; then
		printf 'wan claim: CLUSTER_CONF says cluster prefix %s but the live RETH MAC says %s; own identity undecided\n' \
			"$conf_own" "$live" >&2
		return 2
	fi
	own="${live:-$conf_own}"
	if [[ -z "$own" ]]; then
		printf 'wan claim: no cluster identity (no cluster-id in the conf and the probing interface has no RETH MAC)\n' >&2
		return 2
	fi
	while IFS= read -r line; do
		read -r kind ip mac flag rest <<<"$line"
		[[ "$kind" == reply ]] || continue
		mac="${mac,,}"
		[[ "$mac" =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]] || continue
		# #18580: no host answers with OUR MAC. A reply naming the probing
		# interface's own MAC means the probe read the target-MAC field
		# instead of the sender's, and every reading is worthless (it would
		# turn every claimant into "own").
		# This is sound only because ha_wan_claim_probe binds its socket to
		# ETH_P_ARP. Outgoing frames reach only ETH_P_ALL packet sockets, so
		# this socket never sees our own kernel's ARP replies for the address,
		# which do carry our MAC as sender. Measured in a netns: an ETH_P_ARP
		# socket saw 0 of 3 own-kernel replies, an ETH_P_ALL one saw all 3
		# (docs/log/18580.md). Rebinding to ETH_P_ALL would make this guard
		# VOID every run in which anyone ARPs for us.
		# The guard needs the probe's iface line, which the real probe prints
		# before it sends anything: a reply without one is not its output.
		if [[ -z "$iface_mac" ]]; then
			printf 'wan claim: a reply for %s arrived without the probe interface line (not the probe output)\n' \
				"$ip" >&2
			return 2
		fi
		if [[ "$mac" == "$iface_mac" ]]; then
			printf 'wan claim: a reply for %s names the probing interface MAC %s: the probe read the wrong field\n' \
				"$ip" "$mac" >&2
			return 2
		fi
		if [[ "$ip" == "$gw" ]]; then
			[[ "$flag" == probe ]] && gw_seen=1
			continue
		fi
		[[ "$ip" == "$addr" ]] || continue
		if [[ "$mac" == "$own"* || -n "${own_macs[$mac]:-}" ]]; then
			continue
		fi
		if [[ "$mac" == 02:bf:72:* ]]; then
			[[ " $xpf_other " == *" $mac "* ]] || xpf_other="${xpf_other:+$xpf_other }$mac"
			local cid=$((16#${mac:9:2}))
			[[ " $xpf_ids " == *" $cid "* ]] || xpf_ids="${xpf_ids:+$xpf_ids }$cid"
			continue
		fi
		[[ " $foreign " == *" $mac "* ]] || foreign="${foreign:+$foreign }$mac"
	done <<<"$output"
	if [[ -n "$xpf_other" ]]; then
		printf 'wan claim: %s is also answered for by another xpf cluster (cluster-id %s, %s): an xpf defect, not the lab%s\n' \
			"$addr" "$xpf_ids" "$xpf_other" "${foreign:+; also by non-xpf $foreign}" >&2
		return 3
	fi
	if [[ -n "$foreign" ]]; then
		printf 'wan claim: %s is also answered for by %s, a duplicate IPv4 address on the segment\n' \
			"$addr" "$foreign" >&2
		return 1
	fi
	if (( gw_seen )); then return 0; fi
	printf 'wan claim: gateway %s did not answer the same probe, so no foreign reply for %s is not evidence\n' \
		"$gw" "$addr" >&2
	return 2
}

# ha_wan_own_mac_prefix <cluster-conf>
# #18558: print this cluster's RETH virtual-MAC prefix, 02:bf:72:<cluster-id>:,
# from the conf's `cluster-id N;`. Status 2 if the conf is unreadable or has
# no usable cluster-id. ha_wan_claim_verdict cross-checks it against the live
# RETH MAC, so a drifted conf cannot misclassify.
ha_wan_own_mac_prefix() {
	local conf="${1:-}" id
	[[ -n "$conf" && -r "$conf" ]] || return 2
	id="$(awk '$1 == "cluster-id" { v=$2; sub(/;.*/, "", v); print v; exit }' "$conf")"
	[[ "$id" =~ ^[0-9]+$ ]] && (( id <= 255 )) || return 2
	printf '02:bf:72:%02x:\n' "$id"
}

# ha_wan_claim_probe <address> <gateway> <node>...
# #18558: on the first <node> that holds <address>, send three RFC 5227 ARP
# probes (sender 0.0.0.0, so no cache on the segment learns from them) for
# <address> and for <gateway> from the interface carrying <address>. Prints
# "iface <name> <mac>", then "reply <ip> <mac> probe|other" per ARP reply for
# either address ("probe": addressed to us with target IP 0.0.0.0). Status 2
# if no listed node holds <address>.
ha_wan_claim_probe() {
	local addr="$1" gw="$2" node
	shift 2
	for node in "$@"; do
		if incus exec "$node" -- python3 - "$addr" "$gw" <<'PY'
import select, socket, struct, subprocess, sys, time
addr, gw = sys.argv[1], sys.argv[2]
ifname = None
for line in subprocess.run(["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True).stdout.splitlines():
    f = line.split()
    if len(f) >= 4 and f[2] == "inet" and f[3].split("/")[0] == addr:
        ifname = f[1].split("@")[0]
        break
if ifname is None:
    raise SystemExit(3)
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
s.bind((ifname, 0x0806))
mac = bytes.fromhex(open(f"/sys/class/net/{ifname}/address").read().strip().replace(":", ""))
print("iface", ifname, mac.hex(":"))
targets = [socket.inet_aton(addr), socket.inet_aton(gw)]
for _ in range(3):
    for tip in targets:
        arp = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, mac, bytes(4), bytes(6), tip)
        s.send(b"\xff" * 6 + mac + b"\x08\x06" + arp + bytes(18))
    end = time.time() + 1.0
    while (left := end - time.time()) > 0:
        if not select.select([s], [], [], left)[0]:
            break
        f = s.recv(2048)
        if len(f) >= 42 and f[12:14] == b"\x08\x06" and f[20:22] == b"\x00\x02" and f[28:32] in targets:
            flag = "probe" if f[32:38] == mac and f[38:42] == bytes(4) else "other"
            print("reply", socket.inet_ntoa(f[28:32]), f[22:28].hex(":"), flag, flush=True)
PY
		then
			return 0
		fi
	done
	return 2
}

# ha_wan_node_macs <node>
# #18558: print "own <mac>" for every current and permanent link-layer
# address on <node>, so a reply from one of this cluster's physical (non-RETH)
# MACs is classified as own, not foreign.
ha_wan_node_macs() {
	incus exec "$1" -- sh -c \
		'cat /sys/class/net/*/address 2>/dev/null; ip -o link 2>/dev/null | grep -o "permaddr [0-9a-f:]*" | cut -d" " -f2' \
		2>/dev/null | awk 'NF == 1 && $1 != "00:00:00:00:00:00" { print "own", $1 }'
}

# ha_wan_claim_check <cluster-conf> <address> <gateway> <node>...
# #18558: probe, collect both nodes' own MACs, judge. Sets
# HA_WAN_CLAIM_STATUS (the ha_wan_claim_verdict status: 0 unique, 1 non-xpf
# claimant, 3 another xpf cluster, 2 not measured) and HA_WAN_CLAIM_REASON.
# Always returns 0 so a `set -e` caller reads the variables instead of exiting.
ha_wan_claim_check() {
	local conf="$1" addr="$2" gw="$3" own="" output node
	shift 3
	HA_WAN_CLAIM_STATUS=2
	HA_WAN_CLAIM_REASON="wan claim: not measured"
	own=$(ha_wan_own_mac_prefix "$conf") || own=""
	if ! output=$(ha_wan_claim_probe "$addr" "$gw" "$@" 2>&1); then
		HA_WAN_CLAIM_REASON="wan claim: no node of $* holds ${addr}, or the probe could not run"
		return 0
	fi
	for node in "$@"; do
		output+=$'\n'"$(ha_wan_node_macs "$node")"
	done
	if HA_WAN_CLAIM_REASON=$(ha_wan_claim_verdict "$own" "$addr" "$gw" "$output" 2>&1); then
		HA_WAN_CLAIM_STATUS=0
	else
		HA_WAN_CLAIM_STATUS=$?
	fi
	return 0
}

# ha_external_ping_claim_verdict <ping-status> <ping-output> <claim-status> <claim-reason>
#
# #18558: ha_external_ping_verdict, except that an IPv4 FAIL becomes VOID when
# the claim check that test-failover runs right after that sweep's pings (a
# few seconds later, not the same instant) found a non-xpf claimant (status 1)
# for the WAN address. Only a FAIL is converted, and only by status 1:
# - a PASS stays a PASS (the product did forward);
# - status 3 (another xpf cluster claims the address) is an xpf defect, so the
#   FAIL stands with the claim appended to its reason;
# - with no claim, or a claim probe that was blind or did not run, the plain
#   verdict stands.
# So the check can never remove a FAIL it cannot explain.
ha_external_ping_claim_verdict() {
	if [[ $# -ne 4 ]]; then
		printf 'external ping: expected <ping-status> <ping-output> <claim-status> <claim-reason>\n' >&2
		return 2
	fi
	local ping_status="$1" output="$2" claim_status="$3" claim_reason="$4" status reason
	if reason=$(ha_external_ping_verdict "$ping_status" "$output" 2>&1); then
		return 0
	else
		status=$?
	fi
	if (( status == 1 )) && [[ "$claim_status" == 1 ]]; then
		printf '%s; not attributable to the firewall: %s\n' "$reason" "${claim_reason:-foreign ARP claimant}" >&2
		return 2
	fi
	if (( status == 1 )) && [[ "$claim_status" == 3 ]]; then
		printf '%s; and %s\n' "$reason" "${claim_reason:-another xpf cluster claims the WAN address}" >&2
		return 1
	fi
	printf '%s\n' "$reason" >&2
	return "$status"
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
# `ip route get` may append a single-token `cache` continuation line
# (optionally with flags, e.g. `cache <mc>`) for the one route entry
# (#16307). Strip that trailing line; any other second line stays
# genuinely ambiguous and is rejected below.
if len(lines) > 1 and lines[-1][0] == "cache":
    lines.pop()
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
# Trailing `cache` continuation of the one route entry (#16307); see
# ha_route_device. Any other extra line stays ambiguous -> VOID.
if len(lines) > 1 and lines[-1][0] == "cache":
    lines.pop()
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

# ha_target_claim_probe <vantage> <target> <control>
#
# #18576: which hosts answer ARP for a measurement TARGET (an iperf3 server)?
# The probe runs on an OFF-FIREWALL <vantage> on the target's VLAN (the
# cluster's MOUSE_TARGET_REF container, which normally holds <target>), never
# on a firewall node. A second holder's reply (sender = the target) is then
# delivered to the vantage, which holds that address itself, so no
# neighbor entry that carries iperf traffic can move. (Probing from the
# firewall did move it: seat X reproduced a flip in 6/6 netns runs.)
# <control> is the cluster's own address on that VLAN (WAN_GW80_4): its
# reply proves the probe can hear. Three RFC 5227 rounds (sender 0.0.0.0, so
# no cache learns from them) for <target> and <control>.
# Prints "iface <name> <mac>"; "self <mac>" when the vantage holds <target>
# (a kernel never answers its own probe); then "reply <ip> <mac> probe|other"
# per ARP reply ("probe" = addressed to us with target IP 0.0.0.0).
# Status 3 if <target> is not on-link from the vantage (and not held by it);
# any other non-zero status means the probe could not run.
# [ifname] (optional, #18576): probe from that interface instead of the one
# holding <target> or routing to it. mouse-target-setup.sh `up` uses it to
# probe an address BEFORE it is assigned, when no on-link route may exist
# yet; an RFC 5227 probe needs no address on the interface.
ha_target_claim_probe() {
	local vantage="$1" target="$2" control="$3" ifname="${4:-}"
	incus exec "$vantage" -- python3 - "$target" "$control" "$ifname" <<'PY'
import select, socket, struct, subprocess, sys, time
target, control = sys.argv[1], sys.argv[2]
forced = sys.argv[3] if len(sys.argv) > 3 else ""
# The vantage may hold <target> (loss's container holds its target): probe
# from that interface. Otherwise use the on-link route; a local lookup says
# "dev lo" and a "via" route is not on-link.
ifname, held = None, False
for line in subprocess.run(["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True).stdout.splitlines():
    f = line.split()
    if len(f) >= 4 and f[2] == "inet" and f[3].split("/")[0] == target and f[1] != "lo":
        if forced and f[1].split("@")[0] != forced:
            continue
        ifname, held = f[1].split("@")[0], True
        break
if ifname is None and forced:
    ifname = forced
if ifname is None:
    route = subprocess.run(["ip", "-o", "-4", "route", "get", target], capture_output=True, text=True).stdout.split()
    if "dev" not in route or "via" in route or route[0] == "local":
        raise SystemExit(3)
    ifname = route[route.index("dev") + 1]
mac = bytes.fromhex(open(f"/sys/class/net/{ifname}/address").read().strip().replace(":", ""))
print("iface", ifname, mac.hex(":"))
if held:
    print("self", mac.hex(":"))
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
s.bind((ifname, 0x0806))
tips = [socket.inet_aton(target), socket.inet_aton(control)]
for _ in range(3):
    for tip in tips:
        arp = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, mac, bytes(4), bytes(6), tip)
        s.send(b"\xff" * 6 + mac + b"\x08\x06" + arp + bytes(18))
    end = time.time() + 1.0
    while (left := end - time.time()) > 0:
        if not select.select([s], [], [], left)[0]:
            break
        f = s.recv(2048)
        if len(f) >= 42 and f[12:14] == b"\x08\x06" and f[20:22] == b"\x00\x02" and f[28:32] in tips:
            flag = "probe" if f[32:38] == mac and f[38:42] == bytes(4) else "other"
            print("reply", socket.inet_ntoa(f[28:32]), f[22:28].hex(":"), flag, flush=True)
PY
}

# ha_target_fw_neigh <phase> <target> <control> <node>...
# #18576: READ-ONLY snapshot of each firewall node's neighbor entry for
# <target>. Prints "fw <node> <phase> <lladdr|-> <state|NONE> owner|peer"
# per node; "owner" = the node holding <control> (WAN_GW80_4), i.e. the RG
# owner whose entry carries the iperf traffic.
ha_target_fw_neigh() {
	local phase="$1" target="$2" control="$3" node line lladdr state role
	shift 3
	for node in "$@"; do
		line=$(incus exec "$node" -- ip neigh show "$target" 2>/dev/null | head -1) || line=""
		lladdr=$(awk '{for (i = 1; i < NF; i++) if ($i == "lladdr") print $(i + 1)}' <<<"$line")
		state=$(awk '{print $NF}' <<<"$line")
		role=peer
		if incus exec "$node" -- ip -o -4 addr show 2>/dev/null |
			awk -v c="$control" '{split($4, a, "/"); if (a[1] == c) f = 1} END {exit !f}'; then
			role=owner
		fi
		printf 'fw %s %s %s %s %s\n' "$node" "$phase" "${lladdr:--}" "${state:-NONE}" "$role"
	done
}

# ha_target_claim_verdict <target> <control> <known-holders> <probe-output>
#
# #18576: a measurement target must be ONE host, the intended one. loss's
# old iperf3 target 172.16.80.200 is answered by both xpf-mouse-target
# (10:66:6a:8b:91:a4) and the external v6 target box (f6:f0:06:10:77:d5).
# Linux overrides a neighbor entry with any ARP from the address once the 1 s
# locktime has passed, and a broadcast re-resolution keeps the first reply,
# so the firewall's choice of server, and every v4 measurement with it, could
# move (it did: a 2026-10-31 rg-move soak lost every v4 stream to the
# external box). loss now targets .202, held by the container alone, and no
# env configures <known-holders>; the excuse path below is kept for a future
# documented duplicate, which must carry its own expiry.
#
# Holders = "self" (the vantage container, the intended holder in every env)
# plus every "reply" MAC for <target>. Of the "fw" lines (before/after the
# probe) only the OWNER's (the node holding <control>) carries the iperf
# traffic; a peer's entry is not judged. Rules, in order:
# - a reply naming the prober's own interface MAC: VOID (2), wrong field;
# - an xpf RETH holder (02:bf:72:*): 3, a product defect (mirrors #18575);
# - the owner's entry: FAILED/INCOMPLETE, or REACHABLE/DELAY/PROBE/PERMANENT
#   on a MAC no holder claims, or lladdr changed between two present
#   snapshots: FAIL (1), a product neighbor fault. A STALE entry on an old
#   MAC (e.g. after a container recreate) or an entry that merely appears
#   mid-window is not a FAIL, because the kernel re-validates it on use, but
#   an owner entry naming another MAC still makes a lone-holder PASS
#   uncertifiable (see below);
# - two or more holders equal to <known-holders> (may say "self"):
#     owner resolves <target> to the self MAC before AND after: 4, the known
#       environment duplicate, excused (the cell SKIPs, #18576);
#     owner resolves it to another holder: VOID (2), this run's v4 iperf
#       numbers measured the wrong host;
#     owner has no entry, or no self line: VOID (2), not certifiable;
# - two or more holders, any other set: FAIL (1), naming every holder;
# - otherwise the <control> must have answered OUR probe, else VOID (2);
# - no holder: VOID (2); exactly one holder that is not "self" (the intended
#   container lost the address): VOID (2), the v4 target is misplaced;
# - exactly self but the owner's entry names another MAC (even STALE): VOID
#   (2), not certifiable;
# - exactly self: PASS (0). If <known-holders> is still configured the reason
#   says "configured but not observed: delete IPERF_TARGET4_KNOWN_HOLDERS".
# Whenever "fw" lines are given, the RG owner must be exactly one node, the
# same in both snapshots; otherwise VOID (2).
ha_target_claim_verdict() {
	if [[ $# -ne 4 ]]; then
		printf 'target claim: expected <target> <control> <known-holders> <probe-output>\n' >&2
		return 2
	fi
	python3 - "$@" <<'PY'
import re
import sys

target, control, known_raw, output = sys.argv[1:5]
mac_re = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
def out(msg, code):
    print(f"target claim: {msg}", file=sys.stderr if code else sys.stdout)
    raise SystemExit(code)
if not target or not control or target == control:
    out(f"need distinct target and control (got {target!r} and {control!r})", 2)
iface_mac, holders, self_mac, control_seen, fw = None, [], None, False, {}
for line in output.splitlines():
    f = line.split()
    if len(f) >= 3 and f[0] == "iface" and mac_re.match(f[2].lower()):
        iface_mac = f[2].lower()
    elif len(f) >= 2 and f[0] == "self" and mac_re.match(f[1].lower()):
        self_mac = f[1].lower()
        holders.append(self_mac)
    elif len(f) >= 3 and f[0] == "reply" and mac_re.match(f[2].lower()):
        if iface_mac and f[2].lower() == iface_mac:
            out(f"a reply for {f[1]} names the prober's own MAC {iface_mac}: the probe read the wrong field", 2)
        if f[1] == target:
            holders.append(f[2].lower())
        elif f[1] == control and len(f) >= 4 and f[3] == "probe":
            control_seen = True
    elif len(f) >= 6 and f[0] == "fw" and f[2] in ("before", "after"):
        fw.setdefault(f[1], {})[f[2]] = (f[3].lower(), f[4].upper(), f[5])
holders = sorted(set(holders))
known = set()
for m in known_raw.split():
    m = m.lower()
    if m == "self":
        known.add(self_mac or "self(absent)")
    elif mac_re.match(m):
        known.add(m)
xpf = [m for m in holders if m.startswith("02:bf:72:")]
if xpf:
    out(f"{target} is answered for by an xpf RETH MAC ({' '.join(xpf)}): the product claims a measurement target", 3)
# The RG owner must be ONE node, the same in both snapshots. Two owners (a
# dual-active pair) or ownership moving mid-probe leaves no single entry
# that carries the iperf traffic, so nothing about it is certifiable.
owner, own = None, {}
if fw:
    before_owners = sorted(n for n in fw if fw[n].get("before", ("", "", ""))[2] == "owner")
    after_owners = sorted(n for n in fw if fw[n].get("after", ("", "", ""))[2] == "owner")
    if len(before_owners) != 1 or before_owners != after_owners:
        out(f"the RG owner of {control} is not one stable node (before {before_owners or 'none'}, "
            f"after {after_owners or 'none'}): {target}'s resolution is not certifiable", 2)
    owner = before_owners[0]
    own = {ph: v[:2] for ph, v in fw[owner].items()}
if owner:
    for phase in ("before", "after"):
        if phase not in own:
            continue
        lladdr, state = own[phase]
        if state in ("FAILED", "INCOMPLETE"):
            out(f"RG owner {owner}'s neighbor entry for {target} is {state} ({phase}) while {' '.join(holders) or 'nobody'} answer: product neighbor fault", 1)
        if lladdr != "-" and lladdr not in holders and state in ("REACHABLE", "DELAY", "PROBE", "PERMANENT"):
            out(f"RG owner {owner} resolves {target} to {lladdr} ({state}, {phase}), which no host claims: product neighbor fault", 1)
    b = own.get("before", ("-", "NONE"))[0]
    a = own.get("after", ("-", "NONE"))[0]
    if b != "-" and a != "-" and b != a:
        out(f"RG owner {owner}'s neighbor for {target} changed from {b} to {a} during the probe", 1)
owner_mac = own.get("after", own.get("before", ("-", "NONE")))[0] if owner else "-"
fwview = f"RG owner {owner} -> {owner_mac}" if owner else "no RG owner identified"
if len(holders) >= 2:
    if known and set(holders) == known:
        if not self_mac:
            out(f"{target} is answered for by the known set but the vantage does not hold it ({fwview}): not certifiable", 2)
        b = own.get("before", ("-", "NONE"))[0]
        a = own.get("after", ("-", "NONE"))[0]
        if owner and b == self_mac and a == self_mac:
            out(f"EXCUSED #18576: {target} is answered for by the known dual holder set ({' '.join(holders)}) "
                f"and {fwview} (the intended holder) before and after; expires when one holder drops it", 4)
        if owner_mac in holders and owner_mac != self_mac:
            out(f"{target} is answered for by the known dual holder set and {fwview}, the OTHER holder: "
                f"this run's v4 iperf numbers measured the wrong host; invalid, rerun", 2)
        out(f"{target} is answered for by the known dual holder set but {fwview}: the RG owner's choice of "
            f"server is not established, so this run's v4 target is not certifiable", 2)
    out(f"{target} is answered for by more than one host ({' '.join(holders)}) ({fwview})", 1)
if not control_seen:
    out(f"control {control} did not answer the same probe, so {target}'s holder count is not evidence", 2)
if not holders:
    out(f"nobody answered ARP for {target} although control {control} did", 2)
if not self_mac:
    out(f"{target} is answered for only by {holders[0]}, not by the intended holder (the vantage): "
        f"the v4 target is misplaced and v4 iperf numbers would measure that host ({fwview})", 2)
# A lone holder PASSes only if the RG owner's entry is absent or names that
# holder in both snapshots; an owner still pointing elsewhere (even STALE)
# would send the next v4 packet to another host.
stale = sorted({v[0] for v in own.values() if v[0] not in ("-", self_mac)})
if stale:
    out(f"{target} answered for only by {self_mac} but {fwview} (entries {', '.join(stale)}): "
        f"the RG owner's entry names another MAC, so this run's v4 target is not certifiable", 2)
# Expiry: the excuse is owner-gated, so a stale known set can only ever
# re-excuse the identical benign state. VOIDing a certifiable run would
# block every loss gate after the fix until the env line is edited, so the
# run PASSes and the reason tells the operator to delete the line.
note = (f"; known dual holder set ({' '.join(sorted(known))}) is configured but not observed: "
        f"delete IPERF_TARGET4_KNOWN_HOLDERS (#18576)") if known else ""
out(f"{target} answered for only by {holders[0]} ({fwview}){note}", 0)
PY
}

# ha_target_claim_check <vantage> <target> <control> <known-holders> <node>...
# Snapshot each firewall node's neighbor entry, probe from the off-firewall
# <vantage>, snapshot again, judge. Sets HA_TARGET_CLAIM_STATUS (verdict
# status: 0 PASS, 1 FAIL, 3 xpf RETH holder, 4 excused known duplicate,
# 2 VOID, including a probe that could not run or an off-link target) and
# HA_TARGET_CLAIM_REASON. Always returns 0.
ha_target_claim_check() {
	local vantage="$1" target="$2" control="$3" known="$4" output before after rc
	shift 4
	HA_TARGET_CLAIM_STATUS=2
	HA_TARGET_CLAIM_REASON="target claim: not measured"
	before=$(ha_target_fw_neigh before "$target" "$control" "$@")
	if output=$(ha_target_claim_probe "$vantage" "$target" "$control" 2>&1); then
		rc=0
	else
		rc=$?
	fi
	if (( rc == 3 )); then
		HA_TARGET_CLAIM_REASON="target claim: ${target} is not on-link from ${vantage}, so its holders cannot be probed there"
		return 0
	elif (( rc != 0 )); then
		HA_TARGET_CLAIM_REASON="target claim: probe from ${vantage} could not run (status ${rc})"
		return 0
	fi
	after=$(ha_target_fw_neigh after "$target" "$control" "$@")
	if HA_TARGET_CLAIM_REASON=$(ha_target_claim_verdict "$target" "$control" "$known" \
		"${output}"$'\n'"${before}"$'\n'"${after}" 2>&1); then
		HA_TARGET_CLAIM_STATUS=0
	else
		HA_TARGET_CLAIM_STATUS=$?
	fi
	return 0
}

# ha_rg_owner_node <control> <node>...
# #18586: print the ONE node that holds <control> (the cluster's own address
# on a WAN VLAN, e.g. WAN_GW80_4), i.e. the RG owner whose neighbor entries
# carry that VLAN's traffic. Read-only (`ip -o -4 addr show`). Status 2 when
# no node or more than one node holds it.
ha_rg_owner_node() {
	local control="$1" node addrs owners=()
	shift
	[[ -n "$control" ]] || return 2
	for node in "$@"; do
		# An unreadable node is not "does not hold": it is unknown.
		if ! addrs=$(incus exec "$node" -- ip -o -4 addr show 2>/dev/null); then
			printf 'rg owner: could not read the addresses of %s\n' "$node" >&2
			return 2
		fi
		# Exact address match (field 4 is addr/len): .8 never matches .80.
		if awk -v c="$control" '{split($4, a, "/"); if (a[1] == c) f = 1} END {exit !f}' <<<"$addrs"; then
			owners+=("$node")
		fi
	done
	if (( ${#owners[@]} != 1 )); then
		printf 'rg owner: %d nodes hold %s (%s)\n' "${#owners[@]}" "$control" "${owners[*]:-none}" >&2
		return 2
	fi
	printf '%s\n' "${owners[0]}"
}
