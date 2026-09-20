#!/usr/bin/env bash
# #9506 S5 — r6 §8 live T12/G2 cells.
#
# This cell is deliberately a measurement gate, not a synthetic success
# generator.  It attests the running xpfd executable on BOTH loss userspace
# firewalls, records the exact r6 predicate and observed state for every cell,
# and emits one ledger row per cell.  A cluster without real route-based IPsec
# fixtures/SAs is VOID with the missing precondition named; it is never PASS.
#
# Usage:
#   ./test/incus/t12-g2-9506.sh --selftest
#   ./test/incus/with-cluster.sh '9506 S5 T12/G2' -- \
#       ./test/incus/t12-g2-9506.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

MODE=live
while (($#)); do
    case "$1" in
    --selftest) MODE=selftest ;;
    -h|--help)
        sed -n '1,20p' "$0"
        exit 0
        ;;
    *)
        echo "unknown argument: $1" >&2
        exit 2
        ;;
    esac
    shift
done

# ruleset_flags prints fence-table, exact-fence-shape, inet-divert,
# bridge-divert, exact-four-hook-divert, and a readable/parse-success bit.
# It is defined before the hermetic selftest so parser drift is caught without
# touching a cluster.
ruleset_flags() {
    python3 - "$1" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as fh:
        doc = json.load(fh)
    if not isinstance(doc, dict) or not isinstance(doc.get("nftables"), list):
        raise ValueError("missing nftables list")
except Exception:
    print("0 0 0 0 0 0")
    raise SystemExit(0)

items = doc["nftables"]
tables = set()
for x in items:
    if isinstance(x, dict) and isinstance(x.get("table"), dict):
        t = x["table"]
        tables.add((str(t.get("family")), str(t.get("name"))))
fence_table = int(any((f, "xpf_transit_barrier") in tables for f in ("inet", "bridge")))
fence_exact = int(all((f, "xpf_transit_barrier") in tables for f in ("inet", "bridge")))
fence_chains = set()
divert_chains = set()
for x in items:
    if not isinstance(x, dict) or not isinstance(x.get("chain"), dict):
        continue
    c = x["chain"]
    key = (str(c.get("family")), str(c.get("table")), str(c.get("name")))
    hook = c.get("hook")
    prio = c.get("prio")
    policy = str(c.get("policy", "")).lower()
    if key[1] == "xpf_transit_barrier" and key[2] == "forward":
        if hook == "forward" and prio in (0, "filter") and policy == "drop":
            fence_chains.add(key[0])
    if key[1] == "xpf_ipsec_divert" and key[2] in ("forward", "input"):
        if hook == key[2] and prio == -175 and policy == "accept":
            divert_chains.add(key)
fence_exact = int(fence_exact and all(f in fence_chains for f in ("inet", "bridge")))
inet_divert = int(all((("inet", h) in {(k[0], k[2]) for k in divert_chains})
                      for h in ("forward", "input")))
bridge_divert = int(all((("bridge", h) in {(k[0], k[2]) for k in divert_chains})
                        for h in ("forward", "input")))
divert_exact = int(inet_divert and bridge_divert)
print(f"{fence_table} {fence_exact} {inet_divert} {bridge_divert} {divert_exact} 1")
PY
}

both_nodes_present() {
    [[ "$1" == 1 && "$2" == 1 ]]
}

# The original discrimination probe exercised only inner index 0, which is
# even and therefore RG1/node0.  That made fw1's zero counters a fixture-path
# observation rather than an H1 feed diagnosis.  The live probe must exercise
# both an even and odd tunnel index, in both decrypted directions, and retain
# per-node offered deltas.
fixture_probe_indices() {
    printf '0\n1\n'
}

fixture_probe_directions() {
    printf 'lan-to-peer\npeer-to-lan\n'
}

# ---- r6 observer inventory -------------------------------------------------
# The fixture already proves that nft diversion and NFQUEUE handles exist.
# These observers keep the stronger claims separate:
#   * static ruleset shape is read from nft JSON;
#   * listener/queue economics is read from the live process and procfs;
#   * per-packet CaptureOrigin, permit state, adjudication, and physical q0
#     ACK are NOT inferred from those surfaces.  They remain VOID unless the
#     running binary exports an authoritative witness.
observe_ruleset_shape() {
    # observe_ruleset_shape <ruleset.json>
    # Prints: readable fence_pinhole_shape divert_shape order_shape stn_rules.
    python3 - "$1" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as fh:
        doc = json.load(fh)
    items = doc.get("nftables")
    if not isinstance(items, list):
        raise ValueError("missing nftables list")
except Exception:
    print("0 0 0 0")
    raise SystemExit(0)

chains = {}
rules = []
for item in items:
    if not isinstance(item, dict):
        continue
    chain = item.get("chain")
    if isinstance(chain, dict):
        key = (str(chain.get("family")), str(chain.get("table")), str(chain.get("name")))
        chains[key] = chain
    rule = item.get("rule")
    if isinstance(rule, dict):
        rules.append(rule)

fence = 1
for family in ("inet", "bridge"):
    chain = chains.get((family, "xpf_transit_barrier", "forward"))
    if not isinstance(chain, dict) or chain.get("hook") != "forward" or \
       chain.get("prio") not in (0, "filter") or \
       str(chain.get("policy", "")).lower() != "drop":
        fence = 0

fence_rules = {}
for rule in rules:
    if rule.get("table") != "xpf_transit_barrier" or rule.get("chain") != "forward":
        continue
    expr = rule.get("expr")
    if not isinstance(expr, list):
        continue
    fence_rules.setdefault(str(rule.get("family")), []).append(expr)

# The rendered rule shape is intentionally structural.  Dynamic iifname set
# values may be elided by nft JSON, so this is not promoted to an exact
# pinhole-set claim unless the two expected rule forms are present.
for family in ("inet", "bridge"):
    exprs = fence_rules.get(family, [])
    has_ifset = any(
        any(isinstance(e, dict) and isinstance(e.get("match"), dict) and
            isinstance(e["match"].get("right"), dict) and
            "set" in e["match"]["right"] for e in expr)
        and any(isinstance(e, dict) and "accept" in e for e in expr)
        for expr in exprs
    )
    has_marked = any(
        any(isinstance(e, dict) and isinstance(e.get("match"), dict) and
            e["match"].get("right") == "xpf-usp1" for e in expr)
        and any(isinstance(e, dict) and isinstance(e.get("match"), dict) and
            e["match"].get("left", {}).get("meta", {}).get("key") == "mark" and
            e["match"].get("right") == 0x58465001 for e in expr)
        and any(isinstance(e, dict) and "accept" in e for e in expr)
        for expr in exprs
    )
    if not (has_ifset and has_marked):
        fence = 0

expected = {("inet", "forward"), ("inet", "input"),
            ("bridge", "forward"), ("bridge", "input")}
divert_shape = 1
order_shape = 1
stn_rules = 0
for family, hook in expected:
    chain = chains.get((family, "xpf_ipsec_divert", hook))
    if not isinstance(chain, dict) or chain.get("hook") != hook or \
       chain.get("prio") != -175 or \
       str(chain.get("policy", "")).lower() != "accept":
        divert_shape = 0
        order_shape = 0
    for rule in rules:
        if rule.get("family") != family or rule.get("table") != "xpf_ipsec_divert" or \
           rule.get("chain") != hook:
            continue
        expr = rule.get("expr")
        if not isinstance(expr, list) or len(expr) != 2:
            divert_shape = 0
            continue
        match, queue = expr
        left = match.get("match", {}) if isinstance(match, dict) else {}
        right = queue.get("queue", {}) if isinstance(queue, dict) else {}
        if left.get("op") != "==" or \
           left.get("left", {}).get("meta", {}).get("key") != "iifname" or \
           not str(left.get("right", "")).startswith("st9506.") or \
           not isinstance(right, dict) or not isinstance(right.get("num"), int):
            divert_shape = 0
        else:
            stn_rules += 1

if stn_rules == 0:
    divert_shape = 0
if any(
    isinstance(c, dict) and c.get("table") == "xpf_ipsec_divert" and
    c.get("hook") in ("forward", "input") and c.get("prio") != -175
    for c in chains.values()
):
    order_shape = 0
print(f"1 {fence} {divert_shape} {order_shape} {stn_rules}")
PY
}

observe_provenance_metadata() {
    # observe_provenance_metadata <ruleset.json> <nfqueue.txt>
    #   [status.json] [metrics.prom] [st-links.txt]
    # Static queue→family/hook/stN mapping is measurable from nft/procfs.
    # Packet metadata joins bounded Rust rows against Go actor counters on
    # (run_id, generation, permit_epoch). Missing surfaces remain the literal
    # value "unavailable"; zero is emitted only for a present, authoritative
    # counter/list.
    #
    # Rust rows carry NORMALIZED CaptureOrigin values: family 1=inet, 2=bridge
    # and hook 1=forward, 2=input (slowpath_reinject_9506.rs ORIGIN_*).
    # Raw AF_INET/AF_INET6/AF_BRIDGE and NF_INET_* values are pre-normalization
    # packet values and must never be used for this status-row join.
    python3 - "$1" "$2" "${3:-}" "${4:-}" "${5:-}" <<'PY'
import json
import re
import sys

ruleset_path, nfqueue_path = sys.argv[1:3]
status_path = sys.argv[3]
metrics_path = sys.argv[4]
stlinks_path = sys.argv[5]
classes = (("inet", "forward"), ("inet", "input"),
           ("bridge", "forward"), ("bridge", "input"))
class_counts = {item: 0 for item in classes}
rule_map = {}
rule_ids = set()
UNAVAILABLE = "unavailable"
ruleset_ok = True
static = 1

try:
    with open(ruleset_path, encoding="utf-8") as fh:
        doc = json.load(fh)
    if not isinstance(doc, dict) or not isinstance(doc.get("nftables"), list):
        raise ValueError("missing nftables list")
except Exception:
    ruleset_ok = False
    static = 0

if ruleset_ok:
    for item in doc["nftables"]:
        rule = item.get("rule") if isinstance(item, dict) else None
        if not isinstance(rule, dict) or rule.get("table") != "xpf_ipsec_divert":
            continue
        expr = rule.get("expr")
        if not isinstance(expr, list) or len(expr) != 2:
            static = 0
            continue
        match = expr[0].get("match", {}) if isinstance(expr[0], dict) else {}
        queue = expr[1].get("queue", {}) if isinstance(expr[1], dict) else {}
        stn = str(match.get("right", ""))
        qnum = queue.get("num") if isinstance(queue, dict) else None
        valid = (
            match.get("op") == "=="
            and match.get("left", {}).get("meta", {}).get("key") == "iifname"
            and re.fullmatch(r"st9506\.[0-9]+", stn) is not None
            and isinstance(queue, dict)
            and isinstance(qnum, int)
            and not isinstance(qnum, bool)
        )
        if not valid:
            static = 0
            continue
        fam = str(rule.get("family", ""))
        hook = str(rule.get("chain", ""))
        if (fam, hook) not in class_counts:
            static = 0
            continue
        if qnum in rule_map:
            # Queue numbers must be unique across all four lists: family and
            # hook are part of CaptureOrigin and may not alias.
            static = 0
            continue
        rule_map[qnum] = (fam, hook, stn)
        rule_ids.add(qnum)
        class_counts[(fam, hook)] += 1
    static = int(static and bool(rule_ids))
else:
    static = 0

proc_ids = set()
proc_available = False
try:
    with open(nfqueue_path, encoding="utf-8") as fh:
        proc_available = True
        for line in fh:
            fields = line.split()
            if len(fields) >= 3 and fields[0].isdigit():
                proc_ids.add(int(fields[0]))
except OSError:
    pass
queue_rows = len(proc_ids) if proc_available else UNAVAILABLE
mismatch = int(bool(proc_ids) and not rule_ids.issubset(proc_ids)) if proc_available else UNAVAILABLE

# Optional ifindex source. The ruleset has no ifindex field; when this source
# is absent, ifindex is unavailable rather than silently treated as matching.
ifindexes = {}
ifindex_check = False
if stlinks_path:
    try:
        with open(stlinks_path, encoding="utf-8") as fh:
            ifindex_check = True
            for line in fh:
                m = re.search(r"(?:^|\s)([0-9]+):\s+(st9506\.[0-9]+)(?:@|:)", line)
                if m:
                    ifindexes[m.group(2)] = int(m.group(1))
    except OSError:
        pass

join = UNAVAILABLE
join_reason = "join-inputs-absent"
packet_samples = UNAVAILABLE
stale_samples = UNAVAILABLE
malformed_samples = UNAVAILABLE
packet_classes = UNAVAILABLE
rows_if = rows_ii = rows_bf = rows_bi = UNAVAILABLE
rows_pf_inet = rows_pf_bridge = UNAVAILABLE
prov_mismatch = pf_mismatch = UNAVAILABLE
go_uncertain = go_late = go_timeouts = go_stale = go_cancelled = go_refused = UNAVAILABLE
rust_uncertain = rust_late = rust_timeouts = rust_stale = rust_cancelled = rust_refused = UNAVAILABLE
counter_mismatch = UNAVAILABLE
go_consumed = go_adjudicated = go_reinjected = go_written = UNAVAILABLE
rust_written = rust_reinjected = UNAVAILABLE

def parse_status(path):
    try:
        with open(path, encoding="utf-8") as fh:
            value = json.load(fh)
    except Exception:
        return None, "s5-status-unreadable"
    if isinstance(value, dict) and isinstance(value.get("status"), dict):
        value = value["status"]
    row = value.get("s5_reinject") if isinstance(value, dict) else None
    if not isinstance(row, dict):
        return None, "s5_reinject-status-absent"
    return row, ""

def parse_metrics(path):
    samples = {}
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except Exception:
        return samples
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        match = re.match(
            r"^([a-zA-Z_:][a-zA-Z0-9_:]*)\{([^}]*)\}\s+([-+0-9.eE]+)", line
        )
        if not match:
            continue
        labels = dict(re.findall(
            r'([a-zA-Z_][a-zA-Z0-9_]*)="([^"]*)"', match.group(2)
        ))
        if all(key in labels for key in ("run_id", "generation", "permit_epoch")):
            key = (labels["run_id"], labels["generation"], labels["permit_epoch"])
            samples.setdefault(key, {})[match.group(1)] = match.group(3)
    return samples

def number(value):
    try:
        if value is None or isinstance(value, bool):
            return None
        return int(float(value))
    except (TypeError, ValueError):
        return None

# These values are the serialized normalized CaptureOrigin values, not raw
# nfgenmsg family/hook values.
families = {1: "inet", 2: "bridge"}
hooks = {1: "forward", 2: "input"}
required_status = (
    "run_id", "generation", "permit_epoch", "completed_written", "reinjected",
)
required_go = (
    "xpf_ipsec_capture_actor_active",
    "xpf_ipsec_capture_consumed_total",
    "xpf_ipsec_capture_adjudicated_total",
    "xpf_ipsec_capture_reinjected_total",
    "xpf_ipsec_capture_written_total",
    "xpf_ipsec_capture_uncertain_total",
    "xpf_ipsec_capture_late_completions_total",
    "xpf_ipsec_capture_timeouts_total",
    "xpf_ipsec_capture_stale_total",
    "xpf_ipsec_capture_cancelled_total",
    "xpf_ipsec_capture_refused_total",
)

if status_path and metrics_path:
    rust, reason = parse_status(status_path)
    if rust is None:
        join_reason = reason
    elif any(key not in rust for key in required_status):
        join_reason = "s5-status-fields-absent"
    elif any(
        not isinstance(rust[key], int) or isinstance(rust[key], bool)
        for key in ("generation", "permit_epoch")
    ):
        join_reason = "s5-status-fields-invalid"
    else:
        samples = parse_metrics(metrics_path)
        key = (str(rust["run_id"]), str(rust["generation"]),
               str(rust["permit_epoch"]))
        row = samples.get(key)
        if row is None:
            join_reason = "go-rust-join-key-mismatch"
        elif any(key not in row or number(row.get(key)) is None for key in required_go):
            join_reason = "go-witness-counters-absent"
        else:
            provenance = rust.get("provenance", [])
            if not isinstance(provenance, list):
                join_reason = "provenance-malformed"
            else:
                join = "joined"
                join_reason = "witness-joined"
                current_provenance = []
                stale_samples = 0
                malformed_samples = 0
                current_epoch = rust["permit_epoch"]
                for candidate in provenance:
                    if not isinstance(candidate, dict):
                        malformed_samples += 1
                    elif (
                        not isinstance(candidate.get("permit_epoch"), int)
                        or isinstance(candidate.get("permit_epoch"), bool)
                    ):
                        malformed_samples += 1
                    elif candidate["permit_epoch"] != current_epoch:
                        stale_samples += 1
                    else:
                        current_provenance.append(candidate)
                packet_samples = len(current_provenance)
                packet_class_counts = {item: 0 for item in classes}
                pm = 0
                bucket_counts = {
                    "written": 0,
                    "uncertain": 0,
                    "late": 0,
                    "timeouts": 0,
                    "stale": 0,
                    "cancelled": 0,
                    "refused": 0,
                    "unknown": 0,
                }
                pfm = 0
                for packet in current_provenance:
                    queue = packet.get("queue_number")
                    family_raw = packet.get("family")
                    hook_raw = packet.get("hook")
                    family = families.get(family_raw) if isinstance(family_raw, int) and not isinstance(family_raw, bool) else None
                    hook = hooks.get(hook_raw) if isinstance(hook_raw, int) and not isinstance(hook_raw, bool) else None
                    stn = packet.get("stn")
                    owner = packet.get("owner")
                    valid_shape = (
                        isinstance(queue, int) and not isinstance(queue, bool)
                        and family is not None and hook is not None
                        and isinstance(stn, str) and bool(stn)
                        and isinstance(owner, str) and bool(owner)
                        and isinstance(packet.get("owned_ifindex"), int)
                        and not isinstance(packet.get("owned_ifindex"), bool)
                        and packet.get("owned_ifindex") > 0
                        and isinstance(packet.get("permit_epoch"), int)
                        and not isinstance(packet.get("permit_epoch"), bool)
                        and packet.get("permit_epoch") == current_epoch
                        and isinstance(packet.get("outcome"), str)
                        and bool(packet.get("outcome"))
                    )
                    if not valid_shape:
                        pm += 1
                        continue
                    outcome = packet["outcome"].lower()
                    outcome_bucket = {
                        "written": "written",
                        "accepted": "uncertain",
                        "would_reinject": "uncertain",
                        "uncertain": "uncertain",
                        "stale": "stale",
                        "fenced": "stale",
                        "cancelled": "cancelled",
                        "canceled": "cancelled",
                        "refused": "refused",
                        "denied": "refused",
                    }.get(outcome, "unknown")
                    bucket_counts[outcome_bucket] += 1
                    packet_class_counts[(family, hook)] += 1
                    expected = rule_map.get(queue)
                    if expected is None:
                        pm += 1
                        continue
                    expected_family, expected_hook, expected_stn = expected
                    if (family, hook) != (expected_family, expected_hook):
                        pfm += 1
                    if stn != expected_stn:
                        pm += 1
                    # The fixture's owner names are vpn9506t<N>, where N is
                    # the stN unit suffix. A wrong/poison owner is a mismatch.
                    suffix = expected_stn.rsplit(".", 1)[-1]
                    if owner != "vpn9506t" + suffix:
                        pm += 1
                    if ifindex_check:
                        if ifindexes.get(expected_stn) != packet.get("owned_ifindex"):
                            pm += 1
                rows_if = packet_class_counts[("inet", "forward")]
                rows_ii = packet_class_counts[("inet", "input")]
                rows_bf = packet_class_counts[("bridge", "forward")]
                rows_bi = packet_class_counts[("bridge", "input")]
                rows_pf_inet = rows_if + rows_ii
                rows_pf_bridge = rows_bf + rows_bi
                packet_classes = sum(
                    1 for item in classes if packet_class_counts[item] > 0
                )
                prov_mismatch = pm
                pf_mismatch = pfm
                go_consumed = number(row["xpf_ipsec_capture_consumed_total"])
                go_adjudicated = number(row["xpf_ipsec_capture_adjudicated_total"])
                go_reinjected = number(row["xpf_ipsec_capture_reinjected_total"])
                go_written = number(row["xpf_ipsec_capture_written_total"])
                go_uncertain = number(row["xpf_ipsec_capture_uncertain_total"])
                go_late = number(row["xpf_ipsec_capture_late_completions_total"])
                go_timeouts = number(row["xpf_ipsec_capture_timeouts_total"])
                go_stale = number(row["xpf_ipsec_capture_stale_total"])
                go_cancelled = number(row["xpf_ipsec_capture_cancelled_total"])
                go_refused = number(row["xpf_ipsec_capture_refused_total"])
                rust_written = bucket_counts["written"]
                rust_uncertain = bucket_counts["uncertain"]
                rust_late = 0
                rust_timeouts = 0
                rust_reinjected = rust_written
                rust_stale = bucket_counts["stale"]
                rust_cancelled = bucket_counts["cancelled"]
                rust_refused = bucket_counts["refused"]
                counter_mismatch = int(
                    packet_samples != go_adjudicated
                    or rust_reinjected != go_reinjected
                    or rust_written != go_written
                    or rust_uncertain != go_uncertain
                    or rust_late != go_late
                    or rust_timeouts != go_timeouts
                    or rust_stale != go_stale
                    or rust_cancelled != go_cancelled
                    or bucket_counts["unknown"] != 0
                    or rust_refused != go_refused
                    or sum(bucket_counts.values()) != packet_samples
                )
                if malformed_samples:
                    # A malformed bounded row cannot establish an exact
                    # current-epoch witness, even when other rows are valid.
                    join = UNAVAILABLE
                    join_reason = "provenance-row-malformed"
                    packet_samples = UNAVAILABLE
                    packet_classes = UNAVAILABLE
                    rows_if = rows_ii = rows_bf = rows_bi = UNAVAILABLE
                    rows_pf_inet = rows_pf_bridge = UNAVAILABLE
                    prov_mismatch = pf_mismatch = UNAVAILABLE
                    counter_mismatch = UNAVAILABLE
                    go_consumed = go_adjudicated = go_reinjected = go_written = UNAVAILABLE
                    go_uncertain = go_late = go_timeouts = UNAVAILABLE
                    go_stale = go_cancelled = go_refused = UNAVAILABLE
                    rust_written = rust_reinjected = UNAVAILABLE
                    rust_uncertain = rust_late = rust_timeouts = UNAVAILABLE
                    rust_stale = rust_cancelled = rust_refused = UNAVAILABLE
                elif packet_samples == 0 and go_consumed > 0:
                    # Bounded history may contain only stale permit epochs.
                    # A positive current-epoch Go count then cannot be joined
                    # to exact Rust packet metadata.
                    join = UNAVAILABLE
                    join_reason = "provenance-epoch-no-current-rows"
                    packet_samples = UNAVAILABLE
                    packet_classes = UNAVAILABLE
                    rows_if = rows_ii = rows_bf = rows_bi = UNAVAILABLE
                    rows_pf_inet = rows_pf_bridge = UNAVAILABLE
                    prov_mismatch = pf_mismatch = UNAVAILABLE
                    counter_mismatch = UNAVAILABLE
                    go_consumed = go_adjudicated = go_reinjected = go_written = UNAVAILABLE
                    go_uncertain = go_late = go_timeouts = UNAVAILABLE
                    go_stale = go_cancelled = go_refused = UNAVAILABLE
                    rust_written = rust_reinjected = UNAVAILABLE
                    rust_uncertain = rust_late = rust_timeouts = UNAVAILABLE
                    rust_stale = rust_cancelled = rust_refused = UNAVAILABLE
                if not ifindex_check:
                    # The packet rows and actor counters are real, but the
                    # required owned-ifindex witness is absent; do not expose
                    # an exact join or substitute zeroes.
                    join = UNAVAILABLE
                    join_reason = "st-links-surface-absent"
                    packet_samples = UNAVAILABLE
                    packet_classes = UNAVAILABLE
                    rows_if = rows_ii = rows_bf = rows_bi = UNAVAILABLE
                    rows_pf_inet = rows_pf_bridge = UNAVAILABLE
                    prov_mismatch = pf_mismatch = UNAVAILABLE
                    counter_mismatch = UNAVAILABLE
                    go_consumed = go_adjudicated = go_reinjected = go_written = UNAVAILABLE
                    go_uncertain = go_late = go_timeouts = UNAVAILABLE
                    go_stale = go_cancelled = go_refused = UNAVAILABLE
                    rust_written = rust_reinjected = UNAVAILABLE
                    rust_uncertain = rust_late = rust_timeouts = UNAVAILABLE
                    rust_stale = rust_cancelled = rust_refused = UNAVAILABLE

print(
    f"static={static} queue_rows={queue_rows} queue_ids={len(rule_ids)} "
    f"packet_samples={packet_samples} stale_samples={stale_samples} "
    f"malformed_samples={malformed_samples} mismatch={mismatch} join={join} "
    f"join_reason={join_reason} "
    f"classes_inet_forward={class_counts[('inet', 'forward')]} "
    f"classes_inet_input={class_counts[('inet', 'input')]} "
    f"classes_bridge_forward={class_counts[('bridge', 'forward')]} "
    f"classes_bridge_input={class_counts[('bridge', 'input')]} "
    f"provenance_classes={sum(1 for item in classes if class_counts[item] > 0)} "
    f"pf_inet={class_counts[('inet', 'forward')] + class_counts[('inet', 'input')]} "
    f"pf_bridge={class_counts[('bridge', 'forward')] + class_counts[('bridge', 'input')]} "
    f"packet_classes={packet_classes} rows_inet_forward={rows_if} "
    f"rows_inet_input={rows_ii} rows_bridge_forward={rows_bf} "
    f"rows_bridge_input={rows_bi} rows_pf_inet={rows_pf_inet} "
    f"rows_pf_bridge={rows_pf_bridge} prov_mismatch={prov_mismatch} "
    f"pf_mismatch={pf_mismatch} counter_mismatch={counter_mismatch} "
    f"go_consumed={go_consumed} go_adjudicated={go_adjudicated} "
    f"go_reinjected={go_reinjected} go_written={go_written} "
    f"go_uncertain={go_uncertain} go_late={go_late} "
    f"go_timeouts={go_timeouts} go_stale={go_stale} "
    f"go_cancelled={go_cancelled} go_refused={go_refused} "
    f"rust_written={rust_written} rust_reinjected={rust_reinjected} "
    f"rust_uncertain={rust_uncertain} rust_late={rust_late} "
    f"rust_timeouts={rust_timeouts} rust_stale={rust_stale} "
    f"rust_cancelled={rust_cancelled} rust_refused={rust_refused} "
    f"ifindex_checked={'1' if ifindex_check else UNAVAILABLE}"
)
PY
}
observer_field() {
    local text="$1" key="$2" word
    for word in $text; do
        if [[ "$word" == "$key="* ]]; then
            printf '%s\n' "${word#*=}"
            return 0
        fi
    done
    printf '0\n'
}

observe_runtime() {
    # observe_runtime <node> <directory> <tag>
    # Capture the Rust status block and authenticated-loopback Go metrics.
    # The two surfaces are joined on run_id/generation/permit_epoch; a
    # missing surface stays unavailable instead of becoming an all-zero actor.
    local node="$1"
    local dir="$2"
    local tag="$3"
    local status proc metrics metrics_url
    status="$dir/${tag}-status.json"
    proc="$dir/${tag}-runtime.txt"
    metrics="$dir/${tag}-metrics.prom"
    metrics_url="${METRICS_URL:-http://127.0.0.1:8080/metrics}"
    mkdir -p "$dir"
    remote "$node" "python3 - <<'PY'
import socket
try:
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(2)
    s.connect('/run/xpf/userspace-dp.sock')
    s.sendall(b'{\"type\":\"status\"}\\n')
    chunks = []
    while True:
        part = s.recv(1048576)
        if not part:
            break
        chunks.append(part)
        if b'\\n' in part:
            break
    print(b''.join(chunks).decode(errors='replace'))
except Exception as exc:
    print('STATUS_ERROR=' + str(exc))
PY" >"$status" 2>&1 || :
    remote "$node" "curl -fsS --max-time 2 '$metrics_url'" >"$metrics" 2>&1 || :
    remote "$node" 'set +e
pid="$(pidof xpfd | awk "{print \$1}")"
printf "xpfd_pid=%s\n" "${pid:-0}"
if [[ -n "${pid:-}" && -r "/proc/$pid/fd" ]]; then
    printf "xpfd_fd_count=%s\n" "$(find "/proc/$pid/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)"
else
    printf "xpfd_fd_count=0\n"
fi
for sock in /run/xpf/reinject-submit.sock /run/xpf/reinject-complete.sock /run/xpf/userspace-dp.sock; do
    [[ -S "$sock" ]] && printf "socket_%s=1\n" "$(basename "$sock" .sock | tr - _)" ||
        printf "socket_%s=0\n" "$(basename "$sock" .sock | tr - _)"
done
cat /proc/net/netfilter/nfnetlink_queue 2>&1
printf "===NETLINK===\n"
cat /proc/net/netlink 2>&1' >"$proc" 2>&1 || :
    RUNTIME_STATUS_FILE="$status"
    RUNTIME_METRICS_FILE="$metrics"
    RUNTIME_PROC_FILE="$proc"
    RUNTIME_PID=0
    RUNTIME_FD_COUNT=0
    RUNTIME_QUEUE_ROWS=0
    RUNTIME_QUEUE_PENDING=0
    RUNTIME_QUEUE_DROPS=0
    RUNTIME_DAEMON_ACTIVE=0
    RUNTIME_SOCKET_READY=0
    RUNTIME_ACTOR_ACTIVE=0
    RUNTIME_REINJECT_SOCKETS=0
    RUNTIME_S5_AVAILABLE=0
    RUNTIME_RUN_ID=""
    RUNTIME_GENERATION=0
    RUNTIME_PERMIT_EPOCH=0
    RUNTIME_PERMIT_STATE="UNKNOWN"
    RUNTIME_PERMIT_OPEN=0
    RUNTIME_CONSUMED=0
    RUNTIME_ADJUDICATED=0
    RUNTIME_REINJECTED=0
    RUNTIME_WRITTEN=0
    RUNTIME_UNCERTAIN=0
    RUNTIME_LATE_COMPLETIONS=0
    RUNTIME_TIMEOUTS=0
    RUNTIME_STALE=0
    RUNTIME_CANCELLED=0
    RUNTIME_REFUSED=0
    RUNTIME_DELIVERED_AVAILABLE=0
    RUNTIME_DELIVERED=0
    RUNTIME_REASON="product-observer-unavailable:s5-status-or-go-metrics-absent"
    RUNTIME_PID="$(sed -n 's/^xpfd_pid=//p' "$proc" | head -n 1)"
    RUNTIME_FD_COUNT="$(sed -n 's/^xpfd_fd_count=//p' "$proc" | head -n 1)"
    [[ "$RUNTIME_PID" =~ ^[0-9]+$ ]] || RUNTIME_PID=0
    [[ "$RUNTIME_FD_COUNT" =~ ^[0-9]+$ ]] || RUNTIME_FD_COUNT=0
    local submit complete control
    submit="$(sed -n 's/^socket_reinject_submit=//p' "$proc" | head -n 1)"
    complete="$(sed -n 's/^socket_reinject_complete=//p' "$proc" | head -n 1)"
    control="$(sed -n 's/^socket_userspace_dp=//p' "$proc" | head -n 1)"
    if [[ "$RUNTIME_PID" != 0 ]]; then
        RUNTIME_DAEMON_ACTIVE=1
    fi
    if [[ "$submit" == 1 && "$complete" == 1 && "$control" == 1 ]]; then
        RUNTIME_SOCKET_READY=1
        RUNTIME_REINJECT_SOCKETS=2
    fi
    RUNTIME_QUEUE_ROWS="$(awk '/^===NETLINK===/{exit} /^[[:space:]]*[0-9]+[[:space:]]+[0-9]+[[:space:]]+[0-9]+/ {n++} END {print n+0}' "$proc")"
    RUNTIME_QUEUE_PENDING="$(awk '/^===NETLINK===/{exit} /^[[:space:]]*[0-9]+[[:space:]]+[0-9]+[[:space:]]+[0-9]+/ {sum += $3} END {print sum+0}' "$proc")"
    RUNTIME_QUEUE_DROPS="$(awk '/^===NETLINK===/{exit} /^[[:space:]]*[0-9]+[[:space:]]+[0-9]+[[:space:]]+[0-9]+/ {sum += $6 + $7} END {print sum+0}' "$proc")"
    local witness
    witness="$(python3 - "$status" "$metrics" <<'PY'
import json, re, sys
status_path, metrics_path = sys.argv[1:3]
def out(**values):
    print(" ".join(f"{k}={values[k]}" for k in (
        "available", "actor", "run_id", "generation", "epoch", "state",
        "consumed", "adjudicated", "reinjected", "written", "uncertain",
        "late_completions", "timeouts", "stale", "cancelled", "refused",
        "delivered_available", "delivered", "reason"
    )))
try:
    with open(status_path, encoding="utf-8") as fh:
        doc = json.load(fh)
    if isinstance(doc, dict) and isinstance(doc.get("status"), dict):
        doc = doc["status"]
    rust = doc.get("s5_reinject") if isinstance(doc, dict) else None
except Exception:
    rust = None
samples = {}
try:
    text = open(metrics_path, encoding="utf-8").read()
except Exception:
    text = ""
for line in text.splitlines():
    if not line or line.startswith("#"):
        continue
    m = re.match(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)\{([^}]*)\}\s+([-+0-9.eE]+)", line)
    if not m:
        continue
    labels = dict(re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)="([^"]*)"', m.group(2)))
    if all(key in labels for key in ("run_id", "generation", "permit_epoch")):
        key = (labels["run_id"], labels["generation"], labels["permit_epoch"])
        samples.setdefault(key, {})[m.group(1)] = (labels, m.group(3))
if not isinstance(rust, dict):
    out(available=0, actor=0, run_id="", generation=0, epoch=0, state="UNKNOWN",
        consumed=0, adjudicated=0, reinjected=0, written=0, uncertain=0,
        late_completions=0, timeouts=0, stale=0, cancelled=0, refused=0,
        delivered_available=0, delivered=0,
        reason="product-observer-unavailable:s5_reinject-status-absent")
    raise SystemExit
run_id = str(rust.get("run_id", ""))
generation = str(rust.get("generation", 0))
epoch = str(rust.get("permit_epoch", 0))
state = str(rust.get("permit_state", "UNKNOWN"))
row = samples.get((run_id, generation, epoch))
if row is None:
    out(available=0, actor=0, run_id=run_id, generation=generation, epoch=epoch,
        state=state, consumed=0, adjudicated=0, reinjected=0, written=0,
        uncertain=0, late_completions=0, timeouts=0, stale=0, cancelled=0,
        refused=0, delivered_available=0, delivered=0,
        reason="product-observer-unavailable:go-rust-join-key-mismatch")
    raise SystemExit
def value(name):
    item = row.get(name)
    if item is None:
        return None
    try:
        return int(float(item[1]))
    except ValueError:
        return None
def delivery_value():
    availability = value("xpf_ipsec_capture_delivered_available")
    if availability is None:
        return 0, 0, "go-delivery-availability-absent"
    if availability not in (0, 1):
        return 0, 0, "go-delivery-availability-invalid"
    count = value("xpf_ipsec_capture_delivered_total")
    if availability == 0:
        if count is not None:
            return 0, 0, "go-delivery-count-present-while-unavailable"
        return 0, 0, "residual-downstream-of-tun-witness-unavailable"
    if count is None:
        return 0, 0, "go-delivery-count-absent"
    return 1, count, ""
actor = value("xpf_ipsec_capture_actor_active")
consumed = value("xpf_ipsec_capture_consumed_total")
adjudicated = value("xpf_ipsec_capture_adjudicated_total")
reinjected = value("xpf_ipsec_capture_reinjected_total")
written = value("xpf_ipsec_capture_written_total")
uncertain = value("xpf_ipsec_capture_uncertain_total")
late_completions = value("xpf_ipsec_capture_late_completions_total")
timeouts = value("xpf_ipsec_capture_timeouts_total")
stale = value("xpf_ipsec_capture_stale_total")
cancelled = value("xpf_ipsec_capture_cancelled_total")
refused = value("xpf_ipsec_capture_refused_total")
if None in (actor, consumed, adjudicated, reinjected, written, uncertain,
            late_completions, timeouts, stale, cancelled, refused):
    out(available=0, actor=0, run_id=run_id, generation=generation, epoch=epoch,
        state=state, consumed=0, adjudicated=0, reinjected=0, written=0,
        uncertain=0, late_completions=0, timeouts=0, stale=0, cancelled=0,
        refused=0, delivered_available=0, delivered=0,
        reason="product-observer-unavailable:go-witness-counters-absent")
    raise SystemExit
delivered_available, delivered, delivery_reason = delivery_value()
reason = "witness-joined"
if delivery_reason:
    reason += ":" + delivery_reason
out(available=1, actor=actor, run_id=run_id, generation=generation, epoch=epoch,
    state=state, consumed=consumed, adjudicated=adjudicated, reinjected=reinjected,
    written=written, uncertain=uncertain, late_completions=late_completions,
    timeouts=timeouts, stale=stale, cancelled=cancelled, refused=refused,
    delivered_available=delivered_available, delivered=delivered, reason=reason)
PY
)"
    local key value
    for key in available actor run_id generation epoch state consumed adjudicated reinjected written uncertain late_completions timeouts stale cancelled refused delivered_available delivered reason; do
        value=""
        for word in $witness; do
            if [[ "$word" == "$key="* ]]; then value="${word#*=}"; break; fi
        done
        case "$key" in
        available) [[ "$value" == 1 ]] && RUNTIME_S5_AVAILABLE=1 ;;
        actor) RUNTIME_ACTOR_ACTIVE="${value:-0}" ;;
        run_id) RUNTIME_RUN_ID="${value:-}" ;;
        generation) RUNTIME_GENERATION="${value:-0}" ;;
        epoch) RUNTIME_PERMIT_EPOCH="${value:-0}" ;;
        state) RUNTIME_PERMIT_STATE="${value:-UNKNOWN}" ;;
        consumed) RUNTIME_CONSUMED="${value:-0}" ;;
        adjudicated) RUNTIME_ADJUDICATED="${value:-0}" ;;
        reinjected) RUNTIME_REINJECTED="${value:-0}" ;;
        written) RUNTIME_WRITTEN="${value:-0}" ;;
        uncertain) RUNTIME_UNCERTAIN="${value:-0}" ;;
        late_completions) RUNTIME_LATE_COMPLETIONS="${value:-0}" ;;
        timeouts) RUNTIME_TIMEOUTS="${value:-0}" ;;
        stale) RUNTIME_STALE="${value:-0}" ;;
        cancelled) RUNTIME_CANCELLED="${value:-0}" ;;
        refused) RUNTIME_REFUSED="${value:-0}" ;;
        delivered_available) RUNTIME_DELIVERED_AVAILABLE="${value:-0}" ;;
        delivered) RUNTIME_DELIVERED="${value:-0}" ;;
        reason) RUNTIME_REASON="${value:-product-observer-unavailable}" ;;
        esac
    done
    [[ "$RUNTIME_PERMIT_STATE" == OPEN ]] && RUNTIME_PERMIT_OPEN=1
    printf 'RUNTIME tag=%s daemon_active=%s pid=%s fd_count=%s socket_ready=%s reinject_sockets=%s s5_available=%s actor_active=%s run_id=%s generation=%s permit_state=%s permit_epoch=%s queue_rows=%s queue_pending=%s queue_drops=%s consumed=%s adjudicated=%s reinjected=%s written=%s uncertain=%s late_completions=%s timeouts=%s stale=%s cancelled=%s refused=%s delivered_available=%s delivered=%s reason=%s\n' \
        "$tag" "$RUNTIME_DAEMON_ACTIVE" "$RUNTIME_PID" "$RUNTIME_FD_COUNT" \
        "$RUNTIME_SOCKET_READY" "$RUNTIME_REINJECT_SOCKETS" "$RUNTIME_S5_AVAILABLE" \
        "$RUNTIME_ACTOR_ACTIVE" "$RUNTIME_RUN_ID" "$RUNTIME_GENERATION" \
        "$RUNTIME_PERMIT_STATE" "$RUNTIME_PERMIT_EPOCH" "$RUNTIME_QUEUE_ROWS" \
        "$RUNTIME_QUEUE_PENDING" "$RUNTIME_QUEUE_DROPS" "$RUNTIME_CONSUMED" \
        "$RUNTIME_ADJUDICATED" "$RUNTIME_REINJECTED" "$RUNTIME_WRITTEN" \
        "$RUNTIME_UNCERTAIN" "$RUNTIME_LATE_COMPLETIONS" "$RUNTIME_TIMEOUTS" \
        "$RUNTIME_STALE" "$RUNTIME_CANCELLED" "$RUNTIME_REFUSED" \
        "$RUNTIME_DELIVERED_AVAILABLE" "$RUNTIME_DELIVERED" "$RUNTIME_REASON"
}

observe_queue_economics() {
    # observe_queue_economics <ruleset.json> <runtime.txt> <nfqueue.txt>
    local ruleset="$1" runtime="$2" nfqueue="$3"
    local queue_instances fd_count queue_pending queue_drops
    queue_instances="$(fix9506_divert_queue_ids "$ruleset" 2>/dev/null | wc -l)"
    fd_count="$(sed -n 's/^xpfd_fd_count=//p' "$runtime" | head -n 1)"
    queue_pending="$(awk '/^[[:space:]]*[0-9]+[[:space:]]+[0-9]+[[:space:]]+[0-9]+/ {sum += $3} END {print sum+0}' "$nfqueue" 2>/dev/null)"
    queue_drops="$(awk '/^[[:space:]]*[0-9]+[[:space:]]+[0-9]+/ {sum += $6 + $7} END {print sum+0}' "$nfqueue" 2>/dev/null)"
    [[ "$queue_instances" =~ ^[0-9]+$ ]] || queue_instances=0
    [[ "$fd_count" =~ ^[0-9]+$ ]] || fd_count=0
    [[ "$queue_pending" =~ ^[0-9]+$ ]] || queue_pending=0
    [[ "$queue_drops" =~ ^[0-9]+$ ]] || queue_drops=0
    # Queue buffer reservations and rotation overlap are not exposed by the
    # procfs rows; unknown is safer than pricing them from source constants.
    printf 'queue_instances=%s recv_buffers_mib=unknown socket_buffers_mib=unknown fd_count=%s queue_pending=%s queue_drops=%s rotation_overlap=unknown teardown=unknown\n' \
        "$queue_instances" "$fd_count" "$queue_pending" "$queue_drops"
}

observe_chain_overhead() {
    # observe_chain_overhead <node> <directory> <tag>
    # Chain/listener census is read-only. Workload deltas are supplied by the
    # caller's same-day baseline phases; this function never invents samples.
    local node="$1"
    local dir="$2"
    local tag="$3"
    local out
    out="$dir/${tag}-overhead.txt"
    remote "$node" 'printf "listener_unix="; ss -lxH 2>/dev/null | wc -l
printf "listener_reinject="; ss -lxH 2>/dev/null | grep -cE "reinject-(submit|complete)" || true
printf "listener_userspace="; ss -lxH 2>/dev/null | grep -c "userspace-dp" || true
printf "pid_xpfd="; pidof xpfd 2>/dev/null | awk "{print NF+0}"
printf "nfqueue_rows="; awk "NR>0 && NF>=3 && \$1 ~ /^[0-9]+$/ {n++} END {print n+0}" /proc/net/netfilter/nfnetlink_queue 2>/dev/null' >"$out" 2>&1 || :
    CHAIN_OVERHEAD_FILE="$out"
    CHAIN_OVERHEAD_LISTENERS="$(sed -n 's/^listener_unix=//p' "$out" | head -n 1)"
    CHAIN_OVERHEAD_REINJECT="$(sed -n 's/^listener_reinject=//p' "$out" | head -n 1)"
    CHAIN_OVERHEAD_XPFD="$(sed -n 's/^pid_xpfd=//p' "$out" | head -n 1)"
    CHAIN_OVERHEAD_NFQUEUE="$(sed -n 's/^nfqueue_rows=//p' "$out" | head -n 1)"
    [[ "$CHAIN_OVERHEAD_LISTENERS" =~ ^[0-9]+$ ]] || CHAIN_OVERHEAD_LISTENERS=0
    [[ "$CHAIN_OVERHEAD_REINJECT" =~ ^[0-9]+$ ]] || CHAIN_OVERHEAD_REINJECT=0
    [[ "$CHAIN_OVERHEAD_XPFD" =~ ^[0-9]+$ ]] || CHAIN_OVERHEAD_XPFD=0
    [[ "$CHAIN_OVERHEAD_NFQUEUE" =~ ^[0-9]+$ ]] || CHAIN_OVERHEAD_NFQUEUE=0
    printf 'OVERHEAD tag=%s listeners=%s reinject_listeners=%s xpfd=%s nfqueue_rows=%s baseline_samples=0 idle_samples=0 detached_samples=0\n' \
        "$tag" "$CHAIN_OVERHEAD_LISTENERS" "$CHAIN_OVERHEAD_REINJECT" \
        "$CHAIN_OVERHEAD_XPFD" "$CHAIN_OVERHEAD_NFQUEUE"
}

observe_vrf_scope() {
    # observe_vrf_scope <node> <directory> <tag>
    local node="$1"
    local dir="$2"
    local tag="$3"
    local out
    out="$dir/${tag}-vrf.txt"
    remote "$node" 'ip -d -j link show type xfrm 2>&1; printf "\n===RULES===\n"; ip -j rule show 2>&1; printf "\n===ROUTES===\n"; ip -j route show table all 2>&1' >"$out" 2>&1 || :
    VRF_SCOPE_FILE="$out"
    VRF_TEST_CREATED=0
    VRF_ATTACHED=0
    VRF_MASTER_INDEX=0
    VRF_INPUT_QUEUE_HITS=0
    VRF_SCOPE_REASON="measurement-incomplete:test-vrf-not-created-by-fixture"
    printf 'VRF tag=%s test_created=%s attached=%s master_index=%s input_queue_hits=%s reason=%s\n' \
        "$tag" "$VRF_TEST_CREATED" "$VRF_ATTACHED" "$VRF_MASTER_INDEX" \
        "$VRF_INPUT_QUEUE_HITS" "$VRF_SCOPE_REASON"
}
# The selftest is hermetic: it must not source cluster-env, call incus, or
# create ledger rows.  It checks the conservative refusal model and cell shape.
if [[ "$MODE" == selftest ]]; then
    pass=0
    fail=0
    ok() { echo "  PASS  $1"; pass=$((pass + 1)); }
    bad() { echo "  FAIL  $1"; fail=$((fail + 1)); }
    expect() {
        local label="$1" want="$2" got="$3"
        if [[ "$want" == "$got" ]]; then ok "$label"; else bad "$label (got=$got want=$want)"; fi
    }
    cell_verdict() {
        local fence="$1" divert="$2" fixture="$3" sha="$4"
        if [[ "$sha" != MATCH/both ]]; then
            printf 'VOID\tenv-void\n'
        elif [[ "$fixture" != 1 ]]; then
            printf 'VOID\tenv-void\n'
        else
            # The live body is deliberately conservative until packet/workload
            # measurements and verdict logic are implemented.
            printf 'VOID\tmeasurement-not-run\n'
        fi
    }
    expect "missing SA is VOID" "VOID" "$(cell_verdict 1 1 0 MATCH/both | cut -f1)"
    expect "missing divert is VOID" "VOID" "$(cell_verdict 1 0 0 MATCH/both | cut -f1)"
    expect "unattested binary is VOID" "VOID" "$(cell_verdict 1 1 1 MISMATCH/both | cut -f1)"
    expect "complete fixture awaits measurement" "VOID" "$(cell_verdict 1 1 1 MATCH/both | cut -f1)"
    expect "bad fence awaits measurement" "VOID" "$(cell_verdict 0 1 1 MATCH/both | cut -f1)"
    expect "bad divert awaits measurement" "VOID" "$(cell_verdict 1 0 1 MATCH/both | cut -f1)"
    cell_shape() {
        local label="$1"
        shift
        if [[ "$#" == 7 ]]; then ok "$label"; else bad "$label (argc=$# want=7)"; fi
    }
    cell_shape "VRF cell has seven fields" vrf sec pred obs VOID reason metrics
    cell_shape "G2 shape row has seven fields" g2 sec pred obs VOID reason metrics
    expect "single-node stN fixture is incomplete" "0" \
        "$(if both_nodes_present 1 0; then echo 1; else echo 0; fi)"
    expect "single-node SA fixture is incomplete" "0" \
        "$(if both_nodes_present 0 1; then echo 1; else echo 0; fi)"
    expect "paired fixture is complete" "1" \
        "$(if both_nodes_present 1 1; then echo 1; else echo 0; fi)"
    expect "traffic probes cover even and odd tunnel owners" "0 1" \
        "$(fixture_probe_indices | paste -sd ' ' -)"
    expect "traffic probes cover both decrypted directions" "lan-to-peer peer-to-lan" \
        "$(fixture_probe_directions | paste -sd ' ' -)"
    parser_dir="$(mktemp -d)"
    cat >"$parser_dir/witness-check.py" <<'PY'
import json, re, sys
status_path, metrics_path, mode = sys.argv[1:]
status = json.load(open(status_path, encoding="utf-8"))
rust = status.get("s5_reinject")
if mode == "absent":
    if rust is not None:
        raise SystemExit("absent fixture unexpectedly contains s5_reinject")
    print("0")
    raise SystemExit
text = open(metrics_path, encoding="utf-8").read()
samples = {}
for line in text.splitlines():
    m = re.match(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)\{([^}]*)\}\s+([-+0-9.eE]+)", line)
    if not m:
        continue
    labels = dict(re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)="([^"]*)"', m.group(2)))
    key = (labels.get("run_id"), labels.get("generation"), labels.get("permit_epoch"))
    samples.setdefault(key, {})[m.group(1)] = float(m.group(3))
key = (str(rust["run_id"]), str(rust["generation"]), str(rust["permit_epoch"]))
joined = key in samples
if mode == "join":
    print(int(joined))
elif mode == "zero":
    print(int(joined and samples[key]["xpf_ipsec_capture_consumed_total"] == 0))
elif mode == "dispositions":
    names = {
        "xpf_ipsec_capture_written_total": 3.0,
        "xpf_ipsec_capture_uncertain_total": 0.0,
        "xpf_ipsec_capture_late_completions_total": 0.0,
        "xpf_ipsec_capture_timeouts_total": 0.0,
        "xpf_ipsec_capture_stale_total": 0.0,
        "xpf_ipsec_capture_cancelled_total": 0.0,
        "xpf_ipsec_capture_refused_total": 1.0,
    }
    print(int(joined and all(samples[key].get(name) == value
                             for name, value in names.items())))
elif mode == "refusal":
    rows = rust.get("provenance", [])
    print(int(any(row.get("outcome") == "refused" for row in rows)))
elif mode in ("delivery", "delivery-positive", "delivery-missing-count",
              "delivery-count-while-unavailable"):
    row = samples.get(key, {})
    available = row.get("xpf_ipsec_capture_delivered_available")
    count = row.get("xpf_ipsec_capture_delivered_total")
    if mode == "delivery":
        print(int(joined and available == 0.0 and count is None))
    elif mode == "delivery-positive":
        print(int(joined and available == 1.0 and count == 11.0))
    elif mode == "delivery-missing-count":
        print(int(joined and available == 1.0 and count is None))
    else:
        print(int(joined and available == 0.0 and count is not None))
PY
    printf '%s\n' '{}' >"$parser_dir/absent.json"
    cat >"$parser_dir/witness.json" <<'EOF'
{"s5_reinject":{"run_id":"run-1","generation":4,"permit_epoch":7,"completed_written":4,"reinjected":4,"delivered_available":true,"delivered":999,"provenance":[{"request_id":1,"permit_epoch":7,"queue_epoch":1,"queue_number":1000,"family":1,"hook":1,"owned_ifindex":7,"owner":"vpn9506t0","stn":"st9506.0","outcome":"written","bytes_written":84},{"request_id":2,"permit_epoch":7,"queue_epoch":1,"queue_number":1001,"family":1,"hook":2,"owned_ifindex":7,"owner":"vpn9506t0","stn":"st9506.0","outcome":"written","bytes_written":84},{"request_id":3,"permit_epoch":7,"queue_epoch":1,"queue_number":1002,"family":2,"hook":1,"owned_ifindex":8,"owner":"vpn9506t1","stn":"st9506.1","outcome":"written","bytes_written":84},{"request_id":4,"permit_epoch":7,"queue_epoch":1,"queue_number":1003,"family":2,"hook":2,"owned_ifindex":8,"owner":"vpn9506t1","stn":"st9506.1","outcome":"refused","bytes_written":0}]}}
EOF
    python3 - "$parser_dir/witness.json" <<'PY'
import json
import sys
path = sys.argv[1]
value = json.load(open(path, encoding="utf-8"))
value["s5_reinject"]["completed_written"] = 3
value["s5_reinject"]["reinjected"] = 3
with open(path, "w", encoding="utf-8") as fh:
    json.dump(value, fh)
PY
    cat >"$parser_dir/witness.prom" <<'EOF'
xpf_ipsec_capture_actor_active{run_id="run-1",generation="4",permit_epoch="7"} 1
xpf_ipsec_capture_consumed_total{run_id="run-1",generation="4",permit_epoch="7"} 4
xpf_ipsec_capture_adjudicated_total{run_id="run-1",generation="4",permit_epoch="7"} 4
xpf_ipsec_capture_reinjected_total{run_id="run-1",generation="4",permit_epoch="7"} 3
xpf_ipsec_capture_written_total{run_id="run-1",generation="4",permit_epoch="7"} 3
xpf_ipsec_capture_uncertain_total{run_id="run-1",generation="4",permit_epoch="7"} 0
xpf_ipsec_capture_late_completions_total{run_id="run-1",generation="4",permit_epoch="7"} 0
xpf_ipsec_capture_timeouts_total{run_id="run-1",generation="4",permit_epoch="7"} 0
xpf_ipsec_capture_stale_total{run_id="run-1",generation="4",permit_epoch="7"} 0
xpf_ipsec_capture_cancelled_total{run_id="run-1",generation="4",permit_epoch="7"} 0
xpf_ipsec_capture_refused_total{run_id="run-1",generation="4",permit_epoch="7"} 1
xpf_ipsec_capture_delivered_available{run_id="run-1",generation="4",permit_epoch="7"} 0
EOF
    python3 - "$parser_dir/witness.prom" "$parser_dir/witness-zero.prom" <<'PY'
import sys
source, target = sys.argv[1:]
lines = open(source, encoding="utf-8").read().splitlines()
for index, line in enumerate(lines):
    if line.startswith("xpf_ipsec_capture_") and "_total{" in line:
        lines[index] = line.rsplit(" ", 1)[0] + " 0"
with open(target, "w", encoding="utf-8") as fh:
    fh.write("\n".join(lines) + "\n")
PY
    python3 - "$parser_dir/witness.prom" "$parser_dir/witness-alias.prom" <<'PY'
import sys
source, target = sys.argv[1:]
values = {
    "xpf_ipsec_capture_reinjected_total": "1",
    "xpf_ipsec_capture_written_total": "1",
    "xpf_ipsec_capture_uncertain_total": "2",
}
lines = []
for line in open(source, encoding="utf-8"):
    name = line.split("{", 1)[0]
    if name in values:
        line = line.rsplit(" ", 1)[0] + " " + values[name] + "\n"
    lines.append(line)
with open(target, "w", encoding="utf-8") as fh:
    fh.writelines(lines)
PY
    printf '%s\n' \
        'xpf_ipsec_capture_delivered_available{run_id="run-1",generation="4",permit_epoch="7"} 1' \
        'xpf_ipsec_capture_delivered_total{run_id="run-1",generation="4",permit_epoch="7"} 11' \
        >"$parser_dir/witness-delivered.prom"
    printf '%s\n' \
        'xpf_ipsec_capture_delivered_available{run_id="run-1",generation="4",permit_epoch="7"} 1' \
        >"$parser_dir/witness-delivered-missing-count.prom"
    printf '%s\n' \
        'xpf_ipsec_capture_delivered_available{run_id="run-1",generation="4",permit_epoch="7"} 0' \
        'xpf_ipsec_capture_delivered_total{run_id="run-1",generation="4",permit_epoch="7"} 11' \
        >"$parser_dir/witness-delivered-count-while-unavailable.prom"
    printf '%s\n' 'xpf_ipsec_capture_consumed_total{run_id="run-other",generation="4",permit_epoch="7"} 0' >"$parser_dir/witness-mismatch.prom"
    expect "absent S5 status stays unavailable" "0" \
        "$(python3 "$parser_dir/witness-check.py" "$parser_dir/absent.json" "$parser_dir/witness.prom" absent)"
    expect "present zero counter stays authoritative zero" "1" \
        "$(python3 "$parser_dir/witness-check.py" "$parser_dir/witness.json" "$parser_dir/witness-zero.prom" zero)"
    expect "join mismatch stays unavailable" "0" \
        "$(python3 "$parser_dir/witness-check.py" "$parser_dir/witness.json" "$parser_dir/witness-mismatch.prom" join)"
    expect "Go availability zero requires omitted delivered count" "1" \
        "$(python3 "$parser_dir/witness-check.py" "$parser_dir/witness.json" "$parser_dir/witness.prom" delivery)"
    expect "Go availability one joins delivered count" "1" \
        "$(python3 "$parser_dir/witness-check.py" "$parser_dir/witness.json" "$parser_dir/witness-delivered.prom" delivery-positive)"
    expect "Go availability one without count stays unavailable" "1" \
        "$(python3 "$parser_dir/witness-check.py" "$parser_dir/witness.json" "$parser_dir/witness-delivered-missing-count.prom" delivery-missing-count)"
    expect "Go unavailable gauge rejects present count" "1" \
        "$(python3 "$parser_dir/witness-check.py" "$parser_dir/witness.json" "$parser_dir/witness-delivered-count-while-unavailable.prom" delivery-count-while-unavailable)"
    expect "bounded provenance exposes refusal outcome" "1" \
        "$(python3 "$parser_dir/witness-check.py" "$parser_dir/witness.json" "$parser_dir/witness.prom" refusal)"
    expect "joined disposition counters are observed" "1" \
        "$(python3 "$parser_dir/witness-check.py" "$parser_dir/witness.json" "$parser_dir/witness.prom" dispositions)"
    cat >"$parser_dir/positive.json" <<'EOF'
{"nftables":[
{"table":{"family":"inet","name":"xpf_transit_barrier"}},
{"table":{"family":"bridge","name":"xpf_transit_barrier"}},
{"table":{"family":"inet","name":"xpf_ipsec_divert"}},
{"table":{"family":"bridge","name":"xpf_ipsec_divert"}},
{"chain":{"family":"inet","table":"xpf_transit_barrier","name":"forward","hook":"forward","prio":0,"policy":"drop"}},
{"chain":{"family":"bridge","table":"xpf_transit_barrier","name":"forward","hook":"forward","prio":0,"policy":"drop"}},
{"chain":{"family":"inet","table":"xpf_ipsec_divert","name":"forward","hook":"forward","prio":-175,"policy":"accept"}},
{"chain":{"family":"inet","table":"xpf_ipsec_divert","name":"input","hook":"input","prio":-175,"policy":"accept"}},
{"chain":{"family":"bridge","table":"xpf_ipsec_divert","name":"forward","hook":"forward","prio":-175,"policy":"accept"}},
{"chain":{"family":"bridge","table":"xpf_ipsec_divert","name":"input","hook":"input","prio":-175,"policy":"accept"}}
]}
EOF
    cat >"$parser_dir/provenance-rules.json" <<'EOF'
{"nftables":[
{"rule":{"family":"inet","table":"xpf_ipsec_divert","chain":"forward","expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"st9506.0"}},{"queue":{"num":1000}}]}},
{"rule":{"family":"inet","table":"xpf_ipsec_divert","chain":"input","expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"st9506.0"}},{"queue":{"num":1001}}]}},
{"rule":{"family":"bridge","table":"xpf_ipsec_divert","chain":"forward","expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"st9506.1"}},{"queue":{"num":1002}}]}},
{"rule":{"family":"bridge","table":"xpf_ipsec_divert","chain":"input","expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"st9506.1"}},{"queue":{"num":1003}}]}}
]}
EOF
    printf '%s\n' \
        '1000 0 0 0 0 0' '1001 0 0 0 0 0' \
        '1002 0 0 0 0 0' '1003 0 0 0 0 0' \
        >"$parser_dir/provenance-nfqueue.txt"
    printf '%s\n' '7: st9506.0@NONE:' '8: st9506.1@NONE:' \
        >"$parser_dir/provenance-st-links.txt"
    python3 - "$parser_dir/witness.json" "$parser_dir/zero-status.json" \
        "$parser_dir/no-rows-status.json" "$parser_dir/poison-status.json" \
        "$parser_dir/malformed-status.json" "$parser_dir/mixed-status.json" \
        "$parser_dir/bool-status.json" "$parser_dir/alias-status.json" <<'PY'
import copy
import json
import sys
base = json.load(open(sys.argv[1], encoding="utf-8"))
zero = copy.deepcopy(base)
del zero["s5_reinject"]["provenance"]
no_rows = copy.deepcopy(base)
no_rows["s5_reinject"]["provenance"] = []
poison = copy.deepcopy(base)
poison["s5_reinject"]["provenance"][0]["family"] = 2
poison["s5_reinject"]["provenance"][0]["owner"] = "poison"
malformed = copy.deepcopy(base)
malformed["s5_reinject"]["provenance"] = {"poison": True}
mixed = copy.deepcopy(base)
mixed["s5_reinject"]["provenance"][0]["permit_epoch"] = 6
mixed["s5_reinject"]["provenance"].append(
    copy.deepcopy(base["s5_reinject"]["provenance"][0])
)
mixed["s5_reinject"]["completed_written"] = 99
mixed["s5_reinject"]["reinjected"] = 99
bool_status = copy.deepcopy(base)
bool_status["s5_reinject"]["provenance"][0]["family"] = True
bool_status["s5_reinject"]["provenance"][1]["hook"] = True
alias_status = copy.deepcopy(base)
alias_status["s5_reinject"]["provenance"][0]["outcome"] = "accepted"
alias_status["s5_reinject"]["provenance"][1]["outcome"] = "would_reinject"
alias_status["s5_reinject"]["provenance"][2]["outcome"] = "written"
alias_status["s5_reinject"]["provenance"][3]["outcome"] = "refused"
for path, value in zip(sys.argv[2:], (
    zero, no_rows, poison, malformed, mixed, bool_status, alias_status
)):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(value, fh)
PY
    python3 - "$parser_dir/provenance-rules.json" \
        "$parser_dir/poison-rules.json" "$parser_dir/unknown-rules.json" <<'PY'
import copy
import json
import sys
rules = json.load(open(sys.argv[1], encoding="utf-8"))
poison = copy.deepcopy(rules)
poison["nftables"][0]["rule"]["expr"][0]["match"]["op"] = "!="
unknown = copy.deepcopy(rules)
unknown["nftables"][0]["rule"]["chain"] = "bogus"
with open(sys.argv[2], "w", encoding="utf-8") as fh:
    json.dump(poison, fh)
with open(sys.argv[3], "w", encoding="utf-8") as fh:
    json.dump(unknown, fh)
PY
    sed 's/run-1/run-other/g' "$parser_dir/witness.prom" \
        >"$parser_dir/join-mismatch.prom"
    printf '%s\n' '{"nftables":[{"table":{"family":"inet","name":"xpf_transit_barrier"}}]}' \
        >"$parser_dir/missing-bridge.json"
    printf '%s\n' '{}' >"$parser_dir/missing-list.json"
    printf '%s\n' '42' >"$parser_dir/scalar.json"
    printf '%s\n' '{not-json' >"$parser_dir/malformed.json"
    printf '%s\n' '{"nftables":[]}' >"$parser_dir/empty-list.json"
    printf '%s\n' '[]' >"$parser_dir/list-root.json"
    expect "ruleset parser accepts exact four-hook fixture" "1 1 1 1 1 1" \
        "$(ruleset_flags "$parser_dir/positive.json")"
    expect "ruleset parser rejects missing bridge family" "1 0 0 0 0 1" \
        "$(ruleset_flags "$parser_dir/missing-bridge.json")"
    expect "ruleset parser rejects missing nftables list" "0 0 0 0 0 0" \
        "$(ruleset_flags "$parser_dir/missing-list.json")"
    expect "ruleset parser rejects true scalar JSON" "0 0 0 0 0 0" \
        "$(ruleset_flags "$parser_dir/scalar.json")"
    expect "ruleset parser rejects list-root JSON" "0 0 0 0 0 0" \
        "$(ruleset_flags "$parser_dir/list-root.json")"
    expect "ruleset parser rejects malformed JSON" "0 0 0 0 0 0" \
        "$(ruleset_flags "$parser_dir/malformed.json")"
    expect "ruleset parser accepts empty nftables list as readable" "0 0 0 0 0 1" \
        "$(ruleset_flags "$parser_dir/empty-list.json")"
    printf '%s\n' '1094 0 0 0 0 0' >"$parser_dir/nfqueue.txt"
    expect "observer ruleset parser reports structural-only positive" "1 0 0 1 0" \
        "$(observe_ruleset_shape "$parser_dir/positive.json")"
    PROV_OBS="$(observe_provenance_metadata \
        "$parser_dir/provenance-rules.json" "$parser_dir/provenance-nfqueue.txt" \
        "$parser_dir/witness.json" "$parser_dir/witness.prom" \
        "$parser_dir/provenance-st-links.txt")"
    expect "exact observer joins Rust rows to Go counters" "joined" \
        "$(observer_field "$PROV_OBS" join)"
    expect "exact observer sees four packet samples" "4" \
        "$(observer_field "$PROV_OBS" packet_samples)"
    expect "four ruleset provenance classes are parsed" "4" \
        "$(observer_field "$PROV_OBS" provenance_classes)"
    expect "inet PF-family rule count is exact" "2" \
        "$(observer_field "$PROV_OBS" pf_inet)"
    expect "bridge PF-family rule count is exact" "2" \
        "$(observer_field "$PROV_OBS" pf_bridge)"
    expect "inet forward packet class row binds exactly" "1" \
        "$(observer_field "$PROV_OBS" rows_inet_forward)"
    expect "inet input packet class is parsed" "1" \
        "$(observer_field "$PROV_OBS" rows_inet_input)"
    expect "bridge forward packet class is parsed" "1" \
        "$(observer_field "$PROV_OBS" rows_bridge_forward)"
    expect "bridge input packet class is parsed" "1" \
        "$(observer_field "$PROV_OBS" rows_bridge_input)"
    expect "packet provenance has no rule mismatch" "0" \
        "$(observer_field "$PROV_OBS" prov_mismatch)"
    expect "packet PF-family has no mismatch" "0" \
        "$(observer_field "$PROV_OBS" pf_mismatch)"
    expect "Rust and Go written counters agree" "0" \
        "$(observer_field "$PROV_OBS" counter_mismatch)"
    MIXED_OBS="$(observe_provenance_metadata \
        "$parser_dir/provenance-rules.json" "$parser_dir/provenance-nfqueue.txt" \
        "$parser_dir/mixed-status.json" "$parser_dir/witness.prom" \
        "$parser_dir/provenance-st-links.txt")"
    expect "mixed epochs retain current packet rows only" "4" \
        "$(observer_field "$MIXED_OBS" packet_samples)"
    expect "mixed epochs expose stale row count" "1" \
        "$(observer_field "$MIXED_OBS" stale_samples)"
    expect "mixed epochs preserve counter agreement" "0" \
        "$(observer_field "$MIXED_OBS" counter_mismatch)"
    RULE_POISON_OBS="$(observe_provenance_metadata \
        "$parser_dir/poison-rules.json" "$parser_dir/provenance-nfqueue.txt" \
        "$parser_dir/witness.json" "$parser_dir/witness.prom" \
        "$parser_dir/provenance-st-links.txt")"
    UNKNOWN_RULE_OBS="$(observe_provenance_metadata \
        "$parser_dir/unknown-rules.json" "$parser_dir/provenance-nfqueue.txt" \
        "$parser_dir/witness.json" "$parser_dir/witness.prom" \
        "$parser_dir/provenance-st-links.txt")"
    expect "poisoned operator and unknown class disable static map" "0 0" \
        "$(printf '%s %s' "$(observer_field "$RULE_POISON_OBS" static)" \
            "$(observer_field "$UNKNOWN_RULE_OBS" static)")"
    BOOL_OBS="$(observe_provenance_metadata \
        "$parser_dir/provenance-rules.json" "$parser_dir/provenance-nfqueue.txt" \
        "$parser_dir/bool-status.json" "$parser_dir/witness.prom" \
        "$parser_dir/provenance-st-links.txt")"
    expect "boolean family and hook metadata is rejected" "2" \
        "$(observer_field "$BOOL_OBS" prov_mismatch)"
    ALIAS_OBS="$(observe_provenance_metadata \
        "$parser_dir/provenance-rules.json" "$parser_dir/provenance-nfqueue.txt" \
        "$parser_dir/alias-status.json" "$parser_dir/witness-alias.prom" \
        "$parser_dir/provenance-st-links.txt")"
    expect "accepted and would_reinject map to uncertain" "0 2" \
        "$(printf '%s %s' "$(observer_field "$ALIAS_OBS" counter_mismatch)" \
            "$(observer_field "$ALIAS_OBS" rust_uncertain)")"
    ABSENT_OBS="$(observe_provenance_metadata \
        "$parser_dir/provenance-rules.json" "$parser_dir/provenance-nfqueue.txt" \
        "$parser_dir/absent.json" "$parser_dir/witness.prom" \
        "$parser_dir/provenance-st-links.txt")"
    expect "absent Rust status stays unavailable" "unavailable" \
        "$(observer_field "$ABSENT_OBS" packet_samples)"
    expect "absent Rust status does not fabricate join" "unavailable" \
        "$(observer_field "$ABSENT_OBS" join)"
    OMITTED_OBS="$(observe_provenance_metadata \
        "$parser_dir/provenance-rules.json" "$parser_dir/provenance-nfqueue.txt" \
        "$parser_dir/zero-status.json" "$parser_dir/witness-zero.prom" \
        "$parser_dir/provenance-st-links.txt")"
    expect "omitted provenance vector is authoritative zero" "0" \
        "$(observer_field "$OMITTED_OBS" packet_samples)"
    expect "omitted provenance vector remains joined with zero counters" "joined 0" \
        "$(printf '%s %s' "$(observer_field "$OMITTED_OBS" join)" \
            "$(observer_field "$OMITTED_OBS" counter_mismatch)")"
    PRESENT_EMPTY_OBS="$(observe_provenance_metadata \
        "$parser_dir/provenance-rules.json" "$parser_dir/provenance-nfqueue.txt" \
        "$parser_dir/no-rows-status.json" "$parser_dir/witness-zero.prom" \
        "$parser_dir/provenance-st-links.txt")"
    expect "present empty provenance is authoritative zero" "0" \
        "$(observer_field "$PRESENT_EMPTY_OBS" packet_samples)"
    expect "present empty provenance remains joined with zero counters" "joined 0" \
        "$(printf '%s %s' "$(observer_field "$PRESENT_EMPTY_OBS" join)" \
            "$(observer_field "$PRESENT_EMPTY_OBS" counter_mismatch)")"
    NFQ_MISSING_OBS="$(observe_provenance_metadata \
        "$parser_dir/provenance-rules.json" \
        "$parser_dir/no-such-nfqueue.txt" "$parser_dir/witness.json" \
        "$parser_dir/witness.prom" "$parser_dir/provenance-st-links.txt")"
    expect "missing nfqueue surface stays unavailable" "unavailable" \
        "$(observer_field "$NFQ_MISSING_OBS" queue_rows)"
    expect "missing nfqueue mismatch stays unavailable" "unavailable" \
        "$(observer_field "$NFQ_MISSING_OBS" mismatch)"
    STLINK_MISSING_OBS="$(observe_provenance_metadata \
        "$parser_dir/provenance-rules.json" "$parser_dir/provenance-nfqueue.txt" \
        "$parser_dir/witness.json" "$parser_dir/witness.prom" \
        "$parser_dir/no-such-st-links.txt")"
    expect "missing st-links surface stays packet-unavailable" "unavailable" \
        "$(observer_field "$STLINK_MISSING_OBS" packet_samples)"
    expect "missing st-links reason is explicit" "st-links-surface-absent" \
        "$(observer_field "$STLINK_MISSING_OBS" join_reason)"
    POISON_OBS="$(observe_provenance_metadata \
        "$parser_dir/provenance-rules.json" "$parser_dir/provenance-nfqueue.txt" \
        "$parser_dir/poison-status.json" "$parser_dir/witness.prom" \
        "$parser_dir/provenance-st-links.txt")"
    expect "poison family/owner metadata is rejected" "1" \
        "$(observer_field "$POISON_OBS" prov_mismatch)"
    expect "poison PF family is rejected" "1" \
        "$(observer_field "$POISON_OBS" pf_mismatch)"
    MISMATCH_OBS="$(observe_provenance_metadata \
        "$parser_dir/provenance-rules.json" "$parser_dir/provenance-nfqueue.txt" \
        "$parser_dir/witness.json" "$parser_dir/join-mismatch.prom" \
        "$parser_dir/provenance-st-links.txt")"
    expect "join-key mismatch stays packet-unavailable" "unavailable" \
        "$(observer_field "$MISMATCH_OBS" packet_samples)"
    expect "join-key mismatch is named" "go-rust-join-key-mismatch" \
        "$(observer_field "$MISMATCH_OBS" join_reason)"
    MALFORMED_OBS="$(observe_provenance_metadata \
        "$parser_dir/provenance-rules.json" "$parser_dir/provenance-nfqueue.txt" \
        "$parser_dir/malformed-status.json" "$parser_dir/witness.prom" \
        "$parser_dir/provenance-st-links.txt")"
    expect "malformed provenance stays unavailable" "unavailable" \
        "$(observer_field "$MALFORMED_OBS" packet_samples)"
    rm -rf "$parser_dir"
    if [[ "$fail" == 0 && "$pass" == 63 ]]; then
        echo "t12-g2-9506 selftest: $pass passed, $fail failed"
        exit 0
    fi
    echo "t12-g2-9506 selftest: $pass passed, $fail failed" >&2
    exit 1
fi

# A live cell must be invoked through with-cluster.sh.  This guard prevents a
# caller from accidentally running a destructive/readback probe outside the
# shared-cluster lock protocol.
if [[ -z "${XPF_CLUSTER_LOCK_HELD:-}" ]]; then
    echo "VOID reason=env-void missing with-cluster lock (run through test/incus/with-cluster.sh)" >&2
    exit 2
fi

# shellcheck source=test/incus/loss-userspace-cluster.env
source "${SCRIPT_DIR}/loss-userspace-cluster.env"
# shellcheck source=test/incus/cluster-build-identity.sh
source "${SCRIPT_DIR}/cluster-build-identity.sh"
# shellcheck source=test/incus/harness-result.sh
source "${SCRIPT_DIR}/harness-result.sh"

ENV_NAME="${HARNESS_ENV:-loss-userspace-cluster}"
# shellcheck source=test/incus/deploy-lib.sh
source "${SCRIPT_DIR}/deploy-lib.sh"
# shellcheck source=test/incus/ipsec-9506-fixture.sh
source "${SCRIPT_DIR}/ipsec-9506-fixture.sh"
NODE0="${FW0:-${INCUS_REMOTE:-loss}:xpf-userspace-fw0}"
NODE1="${FW1:-${INCUS_REMOTE:-loss}:xpf-userspace-fw1}"
ARCHIVE_DIR="${XPF_9506_T12_G2_ARCHIVE_DIR:-${TMPDIR:-/var/tmp}/xpf-t12-g2-9506-$(date +%s)}"
mkdir -p "$ARCHIVE_DIR" || {
    echo "cannot create archive directory: $ARCHIVE_DIR" >&2
    exit 2
}

# Incus is normally group-gated on the workstation.  Keep all remote commands
# stdin-independent so a two-node attestation cannot silently sample only fw0.
remote() {
    local node="$1" command="$2"
    sg incus-admin -c "incus exec -n $(printf '%q' "$node") -- bash -lc $(printf '%q' "$command")"
}


fixture_measure_traffic() {
    # fixture_measure_traffic <shape> <count> <dir>: exercise both decrypted
    # directions on one even (RG1/node0) and one odd (RG2/node1) tunnel.
    # The per-node XFRM deltas are the only offered proof; aggregate counters
    # are retained for compatibility with the existing ledger fields.
    local shape="$1" count="$2" dir="$3" family inner peer_out lan_out lan6 index
    local fw0_before="$dir/xfrm-fw0-before.txt" fw1_before="$dir/xfrm-fw1-before.txt"
    local fw0_after="$dir/xfrm-fw0-after.txt" fw1_after="$dir/xfrm-fw1-after.txt"
    local fw0_before_packets fw0_after_packets fw1_before_packets fw1_after_packets
    local lan_success peer_success ix0_window ix0_start ix0_end
    ix0_window="$dir/ix0-window.txt"
    ix0_start=""
    ix0_end=""
    printf 'probe_index=0 if_id_fw0=0x25220001 owner_fw0=node0 if_id_fw1=0x25220002 owner_fw1=node1\n' >"$ix0_window"
    family="$(fix9506_shape_family "$shape")"
    lan_out="$dir/lan-to-peer.txt"
    peer_out="$dir/peer-to-lan.txt"
    : >"$lan_out"
    : >"$peer_out"
    fix9506_remote "$FIX9506_NODE0" 'ip -s xfrm state' >"$fw0_before" 2>&1 || :
    fix9506_remote "$FIX9506_NODE1" 'ip -s xfrm state' >"$fw1_before" 2>&1 || :
    if [[ "$family" == v6 ]]; then
        lan6="$(fix9506_remote "$FIX9506_LAN_REF" 'ip -6 -o addr show scope global | sed -n "1{s/.*inet6 \([^/ ]*\)\/.*/\1/p;}"' 2>/dev/null || true)"
    fi
    while IFS= read -r index; do
        if [[ "$index" == 0 ]]; then
            ix0_start="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
        fi
        if [[ "$family" == v4 ]]; then
            inner="$(fix9506_inner4_ip "$index")"
            printf 'probe_index=%s\n' "$index" >>"$lan_out"
            fix9506_remote "$FIX9506_LAN_REF" "ip -4 route get $inner; ping -c 4 -W 2 $inner" >>"$lan_out" 2>&1 || :
            printf 'probe_index=%s\n' "$index" >>"$peer_out"
            fix9506_remote "$FIX9506_PEER_REF" "ping -c 4 -W 2 -I $inner $LAN_HOST_IP" >>"$peer_out" 2>&1 || :
        else
            inner="$(fix9506_inner6_ip "$index")"
            printf 'probe_index=%s\n' "$index" >>"$lan_out"
            fix9506_remote "$FIX9506_LAN_REF" "ip -6 route get $inner; ping -6 -c 4 -W 2 $inner" >>"$lan_out" 2>&1 || :
            printf 'probe_index=%s\n' "$index" >>"$peer_out"
            fix9506_remote "$FIX9506_PEER_REF" "ping -6 -c 4 -W 2 -I $inner ${lan6:-$LAN_VIP6}" >>"$peer_out" 2>&1 || :
        fi
        if [[ "$index" == 0 ]]; then
            ix0_end="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
        fi
    done < <(fixture_probe_indices)
    printf 'ix0_window_start=%s\nix0_window_end=%s\n' "$ix0_start" "$ix0_end" >>"$ix0_window"
    fix9506_remote "$FIX9506_NODE0" 'ip -s xfrm state' >"$fw0_after" 2>&1 || :
    fix9506_remote "$FIX9506_NODE1" 'ip -s xfrm state' >"$fw1_after" 2>&1 || :
    # Index 0 is the even/RG1 tunnel owned by fw0; index 1 is the
    # odd/RG2 tunnel owned by fw1.  Select by if_id so unrelated fixture
    # tunnels and standing XFRM state cannot become offered evidence.
    fw0_before_packets="$(fix9506_count_xfrm_packets_ifid "$fw0_before" 0x25220001)"
    fw0_after_packets="$(fix9506_count_xfrm_packets_ifid "$fw0_after" 0x25220001)"
    fw1_before_packets="$(fix9506_count_xfrm_packets_ifid "$fw1_before" 0x25220002)"
    fw1_after_packets="$(fix9506_count_xfrm_packets_ifid "$fw1_after" 0x25220002)"
    MEASURE_XFRM_FW0_PACKETS=$((fw0_after_packets - fw0_before_packets))
    MEASURE_XFRM_FW1_PACKETS=$((fw1_after_packets - fw1_before_packets))
    ((MEASURE_XFRM_FW0_PACKETS < 0)) && MEASURE_XFRM_FW0_PACKETS=0
    ((MEASURE_XFRM_FW1_PACKETS < 0)) && MEASURE_XFRM_FW1_PACKETS=0
    MEASURE_OFFERED_FW0="$MEASURE_XFRM_FW0_PACKETS"
    MEASURE_OFFERED_FW1="$MEASURE_XFRM_FW1_PACKETS"
    MEASURE_XFRM_TUNNEL0_PACKETS=$((MEASURE_OFFERED_FW0 + MEASURE_OFFERED_FW1))
    lan_success="$(grep -cE '(^|[[:space:],])0% packet loss' "$lan_out" 2>/dev/null || true)"
    peer_success="$(grep -cE '(^|[[:space:],])0% packet loss' "$peer_out" 2>/dev/null || true)"
    local lan_ok=0 peer_ok=0
    ((lan_success == 2)) && lan_ok=1
    ((peer_success == 2)) && peer_ok=1
    MEASURE_LAN_OK="$lan_ok"
    MEASURE_PEER_OK="$peer_ok"
    MEASURE_PACKETS=$(((lan_success + peer_success) * 4))
    MEASURE_LOSS=0
    ((lan_success == 2 && peer_success == 2)) || MEASURE_LOSS=100

}
run_fixture_measure() {
    # Populate MEASURE_* globals. Setup/teardown failures are never promoted
    # into PASS; all raw probes stay in the per-shape archive directory.
    local shape="$1" count="$2" label="$3"
    local dir="$ARCHIVE_DIR/fixture-${label}-${shape}-${count}"
    mkdir -p "$dir"
    MEASURE_REASON=""
    MEASURE_READY=0
    MEASURE_TEARDOWN=0
    MEASURE_QUEUE_TOTAL=0
    MEASURE_QUEUE_TOTAL_NODE1=0
    MEASURE_QUEUE_EXPECT=$((count * 4))
    MEASURE_QUEUE_CLASSES="0 0 0 0 0"
    MEASURE_QUEUE_CLASSES_NODE1="0 0 0 0 0"
    MEASURE_QUEUE_BOTH=0
    MEASURE_PACKETS=0
    MEASURE_XFRM_TUNNEL0_PACKETS=0
    MEASURE_XFRM_FW0_PACKETS=0
    MEASURE_XFRM_FW1_PACKETS=0
    MEASURE_OFFERED_FW0=0
    MEASURE_OFFERED_FW1=0
    MEASURE_LOSS=100
    MEASURE_RUNTIME_FW0=""
    MEASURE_RUNTIME_FW1=""
    MEASURE_S5_FW0=0
    MEASURE_S5_FW1=0
    MEASURE_CONSUMED_FW0=0
    MEASURE_CONSUMED_FW1=0
    MEASURE_ADJUDICATED_FW0=0
    MEASURE_ADJUDICATED_FW1=0
    MEASURE_REINJECTED_FW0=0
    MEASURE_REINJECTED_FW1=0
    MEASURE_WRITTEN_FW0=0
    MEASURE_WRITTEN_FW1=0
    MEASURE_UNCERTAIN_FW0=0
    MEASURE_UNCERTAIN_FW1=0
    MEASURE_LATE_COMPLETIONS_FW0=0
    MEASURE_LATE_COMPLETIONS_FW1=0
    MEASURE_TIMEOUTS_FW0=0
    MEASURE_TIMEOUTS_FW1=0
    MEASURE_STALE_FW0=0
    MEASURE_STALE_FW1=0
    MEASURE_CANCELLED_FW0=0
    MEASURE_CANCELLED_FW1=0
    MEASURE_REFUSED_FW0=0
    MEASURE_REFUSED_FW1=0
    MEASURE_DELIVERED_AVAILABLE_FW0=0
    MEASURE_DELIVERED_AVAILABLE_FW1=0
    MEASURE_DELIVERED_FW0=0
    MEASURE_DELIVERED_FW1=0
    MEASURE_REASON_FW0=product-observer-unavailable:s5-status-or-go-metrics-absent
    MEASURE_REASON_FW1=product-observer-unavailable:s5-status-or-go-metrics-absent
    MEASURE_PROVENANCE_FW0="static=0 queue_rows=0 queue_ids=0 packet_samples=unavailable mismatch=0 join=unavailable join_reason=inputs-absent"
    MEASURE_PROVENANCE_FW1="$MEASURE_PROVENANCE_FW0"
    MEASURE_QUEUE_ECON_FW0="queue_instances=0 recv_buffers_mib=unknown socket_buffers_mib=unknown fd_count=0 queue_pending=0 queue_drops=0 rotation_overlap=unknown teardown=unknown"
    MEASURE_QUEUE_ECON_FW1="$MEASURE_QUEUE_ECON_FW0"
    if [[ "$FIXTURE_PHASE_BLOCKED" == 1 || "$ACTIVE_FIXTURE_SETUP" == 1 ]]; then
        MEASURE_REASON="fixture-lifecycle-blocked:previous fixture was not restored"
        return 1
    fi
    ACTIVE_FIXTURE_SETUP=1
    ACTIVE_FIXTURE_COUNT="$count"
    ACTIVE_FIXTURE_DIR="$dir"
    if ! fix9506_setup "$shape" "$count" "$dir"; then
        MEASURE_REASON="fixture-setup-failed:${shape}x${count} (inspect ${dir}; no live-SA verdict)"
        if fix9506_teardown "$count" "$dir"; then
            ACTIVE_FIXTURE_SETUP=0
            ACTIVE_FIXTURE_COUNT=0
            ACTIVE_FIXTURE_DIR=""
        else
            FIXTURE_PHASE_BLOCKED=1
        fi
        return 1
    fi
    MEASURE_READY=1
    fix9506_probe_node "$FIX9506_NODE0" "$dir" measure-fw0
    fix9506_probe_node "$FIX9506_NODE1" "$dir" measure-fw1
    observe_runtime "$FIX9506_NODE0" "$dir" measure-fw0
    MEASURE_RUNTIME_FW0="$RUNTIME_PROC_FILE"
    observe_runtime "$FIX9506_NODE1" "$dir" measure-fw1
    MEASURE_RUNTIME_FW1="$RUNTIME_PROC_FILE"
    observe_chain_overhead "$FIX9506_NODE0" "$dir" measure-fw0
    observe_chain_overhead "$FIX9506_NODE1" "$dir" measure-fw1
    MEASURE_PROVENANCE_FW0="$(observe_provenance_metadata "$dir/measure-fw0-ruleset.json" "$dir/measure-fw0-nfqueue.txt")"
    MEASURE_PROVENANCE_FW1="$(observe_provenance_metadata "$dir/measure-fw1-ruleset.json" "$dir/measure-fw1-nfqueue.txt")"
    MEASURE_QUEUE_ECON_FW0="$(observe_queue_economics "$dir/measure-fw0-ruleset.json" "$MEASURE_RUNTIME_FW0" "$dir/measure-fw0-nfqueue.txt")"
    MEASURE_QUEUE_ECON_FW1="$(observe_queue_economics "$dir/measure-fw1-ruleset.json" "$MEASURE_RUNTIME_FW1" "$dir/measure-fw1-nfqueue.txt")"
    MEASURE_QUEUE_CLASSES="$(fix9506_divert_queues "$dir/measure-fw0-ruleset.json")"
    MEASURE_QUEUE_CLASSES_NODE1="$(fix9506_divert_queues "$dir/measure-fw1-ruleset.json")"
    read -r _ _ _ _ MEASURE_QUEUE_TOTAL <<<"$MEASURE_QUEUE_CLASSES"
    read -r _ _ _ _ MEASURE_QUEUE_TOTAL_NODE1 <<<"$MEASURE_QUEUE_CLASSES_NODE1"
    if [[ "$MEASURE_QUEUE_TOTAL" == "$MEASURE_QUEUE_EXPECT" &&
          "$MEASURE_QUEUE_TOTAL_NODE1" == "$MEASURE_QUEUE_EXPECT" ]]; then
        MEASURE_QUEUE_BOTH=1
    fi
    fixture_measure_traffic "$shape" "$count" "$dir"
    observe_runtime "$FIX9506_NODE0" "$dir" measure-fw0-post
    MEASURE_S5_FW0="$RUNTIME_S5_AVAILABLE"
    MEASURE_CONSUMED_FW0="$RUNTIME_CONSUMED"
    MEASURE_ADJUDICATED_FW0="$RUNTIME_ADJUDICATED"
    MEASURE_REINJECTED_FW0="$RUNTIME_REINJECTED"
    MEASURE_WRITTEN_FW0="$RUNTIME_WRITTEN"
    MEASURE_UNCERTAIN_FW0="$RUNTIME_UNCERTAIN"
    MEASURE_LATE_COMPLETIONS_FW0="$RUNTIME_LATE_COMPLETIONS"
    MEASURE_TIMEOUTS_FW0="$RUNTIME_TIMEOUTS"
    MEASURE_STALE_FW0="$RUNTIME_STALE"
    MEASURE_CANCELLED_FW0="$RUNTIME_CANCELLED"
    MEASURE_REFUSED_FW0="$RUNTIME_REFUSED"
    MEASURE_DELIVERED_AVAILABLE_FW0="$RUNTIME_DELIVERED_AVAILABLE"
    MEASURE_DELIVERED_FW0="$RUNTIME_DELIVERED"
    MEASURE_REASON_FW0="$RUNTIME_REASON"
    observe_runtime "$FIX9506_NODE1" "$dir" measure-fw1-post
    MEASURE_S5_FW1="$RUNTIME_S5_AVAILABLE"
    MEASURE_CONSUMED_FW1="$RUNTIME_CONSUMED"
    MEASURE_ADJUDICATED_FW1="$RUNTIME_ADJUDICATED"
    MEASURE_REINJECTED_FW1="$RUNTIME_REINJECTED"
    MEASURE_WRITTEN_FW1="$RUNTIME_WRITTEN"
    MEASURE_UNCERTAIN_FW1="$RUNTIME_UNCERTAIN"
    MEASURE_LATE_COMPLETIONS_FW1="$RUNTIME_LATE_COMPLETIONS"
    MEASURE_TIMEOUTS_FW1="$RUNTIME_TIMEOUTS"
    MEASURE_STALE_FW1="$RUNTIME_STALE"
    MEASURE_CANCELLED_FW1="$RUNTIME_CANCELLED"
    MEASURE_REFUSED_FW1="$RUNTIME_REFUSED"
    MEASURE_DELIVERED_AVAILABLE_FW1="$RUNTIME_DELIVERED_AVAILABLE"
    MEASURE_DELIVERED_FW1="$RUNTIME_DELIVERED"
    MEASURE_REASON_FW1="$RUNTIME_REASON"
    observe_chain_overhead "$FIX9506_NODE0" "$dir" measure-fw0-post
    observe_chain_overhead "$FIX9506_NODE1" "$dir" measure-fw1-post
    # The pre-traffic read proves only static shape. Re-read after traffic so
    # bounded Rust rows and Go counters are joined for the exact workload.
    MEASURE_PROVENANCE_FW0="$(observe_provenance_metadata \
        "$dir/measure-fw0-ruleset.json" "$dir/measure-fw0-nfqueue.txt" \
        "$dir/measure-fw0-post-status.json" "$dir/measure-fw0-post-metrics.prom" \
        "$dir/measure-fw0-st-links.txt")"
    MEASURE_PROVENANCE_FW1="$(observe_provenance_metadata \
        "$dir/measure-fw1-ruleset.json" "$dir/measure-fw1-nfqueue.txt" \
        "$dir/measure-fw1-post-status.json" "$dir/measure-fw1-post-metrics.prom" \
        "$dir/measure-fw1-st-links.txt")"
    if fix9506_teardown "$count" "$dir"; then
        MEASURE_TEARDOWN=1
        ACTIVE_FIXTURE_SETUP=0
        ACTIVE_FIXTURE_COUNT=0
        ACTIVE_FIXTURE_DIR=""
    else
        MEASURE_REASON="fixture-restore-failed:${shape}x${count} (config/SAs/divert/queue/RG residue)"
    fi
    if ((MEASURE_TEARDOWN != 1)); then
        return 1
    fi
    return 0
}

snapshot_node() {
    local node="$1" path="$2"
    remote "$node" 'cli -c "show configuration | display set"' >"$path" 2>&1
}
normalize_config() {
    # The config renderer leaves empty top-level security containers after
    # deleting their last fixture child. They carry no policy/proposal/state
    # and are not semantic residue; ignore these display-set artifacts while
    # comparing the pre/post configuration snapshots.
    sed -n '/^set /p' "$1" |
        sed -E '/^set security (ike|ipsec)$/d; /^set security address-book( global)?$/d'
}

# Determine the source/build identity before any live verdict is emitted.
GIT_SHA="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || printf unknown)"
LOCAL_EXE="${XPF_9506_LOCAL_EXE:-$ROOT/xpfd}"
LOCAL_SHA="unknown"
if [[ -f "$LOCAL_EXE" ]]; then
    LOCAL_SHA="$(sha256sum "$LOCAL_EXE" 2>/dev/null | awk '{print $1}')"
fi
REMOTE0_SHA="$(deploy_running_xpfd_sha256 "$NODE0" 3 2>/dev/null || true)"
REMOTE1_SHA="$(deploy_running_xpfd_sha256 "$NODE1" 3 2>/dev/null || true)"
if [[ -n "$LOCAL_SHA" && "$LOCAL_SHA" != unknown && "$REMOTE0_SHA" == "$LOCAL_SHA" && "$REMOTE1_SHA" == "$LOCAL_SHA" ]]; then
    EXE_CHECK=MATCH
else
    if [[ -z "$REMOTE0_SHA" || -z "$REMOTE1_SHA" || "$LOCAL_SHA" == unknown ]]; then
        EXE_CHECK=UNAVAILABLE
    else
        EXE_CHECK=MISMATCH
    fi
fi
printf 'T12_G2_ATTEST git_sha=%s local_exe_sha=%s fw0_exe_sha=%s fw1_exe_sha=%s exe_check=%s exe_scope=both archive=%s\n' \
    "$GIT_SHA" "$LOCAL_SHA" "${REMOTE0_SHA:-unknown}" "${REMOTE1_SHA:-unknown}" "$EXE_CHECK" "$ARCHIVE_DIR"

# Record complete pre/post configuration snapshots even when the cell refuses
# before creating a fixture.  Restore is an independent acceptance predicate.
BASE0="$ARCHIVE_DIR/fw0-pre.set"
BASE1="$ARCHIVE_DIR/fw1-pre.set"
POST0="$ARCHIVE_DIR/fw0-post.set"
POST1="$ARCHIVE_DIR/fw1-post.set"
snapshot_node "$NODE0" "$BASE0" || true
snapshot_node "$NODE1" "$BASE1" || true
normalize_config "$BASE0" >"$BASE0.norm" 2>/dev/null || :
observe_chain_overhead "$NODE0" "$ARCHIVE_DIR" t12-fence-alone-fw0
T12_OVERHEAD_FENCE_ALONE_FW0="$CHAIN_OVERHEAD_FILE"
observe_chain_overhead "$NODE1" "$ARCHIVE_DIR" t12-fence-alone-fw1
T12_OVERHEAD_FENCE_ALONE_FW1="$CHAIN_OVERHEAD_FILE"
normalize_config "$BASE1" >"$BASE1.norm" 2>/dev/null || :

# T12 uses a small real v4 fixture for the exact shape and no-bypass cells.
# The fixture builder owns setup failure cleanup; successful setup remains
# live until the cell rows have been emitted and then is torn down below.
T12_FIXTURE_SHAPE="${XPF_9506_T12_SHAPE:-v4_native}"
T12_FIXTURE_COUNT="${XPF_9506_T12_COUNT:-2}"
T12_FIXTURE_DIR="$ARCHIVE_DIR/fixture-t12-${T12_FIXTURE_SHAPE}-${T12_FIXTURE_COUNT}"
T12_FIXTURE_SETUP=0
T12_FIXTURE_REASON=""
T12_FIXTURE_RESTORE_OK=1
ACTIVE_FIXTURE_SETUP=1
ACTIVE_FIXTURE_COUNT="$T12_FIXTURE_COUNT"
ACTIVE_FIXTURE_DIR="$T12_FIXTURE_DIR"
FIXTURE_PHASE_BLOCKED=0
T12_FIXTURE_CLEANED=0
t12_fixture_cleanup() {
    local rc=$?
    trap - EXIT
    if [[ "$ACTIVE_FIXTURE_SETUP" == 1 ]]; then
        echo "t12-g2-9506: EXIT cleanup for live fixture count=$ACTIVE_FIXTURE_COUNT dir=$ACTIVE_FIXTURE_DIR" >&2
        if ! fix9506_teardown "$ACTIVE_FIXTURE_COUNT" "$ACTIVE_FIXTURE_DIR"; then
            T12_FIXTURE_RESTORE_OK=0
            rc=1
        else
            ACTIVE_FIXTURE_SETUP=0
            ACTIVE_FIXTURE_COUNT=0
            ACTIVE_FIXTURE_DIR=""
        fi
    fi
    exit "$rc"
}
trap t12_fixture_cleanup EXIT
if fix9506_setup "$T12_FIXTURE_SHAPE" "$T12_FIXTURE_COUNT" "$T12_FIXTURE_DIR"; then
    T12_FIXTURE_SETUP=1
else
    T12_FIXTURE_REASON="fixture-setup-failed:${T12_FIXTURE_SHAPE}x${T12_FIXTURE_COUNT} (inspect ${T12_FIXTURE_DIR}; no live-SA verdict)"
    if fix9506_teardown "$T12_FIXTURE_COUNT" "$T12_FIXTURE_DIR"; then
        ACTIVE_FIXTURE_SETUP=0
        ACTIVE_FIXTURE_COUNT=0
        ACTIVE_FIXTURE_DIR=""
    else
        T12_FIXTURE_RESTORE_OK=0
        FIXTURE_PHASE_BLOCKED=1
    fi
fi
remote "$NODE0" 'ip -d -o link show type xfrm | sed -n "/: st[0-9][0-9]*\(\.[0-9][0-9]*\)\?\(@[^:]*\)\?:/p"' >"$ARCHIVE_DIR/fw0-st-links.txt" 2>&1 || :
remote "$NODE1" 'ip -d -o link show type xfrm | sed -n "/: st[0-9][0-9]*\(\.[0-9][0-9]*\)\?\(@[^:]*\)\?:/p"' >"$ARCHIVE_DIR/fw1-st-links.txt" 2>&1 || :
remote "$NODE0" 'ip -s xfrm state' >"$ARCHIVE_DIR/fw0-xfrm-state.txt" 2>&1 || :
remote "$NODE1" 'ip -s xfrm state' >"$ARCHIVE_DIR/fw1-xfrm-state.txt" 2>&1 || :
remote "$NODE0" 'nft -j list ruleset' >"$ARCHIVE_DIR/fw0-ruleset.json" 2>&1 || :
remote "$NODE1" 'nft -j list ruleset' >"$ARCHIVE_DIR/fw1-ruleset.json" 2>&1 || :
remote "$NODE0" 'ip -d link show xpf-usp1; tc filter show dev xpf-usp1 ingress' >"$ARCHIVE_DIR/fw0-q0-mark.txt" 2>&1 || :
remote "$NODE1" 'ip -d link show xpf-usp1; tc filter show dev xpf-usp1 ingress' >"$ARCHIVE_DIR/fw1-q0-mark.txt" 2>&1 || :
has_st_fw0=0
if grep -qE 'st9506[0-9]*(\.[0-9]+)?' "$ARCHIVE_DIR/fw0-st-links.txt" 2>/dev/null; then has_st_fw0=1; fi
has_st_fw1=0
if grep -qE 'st9506[0-9]*(\.[0-9]+)?' "$ARCHIVE_DIR/fw1-st-links.txt" 2>/dev/null; then has_st_fw1=1; fi
has_st=0
if both_nodes_present "$has_st_fw0" "$has_st_fw1"; then has_st=1; fi
has_sa_fw0=0
if grep -qE 'if_id (0x2522[0-9a-fA-F]{4}|622985[0-9]+)' "$ARCHIVE_DIR/fw0-xfrm-state.txt" 2>/dev/null; then has_sa_fw0=1; fi
has_sa_fw1=0
if grep -qE 'if_id (0x2522[0-9a-fA-F]{4}|622985[0-9]+)' "$ARCHIVE_DIR/fw1-xfrm-state.txt" 2>/dev/null; then has_sa_fw1=1; fi
has_sa=0
if both_nodes_present "$has_sa_fw0" "$has_sa_fw1"; then has_sa=1; fi

read -r F0_TABLE F0_EXACT F0_INET_DIVERT F0_BRIDGE_DIVERT F0_DIVERT_EXACT F0_READ < <(
    ruleset_flags "$ARCHIVE_DIR/fw0-ruleset.json"
)
read -r F1_TABLE F1_EXACT F1_INET_DIVERT F1_BRIDGE_DIVERT F1_DIVERT_EXACT F1_READ < <(
    ruleset_flags "$ARCHIVE_DIR/fw1-ruleset.json"
)
read -r F0_IF F0_II F0_BF F0_BI F0_QTOTAL < <(fix9506_divert_queues "$ARCHIVE_DIR/fw0-ruleset.json")
read -r F1_IF F1_II F1_BF F1_BI F1_QTOTAL < <(fix9506_divert_queues "$ARCHIVE_DIR/fw1-ruleset.json")
has_fence=0
if [[ "$F0_READ" == 1 && "$F1_READ" == 1 && "$F0_EXACT" == 1 && "$F1_EXACT" == 1 ]]; then has_fence=1; fi
has_inet_divert=0
if [[ "$F0_READ" == 1 && "$F1_READ" == 1 && "$F0_INET_DIVERT" == 1 && "$F1_INET_DIVERT" == 1 ]]; then has_inet_divert=1; fi
has_divert=0
if [[ "$T12_FIXTURE_SETUP" == 1 && "$F0_READ" == 1 && "$F1_READ" == 1 &&
      "$F0_DIVERT_EXACT" == 1 && "$F1_DIVERT_EXACT" == 1 &&
      "$F0_IF" -ge "$T12_FIXTURE_COUNT" && "$F0_II" -ge "$T12_FIXTURE_COUNT" &&
      "$F0_BF" -ge "$T12_FIXTURE_COUNT" && "$F0_BI" -ge "$T12_FIXTURE_COUNT" &&
      "$F1_IF" -ge "$T12_FIXTURE_COUNT" && "$F1_II" -ge "$T12_FIXTURE_COUNT" &&
      "$F1_BF" -ge "$T12_FIXTURE_COUNT" && "$F1_BI" -ge "$T12_FIXTURE_COUNT" ]]; then
    has_divert=1
fi
has_q0=0
if grep -qE 'xpf-usp1' "$ARCHIVE_DIR/fw0-q0-mark.txt" 2>/dev/null &&
    grep -qE '58465001|queue_mapping' "$ARCHIVE_DIR/fw0-q0-mark.txt" 2>/dev/null &&
    grep -qE 'xpf-usp1' "$ARCHIVE_DIR/fw1-q0-mark.txt" 2>/dev/null &&
    grep -qE '58465001|queue_mapping' "$ARCHIVE_DIR/fw1-q0-mark.txt" 2>/dev/null; then
    has_q0=1
fi
read -r T12_RULESET_READ T12_FENCE_SHAPE T12_DIVERT_SHAPE T12_ORDER_SHAPE T12_STN_RULES < <(
    observe_ruleset_shape "$ARCHIVE_DIR/fw0-ruleset.json"
)
read -r T12_RULESET_READ1 T12_FENCE_SHAPE1 T12_DIVERT_SHAPE1 T12_ORDER_SHAPE1 T12_STN_RULES1 < <(
    observe_ruleset_shape "$ARCHIVE_DIR/fw1-ruleset.json"
)
T12_STATIC_FENCE=0
T12_STATIC_DIVERT=0
T12_STATIC_ORDER=0
if [[ "$T12_RULESET_READ" == 1 && "$T12_RULESET_READ1" == 1 &&
      "$T12_FENCE_SHAPE" == 1 && "$T12_FENCE_SHAPE1" == 1 ]]; then
    T12_STATIC_FENCE=1
fi
if [[ "$T12_RULESET_READ" == 1 && "$T12_RULESET_READ1" == 1 &&
      "$T12_DIVERT_SHAPE" == 1 && "$T12_DIVERT_SHAPE1" == 1 ]]; then
    T12_STATIC_DIVERT=1
fi
if [[ "$T12_RULESET_READ" == 1 && "$T12_RULESET_READ1" == 1 &&
      "$T12_ORDER_SHAPE" == 1 && "$T12_ORDER_SHAPE1" == 1 ]]; then
    T12_STATIC_ORDER=1
fi
observe_runtime "$NODE0" "$ARCHIVE_DIR" t12-fw0-pre
T12_RUNTIME_FW0_PRE="$RUNTIME_PROC_FILE"
observe_runtime "$NODE1" "$ARCHIVE_DIR" t12-fw1-pre
T12_RUNTIME_FW1_PRE="$RUNTIME_PROC_FILE"
observe_chain_overhead "$NODE0" "$ARCHIVE_DIR" t12-fw0-pre
T12_OVERHEAD_FW0_PRE="$CHAIN_OVERHEAD_FILE"
observe_chain_overhead "$NODE1" "$ARCHIVE_DIR" t12-fw1-pre
T12_OVERHEAD_FW1_PRE="$CHAIN_OVERHEAD_FILE"
T12_FENCE_ALONE_LISTENERS_FW0="$(sed -n 's/^listener_unix=//p' "$T12_OVERHEAD_FENCE_ALONE_FW0" | head -n 1)"
T12_FENCE_ALONE_LISTENERS_FW1="$(sed -n 's/^listener_unix=//p' "$T12_OVERHEAD_FENCE_ALONE_FW1" | head -n 1)"
T12_DIVERT_LISTENERS_FW0="$(sed -n 's/^listener_unix=//p' "$T12_OVERHEAD_FW0_PRE" | head -n 1)"
T12_DIVERT_LISTENERS_FW1="$(sed -n 's/^listener_unix=//p' "$T12_OVERHEAD_FW1_PRE" | head -n 1)"
[[ "$T12_FENCE_ALONE_LISTENERS_FW0" =~ ^[0-9]+$ ]] || T12_FENCE_ALONE_LISTENERS_FW0=0
[[ "$T12_FENCE_ALONE_LISTENERS_FW1" =~ ^[0-9]+$ ]] || T12_FENCE_ALONE_LISTENERS_FW1=0
[[ "$T12_DIVERT_LISTENERS_FW0" =~ ^[0-9]+$ ]] || T12_DIVERT_LISTENERS_FW0=0
[[ "$T12_DIVERT_LISTENERS_FW1" =~ ^[0-9]+$ ]] || T12_DIVERT_LISTENERS_FW1=0
observe_vrf_scope "$NODE0" "$ARCHIVE_DIR" t12-fw0
observe_vrf_scope "$NODE1" "$ARCHIVE_DIR" t12-fw1
T12_PROVENANCE_FW0="$(observe_provenance_metadata \
    "$ARCHIVE_DIR/fw0-ruleset.json" "$T12_FIXTURE_DIR/fw0-nfqueue.txt" \
    "$ARCHIVE_DIR/t12-fw0-pre-status.json" "$ARCHIVE_DIR/t12-fw0-pre-metrics.prom" \
    "$ARCHIVE_DIR/fw0-st-links.txt")"
T12_PROVENANCE_FW1="$(observe_provenance_metadata \
    "$ARCHIVE_DIR/fw1-ruleset.json" "$T12_FIXTURE_DIR/fw1-nfqueue.txt" \
    "$ARCHIVE_DIR/t12-fw1-pre-status.json" "$ARCHIVE_DIR/t12-fw1-pre-metrics.prom" \
    "$ARCHIVE_DIR/fw1-st-links.txt")"
T12_QUEUE_ECON_FW0="$(observe_queue_economics "$ARCHIVE_DIR/fw0-ruleset.json" "$T12_RUNTIME_FW0_PRE" "$T12_FIXTURE_DIR/fw0-nfqueue.txt")"
T12_QUEUE_ECON_FW1="$(observe_queue_economics "$ARCHIVE_DIR/fw1-ruleset.json" "$T12_RUNTIME_FW1_PRE" "$T12_FIXTURE_DIR/fw1-nfqueue.txt")"
printf 'T12_G2_OBSERVERS fence_structural=%s divert_structural=%s order_structural=%s fence_exact=0 divert_exact=0 order_exact=0 fw0_provenance="%s" fw1_provenance="%s" fw0_queue_economics="%s" fw1_queue_economics="%s"\n' \
    "$T12_STATIC_FENCE" "$T12_STATIC_DIVERT" "$T12_STATIC_ORDER" \
    "$T12_PROVENANCE_FW0" "$T12_PROVENANCE_FW1" "$T12_QUEUE_ECON_FW0" "$T12_QUEUE_ECON_FW1"
T12_PROV_STATIC_FW0="$(observer_field "$T12_PROVENANCE_FW0" static)"
T12_PROV_STATIC_FW1="$(observer_field "$T12_PROVENANCE_FW1" static)"
T12_PROV_QUEUE_ROWS_FW0="$(observer_field "$T12_PROVENANCE_FW0" queue_rows)"
T12_PROV_QUEUE_ROWS_FW1="$(observer_field "$T12_PROVENANCE_FW1" queue_rows)"
T12_PROV_PACKET_SAMPLES_FW0="$(observer_field "$T12_PROVENANCE_FW0" packet_samples)"
T12_PROV_PACKET_SAMPLES_FW1="$(observer_field "$T12_PROVENANCE_FW1" packet_samples)"
T12_PROV_MISMATCH_FW0="$(observer_field "$T12_PROVENANCE_FW0" mismatch)"
T12_PROV_MISMATCH_FW1="$(observer_field "$T12_PROVENANCE_FW1" mismatch)"
T12_PROV_JOIN_FW0="$(observer_field "$T12_PROVENANCE_FW0" join)"
T12_PROV_JOIN_FW1="$(observer_field "$T12_PROVENANCE_FW1" join)"
T12_PROV_CLASSES_FW0="$(observer_field "$T12_PROVENANCE_FW0" provenance_classes)"
T12_PROV_CLASSES_FW1="$(observer_field "$T12_PROVENANCE_FW1" provenance_classes)"
T12_PROV_PF_INET_FW0="$(observer_field "$T12_PROVENANCE_FW0" pf_inet)"
T12_PROV_PF_INET_FW1="$(observer_field "$T12_PROVENANCE_FW1" pf_inet)"
T12_PROV_PF_BRIDGE_FW0="$(observer_field "$T12_PROVENANCE_FW0" pf_bridge)"
T12_PROV_PF_BRIDGE_FW1="$(observer_field "$T12_PROVENANCE_FW1" pf_bridge)"
T12_PROV_PACKET_CLASSES_FW0="$(observer_field "$T12_PROVENANCE_FW0" packet_classes)"
T12_PROV_PACKET_CLASSES_FW1="$(observer_field "$T12_PROVENANCE_FW1" packet_classes)"
T12_PROV_ROWS_IF_FW0="$(observer_field "$T12_PROVENANCE_FW0" rows_inet_forward)"
T12_PROV_ROWS_IF_FW1="$(observer_field "$T12_PROVENANCE_FW1" rows_inet_forward)"
T12_PROV_ROWS_II_FW0="$(observer_field "$T12_PROVENANCE_FW0" rows_inet_input)"
T12_PROV_ROWS_II_FW1="$(observer_field "$T12_PROVENANCE_FW1" rows_inet_input)"
T12_PROV_ROWS_BF_FW0="$(observer_field "$T12_PROVENANCE_FW0" rows_bridge_forward)"
T12_PROV_ROWS_BF_FW1="$(observer_field "$T12_PROVENANCE_FW1" rows_bridge_forward)"
T12_PROV_ROWS_BI_FW0="$(observer_field "$T12_PROVENANCE_FW0" rows_bridge_input)"
T12_PROV_ROWS_BI_FW1="$(observer_field "$T12_PROVENANCE_FW1" rows_bridge_input)"
T12_PROV_PF_MISMATCH_FW0="$(observer_field "$T12_PROVENANCE_FW0" pf_mismatch)"
T12_PROV_PF_MISMATCH_FW1="$(observer_field "$T12_PROVENANCE_FW1" pf_mismatch)"
T12_PROV_COUNTER_MISMATCH_FW0="$(observer_field "$T12_PROVENANCE_FW0" counter_mismatch)"
T12_PROV_PACKET_MISMATCH_FW0="$(observer_field "$T12_PROVENANCE_FW0" prov_mismatch)"
T12_PROV_PACKET_MISMATCH_FW1="$(observer_field "$T12_PROVENANCE_FW1" prov_mismatch)"
T12_PROV_COUNTER_MISMATCH_FW1="$(observer_field "$T12_PROVENANCE_FW1" counter_mismatch)"
T12_QUEUE_INSTANCES_FW0="$(observer_field "$T12_QUEUE_ECON_FW0" queue_instances)"
T12_QUEUE_INSTANCES_FW1="$(observer_field "$T12_QUEUE_ECON_FW1" queue_instances)"
T12_QUEUE_FDS_FW0="$(observer_field "$T12_QUEUE_ECON_FW0" fd_count)"
T12_QUEUE_FDS_FW1="$(observer_field "$T12_QUEUE_ECON_FW1" fd_count)"
T12_QUEUE_PENDING_FW0="$(observer_field "$T12_QUEUE_ECON_FW0" queue_pending)"
T12_QUEUE_PENDING_FW1="$(observer_field "$T12_QUEUE_ECON_FW1" queue_pending)"
T12_QUEUE_DROPS_FW0="$(observer_field "$T12_QUEUE_ECON_FW0" queue_drops)"
T12_QUEUE_DROPS_FW1="$(observer_field "$T12_QUEUE_ECON_FW1" queue_drops)"
fixture=0
if [[ "$T12_FIXTURE_SETUP" == 1 && "$has_st" == 1 && "$has_sa" == 1 && "$has_divert" == 1 ]]; then fixture=1; fi
printf 'T12_G2_PRECONDITIONS stn=%s stn_fw0=%s stn_fw1=%s xfrm_sa=%s xfrm_sa_fw0=%s xfrm_sa_fw1=%s divert_table=%s fence_table=%s q0_mark_surface=%s ruleset_fw0_readable=%s ruleset_fw1_readable=%s complete_fixture=%s\n' \
    "$has_st" "$has_st_fw0" "$has_st_fw1" "$has_sa" "$has_sa_fw0" "$has_sa_fw1" "$has_divert" "$has_fence" "$has_q0" "$F0_READ" "$F1_READ" "$fixture"
T12_TRAFFIC_PACKETS=0
T12_TRAFFIC_LOSS=100
T12_TRAFFIC_XFRM_TUNNEL0_PACKETS=0
T12_TRAFFIC_OFFERED_FW0=0
T12_TRAFFIC_OFFERED_FW1=0
T12_TRAFFIC_LAN_OK=0
T12_TRAFFIC_PEER_OK=0
if [[ "$T12_FIXTURE_SETUP" == 1 ]]; then
    T12_TRAFFIC_DIR="$T12_FIXTURE_DIR/traffic"
    mkdir -p "$T12_TRAFFIC_DIR"
    fixture_measure_traffic "$T12_FIXTURE_SHAPE" "$T12_FIXTURE_COUNT" "$T12_TRAFFIC_DIR"
    T12_TRAFFIC_XFRM_TUNNEL0_PACKETS="$MEASURE_XFRM_TUNNEL0_PACKETS"
    T12_TRAFFIC_OFFERED_FW0="$MEASURE_OFFERED_FW0"
    T12_TRAFFIC_OFFERED_FW1="$MEASURE_OFFERED_FW1"
    T12_TRAFFIC_PACKETS="$MEASURE_PACKETS"
    T12_TRAFFIC_LOSS="$MEASURE_LOSS"
    T12_TRAFFIC_LAN_OK="$MEASURE_LAN_OK"
    T12_TRAFFIC_PEER_OK="$MEASURE_PEER_OK"
fi
T12_S5_FW0=0
T12_S5_FW1=0
T12_ACTOR_FW0=0
T12_ACTOR_FW1=0
T12_RUN_ID_FW0=unknown
T12_RUN_ID_FW1=unknown
T12_GENERATION_FW0=0
T12_GENERATION_FW1=0
T12_PERMIT_STATE_FW0=UNKNOWN
T12_PERMIT_STATE_FW1=UNKNOWN
T12_PERMIT_EPOCH_FW0=0
T12_PERMIT_EPOCH_FW1=0
T12_CONSUMED_FW0=0
T12_CONSUMED_FW1=0
T12_ADJUDICATED_FW0=0
T12_ADJUDICATED_FW1=0
T12_REINJECTED_FW0=0
T12_REINJECTED_FW1=0
T12_WRITTEN_FW0=0
T12_WRITTEN_FW1=0
T12_UNCERTAIN_FW0=0
T12_UNCERTAIN_FW1=0
T12_LATE_COMPLETIONS_FW0=0
T12_LATE_COMPLETIONS_FW1=0
T12_TIMEOUTS_FW0=0
T12_TIMEOUTS_FW1=0
T12_STALE_FW0=0
T12_STALE_FW1=0
T12_CANCELLED_FW0=0
T12_CANCELLED_FW1=0
T12_REFUSED_FW0=0
T12_REFUSED_FW1=0
T12_DELIVERED_AVAILABLE_FW0=0
T12_DELIVERED_AVAILABLE_FW1=0
T12_DELIVERED_FW0=0
T12_DELIVERED_FW1=0
T12_REASON_FW0=product-observer-unavailable:s5-status-or-go-metrics-absent
T12_REASON_FW1=product-observer-unavailable:s5-status-or-go-metrics-absent
if [[ "$T12_FIXTURE_SETUP" == 1 ]]; then
    observe_runtime "$NODE0" "$ARCHIVE_DIR" t12-fw0-post
    T12_RUNTIME_FW0_POST="$RUNTIME_PROC_FILE"
    T12_STATUS_FW0_POST="$RUNTIME_STATUS_FILE"
    T12_METRICS_FW0_POST="$RUNTIME_METRICS_FILE"
    T12_S5_FW0="$RUNTIME_S5_AVAILABLE"
    T12_ACTOR_FW0="$RUNTIME_ACTOR_ACTIVE"
    T12_RUN_ID_FW0="$RUNTIME_RUN_ID"
    T12_GENERATION_FW0="$RUNTIME_GENERATION"
    T12_PERMIT_STATE_FW0="$RUNTIME_PERMIT_STATE"
    T12_PERMIT_EPOCH_FW0="$RUNTIME_PERMIT_EPOCH"
    T12_CONSUMED_FW0="$RUNTIME_CONSUMED"
    T12_ADJUDICATED_FW0="$RUNTIME_ADJUDICATED"
    T12_REINJECTED_FW0="$RUNTIME_REINJECTED"
    T12_WRITTEN_FW0="$RUNTIME_WRITTEN"
    T12_UNCERTAIN_FW0="$RUNTIME_UNCERTAIN"
    T12_LATE_COMPLETIONS_FW0="$RUNTIME_LATE_COMPLETIONS"
    T12_TIMEOUTS_FW0="$RUNTIME_TIMEOUTS"
    T12_STALE_FW0="$RUNTIME_STALE"
    T12_CANCELLED_FW0="$RUNTIME_CANCELLED"
    T12_REFUSED_FW0="$RUNTIME_REFUSED"
    T12_DELIVERED_AVAILABLE_FW0="$RUNTIME_DELIVERED_AVAILABLE"
    T12_DELIVERED_FW0="$RUNTIME_DELIVERED"
    T12_REASON_FW0="$RUNTIME_REASON"
    observe_runtime "$NODE1" "$ARCHIVE_DIR" t12-fw1-post
    T12_RUNTIME_FW1_POST="$RUNTIME_PROC_FILE"
    T12_STATUS_FW1_POST="$RUNTIME_STATUS_FILE"
    T12_METRICS_FW1_POST="$RUNTIME_METRICS_FILE"
    T12_S5_FW1="$RUNTIME_S5_AVAILABLE"
    T12_ACTOR_FW1="$RUNTIME_ACTOR_ACTIVE"
    T12_RUN_ID_FW1="$RUNTIME_RUN_ID"
    T12_GENERATION_FW1="$RUNTIME_GENERATION"
    T12_PERMIT_STATE_FW1="$RUNTIME_PERMIT_STATE"
    T12_PERMIT_EPOCH_FW1="$RUNTIME_PERMIT_EPOCH"
    T12_CONSUMED_FW1="$RUNTIME_CONSUMED"
    T12_ADJUDICATED_FW1="$RUNTIME_ADJUDICATED"
    T12_REINJECTED_FW1="$RUNTIME_REINJECTED"
    T12_WRITTEN_FW1="$RUNTIME_WRITTEN"
    T12_UNCERTAIN_FW1="$RUNTIME_UNCERTAIN"
    # Re-read provenance after traffic and the post-traffic actor snapshot.
    # The pre-read above remains useful as the static baseline but cannot
    # claim packet rows that did not yet exist.
    T12_PROVENANCE_FW0="$(observe_provenance_metadata \
        "$ARCHIVE_DIR/fw0-ruleset.json" "$T12_FIXTURE_DIR/fw0-nfqueue.txt" \
        "$T12_STATUS_FW0_POST" "$T12_METRICS_FW0_POST" \
        "$T12_FIXTURE_DIR/fw0-st-links.txt")"
    T12_PROVENANCE_FW1="$(observe_provenance_metadata \
        "$ARCHIVE_DIR/fw1-ruleset.json" "$T12_FIXTURE_DIR/fw1-nfqueue.txt" \
        "$T12_STATUS_FW1_POST" "$T12_METRICS_FW1_POST" \
        "$T12_FIXTURE_DIR/fw1-st-links.txt")"
    T12_PROV_STATIC_FW0="$(observer_field "$T12_PROVENANCE_FW0" static)"
    T12_PROV_STATIC_FW1="$(observer_field "$T12_PROVENANCE_FW1" static)"
    T12_PROV_QUEUE_ROWS_FW0="$(observer_field "$T12_PROVENANCE_FW0" queue_rows)"
    T12_PROV_QUEUE_ROWS_FW1="$(observer_field "$T12_PROVENANCE_FW1" queue_rows)"
    T12_PROV_PACKET_SAMPLES_FW0="$(observer_field "$T12_PROVENANCE_FW0" packet_samples)"
    T12_PROV_PACKET_SAMPLES_FW1="$(observer_field "$T12_PROVENANCE_FW1" packet_samples)"
    T12_PROV_MISMATCH_FW0="$(observer_field "$T12_PROVENANCE_FW0" mismatch)"
    T12_PROV_MISMATCH_FW1="$(observer_field "$T12_PROVENANCE_FW1" mismatch)"
    T12_PROV_JOIN_FW0="$(observer_field "$T12_PROVENANCE_FW0" join)"
    T12_PROV_JOIN_FW1="$(observer_field "$T12_PROVENANCE_FW1" join)"
    T12_PROV_CLASSES_FW0="$(observer_field "$T12_PROVENANCE_FW0" provenance_classes)"
    T12_PROV_CLASSES_FW1="$(observer_field "$T12_PROVENANCE_FW1" provenance_classes)"
    T12_PROV_PF_INET_FW0="$(observer_field "$T12_PROVENANCE_FW0" pf_inet)"
    T12_PROV_PF_INET_FW1="$(observer_field "$T12_PROVENANCE_FW1" pf_inet)"
    T12_PROV_PF_BRIDGE_FW0="$(observer_field "$T12_PROVENANCE_FW0" pf_bridge)"
    T12_PROV_PF_BRIDGE_FW1="$(observer_field "$T12_PROVENANCE_FW1" pf_bridge)"
    T12_PROV_PACKET_CLASSES_FW0="$(observer_field "$T12_PROVENANCE_FW0" packet_classes)"
    T12_PROV_PACKET_CLASSES_FW1="$(observer_field "$T12_PROVENANCE_FW1" packet_classes)"
    T12_PROV_ROWS_IF_FW0="$(observer_field "$T12_PROVENANCE_FW0" rows_inet_forward)"
    T12_PROV_ROWS_IF_FW1="$(observer_field "$T12_PROVENANCE_FW1" rows_inet_forward)"
    T12_PROV_ROWS_II_FW0="$(observer_field "$T12_PROVENANCE_FW0" rows_inet_input)"
    T12_PROV_ROWS_II_FW1="$(observer_field "$T12_PROVENANCE_FW1" rows_inet_input)"
    T12_PROV_ROWS_BF_FW0="$(observer_field "$T12_PROVENANCE_FW0" rows_bridge_forward)"
    T12_PROV_ROWS_BF_FW1="$(observer_field "$T12_PROVENANCE_FW1" rows_bridge_forward)"
    T12_PROV_ROWS_BI_FW0="$(observer_field "$T12_PROVENANCE_FW0" rows_bridge_input)"
    T12_PROV_ROWS_BI_FW1="$(observer_field "$T12_PROVENANCE_FW1" rows_bridge_input)"
    T12_PROV_PF_MISMATCH_FW0="$(observer_field "$T12_PROVENANCE_FW0" pf_mismatch)"
    T12_PROV_PF_MISMATCH_FW1="$(observer_field "$T12_PROVENANCE_FW1" pf_mismatch)"
    T12_PROV_PACKET_MISMATCH_FW0="$(observer_field "$T12_PROVENANCE_FW0" prov_mismatch)"
    T12_PROV_PACKET_MISMATCH_FW1="$(observer_field "$T12_PROVENANCE_FW1" prov_mismatch)"
    T12_PROV_COUNTER_MISMATCH_FW0="$(observer_field "$T12_PROVENANCE_FW0" counter_mismatch)"
    T12_PROV_COUNTER_MISMATCH_FW1="$(observer_field "$T12_PROVENANCE_FW1" counter_mismatch)"
    printf 'T12_G2_PROVENANCE_EXACT fw0="%s" fw1="%s"\n' \
        "$T12_PROVENANCE_FW0" "$T12_PROVENANCE_FW1"
    T12_LATE_COMPLETIONS_FW1="$RUNTIME_LATE_COMPLETIONS"
    T12_TIMEOUTS_FW1="$RUNTIME_TIMEOUTS"
    T12_STALE_FW1="$RUNTIME_STALE"
    T12_CANCELLED_FW1="$RUNTIME_CANCELLED"
    T12_REFUSED_FW1="$RUNTIME_REFUSED"
    T12_DELIVERED_AVAILABLE_FW1="$RUNTIME_DELIVERED_AVAILABLE"
    T12_DELIVERED_FW1="$RUNTIME_DELIVERED"
    T12_REASON_FW1="$RUNTIME_REASON"
    observe_chain_overhead "$NODE0" "$ARCHIVE_DIR" t12-fw0-post
    observe_chain_overhead "$NODE1" "$ARCHIVE_DIR" t12-fw1-post
    printf 'T12_G2_CONSUMER fw0_actor_active=%s fw0_s5_available=%s fw0_run_id=%s fw0_generation=%s fw0_permit_state=%s fw0_permit_epoch=%s fw0_consumed=%s fw0_adjudicated=%s fw0_reinjected=%s fw0_delivered_available=%s fw0_delivered=%s fw0_reason=%s fw1_actor_active=%s fw1_s5_available=%s fw1_run_id=%s fw1_generation=%s fw1_permit_state=%s fw1_permit_epoch=%s fw1_consumed=%s fw1_adjudicated=%s fw1_reinjected=%s fw1_delivered_available=%s fw1_delivered=%s fw1_reason=%s\n' \
        "$T12_ACTOR_FW0" "$T12_S5_FW0" "$T12_RUN_ID_FW0" "$T12_GENERATION_FW0" "$T12_PERMIT_STATE_FW0" "$T12_PERMIT_EPOCH_FW0" "$T12_CONSUMED_FW0" "$T12_ADJUDICATED_FW0" "$T12_REINJECTED_FW0" "$T12_DELIVERED_AVAILABLE_FW0" "$T12_DELIVERED_FW0" "$T12_REASON_FW0" \
        "$T12_ACTOR_FW1" "$T12_S5_FW1" "$T12_RUN_ID_FW1" "$T12_GENERATION_FW1" "$T12_PERMIT_STATE_FW1" "$T12_PERMIT_EPOCH_FW1" "$T12_CONSUMED_FW1" "$T12_ADJUDICATED_FW1" "$T12_REINJECTED_FW1" "$T12_DELIVERED_AVAILABLE_FW1" "$T12_DELIVERED_FW1" "$T12_REASON_FW1"
fi

# Cell result helper.  Every cell names its plan section/predicate and emits a
# dedicated ledger row.  Metrics are numeric so the row remains auditable by
# ledger_compare.py; the human predicate/observation is printed beside it.
# Buffer every cell until the post-run configuration/residue proof succeeds.
# A PASS written before restore is not evidence: a later teardown failure must
# demote every buffered result to VOID and never leave a false green ledger row.
CELL_ROWS_FILE="$ARCHIVE_DIR/cells.tsv"
: >"$CELL_ROWS_FILE"
CELL_BUFFER_ONLY=1
CELL_COUNT=0
CELL_VOID=0
CELL_FAIL=0
CELL_PASS=0
emit_cell() {
    local gate="$1" section="$2" predicate="$3" observed="$4" verdict="$5" reason="$6" metrics="$7"
    metrics="${metrics} ruleset_fw0_readable=${F0_READ} ruleset_fw0_parse_ok=${F0_READ} ruleset_fw1_readable=${F1_READ} ruleset_fw1_parse_ok=${F1_READ}"
    printf 'T12_G2_CELL gate=%s section=%s predicate=%s observed=%s verdict=%s reason=%s\n' \
        "$gate" "$section" "$predicate" "$observed" "$verdict" "${reason:---}"
    if [[ "$CELL_BUFFER_ONLY" == 1 ]]; then
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$gate" "$section" "$predicate" "$observed" "$verdict" "$reason" "$metrics" >>"$CELL_ROWS_FILE"
        return 0
    fi
    CELL_COUNT=$((CELL_COUNT + 1))
    case "$verdict" in PASS) CELL_PASS=$((CELL_PASS + 1));; FAIL) CELL_FAIL=$((CELL_FAIL + 1));; VOID) CELL_VOID=$((CELL_VOID + 1));; esac
    local emit_args=(
        --gate "$gate" --env "$ENV_NAME" --verdict "$verdict"
        --build-git-sha "$GIT_SHA" --build-exe-sha256 "$LOCAL_SHA"
        --running-exe-sha256 "${REMOTE0_SHA:-unknown}"
        --running-exe-sha256-peer "${REMOTE1_SHA:-unknown}"
        --exe-check "$EXE_CHECK" --exe-scope both --node "$NODE0" --node-peer "$NODE1"
        --adapter t12-g2-9506 --artifacts "$ARCHIVE_DIR"
        --metrics "$metrics" --ledger "${XPF_LEDGER:-$ROOT/test/results/ledger.d}"
    )
    if [[ "$verdict" == VOID ]]; then
        emit_args+=(--void-reason "$reason")
    else
        emit_args+=(--headline-metric cell_failed --headline-direction lower-better)
    fi
    harness_result_emit "${emit_args[@]}" >/dev/null 2>&1 || {
        echo "T12_G2_LEDGER_WRITE_FAIL gate=$gate" >&2
        CELL_FAIL=$((CELL_FAIL + 1))
    }
}

# If a required fixture/SAs is absent, every packet/overhead claim is a VOID,
# with the exact missing inputs carried in the reason.  Fence-only shape is
# still independently observable, but never promoted into a traffic claim.
missing=""
[[ "$has_st_fw0" == 1 ]] || missing="${missing:+$missing,}fw0-owned-stN"
[[ "$has_st_fw1" == 1 ]] || missing="${missing:+$missing,}fw1-owned-stN"
[[ "$has_sa_fw0" == 1 ]] || missing="${missing:+$missing,}fw0-live-XFRM-SA"
[[ "$has_sa_fw1" == 1 ]] || missing="${missing:+$missing,}fw1-live-XFRM-SA"
[[ "$has_divert" == 1 ]] || missing="${missing:+$missing,}xpf_ipsec_divert"
[[ "$F0_READ" == 1 ]] || missing="${missing:+$missing,}fw0-nft-unavailable"
[[ "$F1_READ" == 1 ]] || missing="${missing:+$missing,}fw1-nft-unavailable"
[[ "$EXE_CHECK" == MATCH ]] || missing="${missing:+$missing,}exe-attestation-${EXE_CHECK}-requires-MATCH"
[[ "$T12_FIXTURE_RESTORE_OK" == 1 ]] || missing="${missing:+$missing,}t12-fixture-restore-failed"
if [[ -n "$missing" ]]; then
    PREASON="missing-precondition:${missing} (r6 §5.1/§5.2 real-SA routed-inet fixture unavailable; unreadable ruleset observers are not treated as absence)"
else
    PREASON=""
fi
LIVE_REASON="${PREASON:-harness-void}"
# r6 §5.2 cells.
if [[ "$has_fence" == 1 ]]; then
    emit_cell t12_9506_fence_shape 'r6 §5.2.1' 'inet+bridge fence exact shape/policy DROP' \
        "both nodes readable; structural fence observer=$T12_STATIC_FENCE; dynamic armed pinholes and prohibited-name absence were not parsed" VOID \
        "measurement-incomplete:exact-armed-pinhole-set" \
        "cell_failed=1 fence_chain_exact=0 fence_structural=$T12_STATIC_FENCE fence_both_nodes=1 pinholes_validated=0"
else
    emit_cell t12_9506_fence_shape 'r6 §5.2.1' 'inet+bridge fence exact shape/policy DROP' \
        'xpf_transit_barrier absent from observed ruleset or observer unavailable' VOID "$LIVE_REASON" \
        "cell_failed=1 fence_chain_exact=0 fence_structural=$T12_STATIC_FENCE fence_both_nodes=0 pinholes_validated=0"
fi
if [[ "$has_divert" == 1 ]]; then
    emit_cell t12_9506_divert_order 'r6 §5.2.2-§5.2.3' 'divert chains at P_divert before filter fence; four provenance classes' \
        "queue classes counted ($F0_IF/$F0_II/$F0_BF/$F0_BI); structural observer divert=$T12_STATIC_DIVERT order=$T12_STATIC_ORDER, but exact per-rule provenance/PF binds/same-priority-chain absence were not parsed" VOID \
        "measurement-incomplete:exact-provenance-rule-set" \
        "cell_failed=1 divert_table=1 divert_structural=$T12_STATIC_DIVERT order_structural=$T12_STATIC_ORDER provenance_classes=0 priority_divert=-175 priority_fence=0"
else
    emit_cell t12_9506_divert_order 'r6 §5.2.2-§5.2.3' 'divert chains at P_divert before filter fence; four provenance classes' \
        'xpf_ipsec_divert absent from observed ruleset or observer unavailable' VOID "$LIVE_REASON" \
        "cell_failed=1 divert_table=0 divert_structural=$T12_STATIC_DIVERT order_structural=$T12_STATIC_ORDER provenance_classes=0 priority_divert=0 priority_fence=0"
fi
if [[ "$has_q0" == 1 && "$T12_TRAFFIC_PACKETS" -gt 0 ]]; then
    emit_cell t12_9506_no_bypass 'r6 §5.2.4-§5.2.5' 'q0 exact mark admits; q1/wrong mark and resumed xfrmi ACCEPT remain DROP' \
        "bidirectional decrypted delivery observed packets=$T12_TRAFFIC_PACKETS; offered_fw0=$T12_TRAFFIC_OFFERED_FW0 offered_fw1=$T12_TRAFFIC_OFFERED_FW1; xfrm_tunnel0_state_delta=$T12_TRAFFIC_XFRM_TUNNEL0_PACKETS; q0/wrong-mark/resumption matrix not injected" VOID \
        "measurement-incomplete:no-bypass-matrix" \
        "cell_failed=1 q0_mark_surface=1 packet_rows=$T12_TRAFFIC_PACKETS offered_fw0=$T12_TRAFFIC_OFFERED_FW0 offered_fw1=$T12_TRAFFIC_OFFERED_FW1 xfrm_tunnel0_packets=$T12_TRAFFIC_XFRM_TUNNEL0_PACKETS lan_to_peer=$T12_TRAFFIC_LAN_OK peer_to_lan=$T12_TRAFFIC_PEER_OK"
else
    emit_cell t12_9506_no_bypass 'r6 §5.2.4-§5.2.5' 'q0 exact mark admits; q1/wrong mark and resumed xfrmi ACCEPT remain DROP' \
        "${PREASON:-q0 mark surface or bidirectional traffic absent}" VOID "$LIVE_REASON" \
        "cell_failed=1 q0_mark_surface=$has_q0 packet_rows=$T12_TRAFFIC_PACKETS offered_fw0=$T12_TRAFFIC_OFFERED_FW0 offered_fw1=$T12_TRAFFIC_OFFERED_FW1 xfrm_tunnel0_packets=$T12_TRAFFIC_XFRM_TUNNEL0_PACKETS"
fi
emit_cell t12_9506_vrf_refusal 'r6 §5.2.5a' 'VRF/l3mdev enslaving revokes permit and publishes ACKed host fence' \
    "VRF scope census captured, but fixture did not create/enslave a test VRF; permit/fence ACK state is not exported" VOID \
    "measurement-incomplete:test-vrf-not-created-by-fixture" \
    "cell_failed=1 vrf_test_created=0 vrf_attached=0 fence_ack=0 conntrack_ack=0 input_queue_hits=0"
emit_cell t12_9506_coexistence_order 'r6 §5.2.3' 'both-family divert priority precedes filter; no same-priority base chain; mixed OPEN generation forbidden' \
    "structural divert order=$T12_STATIC_ORDER; exact same-priority-chain absence and mixed OPEN generation were not observed" VOID \
    "measurement-incomplete:exact-order-and-permit-observer-unavailable" \
    "cell_failed=1 inet_order_structural=$T12_STATIC_ORDER bridge_order_structural=$T12_STATIC_ORDER mixed_open=0 rotation_budget_ms=0"
T12_PROV_METRICS="cell_failed=1 packets=$T12_TRAFFIC_PACKETS provenance_static_fw0=$T12_PROV_STATIC_FW0 provenance_static_fw1=$T12_PROV_STATIC_FW1 provenance_rule_classes_fw0=$T12_PROV_CLASSES_FW0 provenance_rule_classes_fw1=$T12_PROV_CLASSES_FW1 pf_rules_inet_fw0=$T12_PROV_PF_INET_FW0 pf_rules_inet_fw1=$T12_PROV_PF_INET_FW1 pf_rules_bridge_fw0=$T12_PROV_PF_BRIDGE_FW0 pf_rules_bridge_fw1=$T12_PROV_PF_BRIDGE_FW1"
if [[ "$T12_PROV_JOIN_FW0" == joined ]]; then
    T12_PROV_METRICS+=" packet_samples_fw0=$T12_PROV_PACKET_SAMPLES_FW0 packet_classes_fw0=$T12_PROV_PACKET_CLASSES_FW0 rows_if_fw0=$T12_PROV_ROWS_IF_FW0 rows_ii_fw0=$T12_PROV_ROWS_II_FW0 rows_bf_fw0=$T12_PROV_ROWS_BF_FW0 rows_bi_fw0=$T12_PROV_ROWS_BI_FW0 packet_mismatch_fw0=$T12_PROV_PACKET_MISMATCH_FW0 pf_mismatch_fw0=$T12_PROV_PF_MISMATCH_FW0 counter_mismatch_fw0=$T12_PROV_COUNTER_MISMATCH_FW0 go_consumed_fw0=$T12_CONSUMED_FW0 go_adjudicated_fw0=$T12_ADJUDICATED_FW0 go_reinjected_fw0=$T12_REINJECTED_FW0 go_written_fw0=$T12_WRITTEN_FW0"
fi
if [[ "$T12_PROV_JOIN_FW1" == joined ]]; then
    T12_PROV_METRICS+=" packet_samples_fw1=$T12_PROV_PACKET_SAMPLES_FW1 packet_classes_fw1=$T12_PROV_PACKET_CLASSES_FW1 rows_if_fw1=$T12_PROV_ROWS_IF_FW1 rows_ii_fw1=$T12_PROV_ROWS_II_FW1 rows_bf_fw1=$T12_PROV_ROWS_BF_FW1 rows_bi_fw1=$T12_PROV_ROWS_BI_FW1 packet_mismatch_fw1=$T12_PROV_PACKET_MISMATCH_FW1 pf_mismatch_fw1=$T12_PROV_PF_MISMATCH_FW1 counter_mismatch_fw1=$T12_PROV_COUNTER_MISMATCH_FW1 go_consumed_fw1=$T12_CONSUMED_FW1 go_adjudicated_fw1=$T12_ADJUDICATED_FW1 go_reinjected_fw1=$T12_REINJECTED_FW1 go_written_fw1=$T12_WRITTEN_FW1"
fi
T12_PROV_REASON="measurement-incomplete:verdict-flip-owned-by-v-flip"
if [[ "$T12_PROV_JOIN_FW0" != joined || "$T12_PROV_JOIN_FW1" != joined ]]; then
    T12_PROV_REASON="product-observer-unavailable:fw0=${T12_REASON_FW0};fw1=${T12_REASON_FW1}"
fi
emit_cell t12_9506_provenance_metadata 'r6 §5.2.3-§5.2.4' 'queue-id, nfgen_family, hook, ifindex, owner and stN agree for every packet' \
    "ruleset_classes_fw0=$T12_PROV_CLASSES_FW0/$T12_PROV_PF_INET_FW0/$T12_PROV_PF_BRIDGE_FW0 ruleset_classes_fw1=$T12_PROV_CLASSES_FW1/$T12_PROV_PF_INET_FW1/$T12_PROV_PF_BRIDGE_FW1 join_fw0=$T12_PROV_JOIN_FW0 join_fw1=$T12_PROV_JOIN_FW1 packet_samples_fw0=$T12_PROV_PACKET_SAMPLES_FW0 packet_samples_fw1=$T12_PROV_PACKET_SAMPLES_FW1 packet_classes_fw0=$T12_PROV_PACKET_CLASSES_FW0 packet_classes_fw1=$T12_PROV_PACKET_CLASSES_FW1 rows_fw0=$T12_PROV_ROWS_IF_FW0/$T12_PROV_ROWS_II_FW0/$T12_PROV_ROWS_BF_FW0/$T12_PROV_ROWS_BI_FW0 rows_fw1=$T12_PROV_ROWS_IF_FW1/$T12_PROV_ROWS_II_FW1/$T12_PROV_ROWS_BF_FW1/$T12_PROV_ROWS_BI_FW1 packet_mismatch_fw0=$T12_PROV_PACKET_MISMATCH_FW0 packet_mismatch_fw1=$T12_PROV_PACKET_MISMATCH_FW1 pf_mismatch_fw0=$T12_PROV_PF_MISMATCH_FW0 pf_mismatch_fw1=$T12_PROV_PF_MISMATCH_FW1 counter_mismatch_fw0=$T12_PROV_COUNTER_MISMATCH_FW0 counter_mismatch_fw1=$T12_PROV_COUNTER_MISMATCH_FW1 fw0_reason=$T12_REASON_FW0 fw1_reason=$T12_REASON_FW1" VOID \
    "$T12_PROV_REASON" \
    "$T12_PROV_METRICS"
emit_cell t12_9506_ifindex_recreate 'r6 §5.2.3-§5.2.4' 'device delete/recreate/name reuse with changed ifindex drops and counts' "$LIVE_REASON" VOID "$LIVE_REASON" \
    "cell_failed=1 delete_recreate=0 changed_ifindex=0 mismatch_drop=0"

emit_cell t12_9506_bridge_conformance 'r6 §5.2.5' 'accepted bridge enslavement receives forward+input AF_BRIDGE then DROP-counts; rejection takes degraded branch' "$LIVE_REASON" VOID "$LIVE_REASON" \
    "cell_failed=1 enslavement_attempt=0 bridge_forward_rx=0 bridge_input_rx=0 bridge_drop=0"
emit_cell t12_9506_l2_refusal 'r6 §5.2.4-§5.2.5' 'bridge-forward/input never q0-reinject; unsupported L2 is DROP-and-count' "$LIVE_REASON" VOID "$LIVE_REASON" \
    "cell_failed=1 bridge_packets=0 q0_writes=0 l2_refusal=0"
emit_cell t12_9506_rotation_atomicity 'r6 §5.2.3' 'cross-family generation rotation is bounded, rollback-safe, and never mixed OPEN' "$LIVE_REASON" VOID "$LIVE_REASON" \
    "cell_failed=1 rotations=0 rollback=0 mixed_open=0"
emit_cell t12_9506_integration_ownership 'r6 §5.2.6' 'divert install/rotation/teardown uses gate helpers under transitGateMu; no bare writer' "$LIVE_REASON" VOID "$LIVE_REASON" \
    "cell_failed=1 helper_calls=0 bare_writers=0"
emit_cell t12_9506_pf_bind_scope 'r6 §5.2.2-§5.2.6' 'inet PF binds AF_INET/AF_INET6 and supported bridge binds AF_BRIDGE only' "$LIVE_REASON" VOID "$LIVE_REASON" \
    "cell_failed=1 inet_pf_bind=0 bridge_pf_bind=0 pf_mismatch=0"

# T12's live fixture must be fully removed before the independent G2 phases;
# keeping stN/SAs here would invalidate the post-run residue predicate.
if [[ "$T12_FIXTURE_SETUP" == 1 && "$T12_FIXTURE_CLEANED" != 1 ]]; then
    if fix9506_teardown "$T12_FIXTURE_COUNT" "$T12_FIXTURE_DIR"; then
        T12_FIXTURE_CLEANED=1
        ACTIVE_FIXTURE_SETUP=0
        ACTIVE_FIXTURE_COUNT=0
        ACTIVE_FIXTURE_DIR=""
    else
        T12_FIXTURE_REASON="fixture-restore-failed:${T12_FIXTURE_SHAPE}x${T12_FIXTURE_COUNT}"
        T12_FIXTURE_RESTORE_OK=0
        FIXTURE_PHASE_BLOCKED=1
    fi
fi

# r6 §5.1 G2 measurements. The per-shape rows exercise live routed-inet
# traffic, queue cardinality, teardown, and packet loss. Provenance and
# overhead cells remain VOID unless their dedicated observer is present.
QUEUE32_READY=0
QUEUE32_ECON_FW0="queue_instances=0 recv_buffers_mib=unknown socket_buffers_mib=unknown fd_count=0 queue_pending=0 queue_drops=0 rotation_overlap=unknown teardown=unknown"
QUEUE32_ECON_FW1="$QUEUE32_ECON_FW0"
QUEUE32_PROVENANCE_FW0="static=0 queue_rows=0 queue_ids=0 packet_samples=0 mismatch=0"
QUEUE32_PROVENANCE_FW1="$QUEUE32_PROVENANCE_FW0"
g2_emit_measured() {
    local shape="$1" tunnels="$2" gate="g2_9506_${shape}_${tunnels}"
    local observed prov0 prov1 mismatch0 mismatch1 qinst0 qinst1 qfd0 qfd1
    if run_fixture_measure "$shape" "$tunnels" g2; then
        local qif qii qbf qbi qt
        read -r qif qii qbf qbi qt <<<"$MEASURE_QUEUE_CLASSES"
        prov0="$(observer_field "$MEASURE_PROVENANCE_FW0" packet_samples)"
        prov1="$(observer_field "$MEASURE_PROVENANCE_FW1" packet_samples)"
        mismatch0="$(observer_field "$MEASURE_PROVENANCE_FW0" mismatch)"
        mismatch1="$(observer_field "$MEASURE_PROVENANCE_FW1" mismatch)"
        qinst0="$(observer_field "$MEASURE_QUEUE_ECON_FW0" queue_instances)"
        qinst1="$(observer_field "$MEASURE_QUEUE_ECON_FW1" queue_instances)"
        qfd0="$(observer_field "$MEASURE_QUEUE_ECON_FW0" fd_count)"
        qfd1="$(observer_field "$MEASURE_QUEUE_ECON_FW1" fd_count)"
        observed="fixture_ready=$MEASURE_READY queues_fw0=$MEASURE_QUEUE_TOTAL queues_fw1=$MEASURE_QUEUE_TOTAL_NODE1 queue_classes_fw0=${qif}/${qii}/${qbf}/${qbi} packets=$MEASURE_PACKETS offered_fw0=$MEASURE_OFFERED_FW0 offered_fw1=$MEASURE_OFFERED_FW1 xfrm_tunnel0_packets=$MEASURE_XFRM_TUNNEL0_PACKETS loss_pct=$MEASURE_LOSS teardown=$MEASURE_TEARDOWN provenance_samples_fw0=$prov0 provenance_samples_fw1=$prov1 s5_available_fw0=$MEASURE_S5_FW0 s5_available_fw1=$MEASURE_S5_FW1 consumed_fw0=$MEASURE_CONSUMED_FW0 consumed_fw1=$MEASURE_CONSUMED_FW1 adjudicated_fw0=$MEASURE_ADJUDICATED_FW0 adjudicated_fw1=$MEASURE_ADJUDICATED_FW1 reinjected_fw0=$MEASURE_REINJECTED_FW0 reinjected_fw1=$MEASURE_REINJECTED_FW1 written_fw0=$MEASURE_WRITTEN_FW0 written_fw1=$MEASURE_WRITTEN_FW1 uncertain_fw0=$MEASURE_UNCERTAIN_FW0 uncertain_fw1=$MEASURE_UNCERTAIN_FW1 late_completions_fw0=$MEASURE_LATE_COMPLETIONS_FW0 late_completions_fw1=$MEASURE_LATE_COMPLETIONS_FW1 timeouts_fw0=$MEASURE_TIMEOUTS_FW0 timeouts_fw1=$MEASURE_TIMEOUTS_FW1 stale_fw0=$MEASURE_STALE_FW0 stale_fw1=$MEASURE_STALE_FW1 cancelled_fw0=$MEASURE_CANCELLED_FW0 cancelled_fw1=$MEASURE_CANCELLED_FW1 refused_fw0=$MEASURE_REFUSED_FW0 refused_fw1=$MEASURE_REFUSED_FW1 delivered_available_fw0=$MEASURE_DELIVERED_AVAILABLE_FW0 delivered_available_fw1=$MEASURE_DELIVERED_AVAILABLE_FW1 queue_economics_fw0=$MEASURE_QUEUE_ECON_FW0 queue_economics_fw1=$MEASURE_QUEUE_ECON_FW1"
        emit_cell "$gate" 'r6 §5.1' \
            "${shape} routed-inet real-SA workload at ${tunnels} tunnels with provenance and non-tunnel overhead" \
            "$observed" VOID "measurement-incomplete:verdict-flip-unimplemented;fw0=${MEASURE_REASON_FW0};fw1=${MEASURE_REASON_FW1}" \
            "cell_failed=1 tunnels=$tunnels offered_expected=16 offered_fw0=$MEASURE_OFFERED_FW0 offered_fw1=$MEASURE_OFFERED_FW1 observed=$MEASURE_PACKETS xfrm_tunnel0_packets=$MEASURE_XFRM_TUNNEL0_PACKETS provenance_samples_fw0=$prov0 provenance_samples_fw1=$prov1 provenance_mismatch_fw0=$mismatch0 provenance_mismatch_fw1=$mismatch1 s5_available_fw0=$MEASURE_S5_FW0 s5_available_fw1=$MEASURE_S5_FW1 consumed_fw0=$MEASURE_CONSUMED_FW0 consumed_fw1=$MEASURE_CONSUMED_FW1 adjudicated_fw0=$MEASURE_ADJUDICATED_FW0 adjudicated_fw1=$MEASURE_ADJUDICATED_FW1 reinjected_fw0=$MEASURE_REINJECTED_FW0 reinjected_fw1=$MEASURE_REINJECTED_FW1 written_fw0=$MEASURE_WRITTEN_FW0 written_fw1=$MEASURE_WRITTEN_FW1 uncertain_fw0=$MEASURE_UNCERTAIN_FW0 uncertain_fw1=$MEASURE_UNCERTAIN_FW1 late_completions_fw0=$MEASURE_LATE_COMPLETIONS_FW0 late_completions_fw1=$MEASURE_LATE_COMPLETIONS_FW1 timeouts_fw0=$MEASURE_TIMEOUTS_FW0 timeouts_fw1=$MEASURE_TIMEOUTS_FW1 stale_fw0=$MEASURE_STALE_FW0 stale_fw1=$MEASURE_STALE_FW1 cancelled_fw0=$MEASURE_CANCELLED_FW0 cancelled_fw1=$MEASURE_CANCELLED_FW1 refused_fw0=$MEASURE_REFUSED_FW0 refused_fw1=$MEASURE_REFUSED_FW1 delivered_available_fw0=$MEASURE_DELIVERED_AVAILABLE_FW0 delivered_available_fw1=$MEASURE_DELIVERED_AVAILABLE_FW1 delivered_fw0=$MEASURE_DELIVERED_FW0 delivered_fw1=$MEASURE_DELIVERED_FW1 overhead_ns=0 queue_instances=$qinst0 queue_instances_fw1=$qinst1 fd_count=$qfd0 fd_count_fw1=$qfd1 recv_buffers_mib=0 recv_buffers_known=0 socket_buffers_mib=0 socket_buffers_known=0 rotation_overlap=0 rotation_known=0 loss_pct=$MEASURE_LOSS restore_clean=$MEASURE_TEARDOWN"
    else
        observed="fixture_ready=$MEASURE_READY queues_fw0=$MEASURE_QUEUE_TOTAL queues_fw1=$MEASURE_QUEUE_TOTAL_NODE1 packets=$MEASURE_PACKETS offered_fw0=$MEASURE_OFFERED_FW0 offered_fw1=$MEASURE_OFFERED_FW1 xfrm_tunnel0_packets=$MEASURE_XFRM_TUNNEL0_PACKETS loss_pct=$MEASURE_LOSS teardown=$MEASURE_TEARDOWN"
        emit_cell "$gate" 'r6 §5.1' \
            "${shape} routed-inet real-SA workload at ${tunnels} tunnels with provenance and non-tunnel overhead" \
            "$observed" VOID "${MEASURE_REASON:-fixture-measurement-failed}" \
            "cell_failed=1 tunnels=$tunnels offered_expected=16 offered_fw0=$MEASURE_OFFERED_FW0 offered_fw1=$MEASURE_OFFERED_FW1 observed=$MEASURE_PACKETS xfrm_tunnel0_packets=$MEASURE_XFRM_TUNNEL0_PACKETS provenance_mismatch=0 overhead_ns=0 queue_instances=$MEASURE_QUEUE_TOTAL queue_instances_fw1=$MEASURE_QUEUE_TOTAL_NODE1 loss_pct=$MEASURE_LOSS restore_clean=$MEASURE_TEARDOWN"
    fi
    if [[ "$shape" == v4_native && "$tunnels" == 32 ]]; then
        QUEUE32_READY="$MEASURE_READY"
        QUEUE32_ECON_FW0="$MEASURE_QUEUE_ECON_FW0"
        QUEUE32_ECON_FW1="$MEASURE_QUEUE_ECON_FW1"
        QUEUE32_PROVENANCE_FW0="$MEASURE_PROVENANCE_FW0"
        QUEUE32_PROVENANCE_FW1="$MEASURE_PROVENANCE_FW1"
    fi
}
emit_cell g2_9506_fence_baseline 'r6 §5.1' 'fence-alone baseline with concurrent routed+bridged non-tunnel traffic' \
    "fence-alone listener census fw0=$T12_FENCE_ALONE_LISTENERS_FW0 fw1=$T12_FENCE_ALONE_LISTENERS_FW1; workload/latency samples were not executed" VOID \
    "measurement-incomplete:fence-baseline-workload-observer-unavailable" \
    "cell_failed=1 baseline_samples=0 offered=0 observed=0 fence_alone_listeners_fw0=$T12_FENCE_ALONE_LISTENERS_FW0 fence_alone_listeners_fw1=$T12_FENCE_ALONE_LISTENERS_FW1"
emit_cell g2_9506_divert_detached 'r6 §5.1' 'fence+divert detached-listener overhead delta' \
    "fence+divert listener census fw0=$T12_DIVERT_LISTENERS_FW0 fw1=$T12_DIVERT_LISTENERS_FW1; detached-listener workload/latency samples were not executed" VOID \
    "measurement-incomplete:detached-listener-workload-observer-unavailable" \
    "cell_failed=1 baseline_samples=0 detached_samples=0 overhead_ns=0 divert_listeners_fw0=$T12_DIVERT_LISTENERS_FW0 divert_listeners_fw1=$T12_DIVERT_LISTENERS_FW1"
emit_cell g2_9506_divert_idle 'r6 §5.1' 'fence+divert attached-idle listener overhead delta' \
    "fence+divert attached-idle listener census fw0=$T12_DIVERT_LISTENERS_FW0 fw1=$T12_DIVERT_LISTENERS_FW1; idle workload/latency samples were not executed" VOID \
    "measurement-incomplete:idle-listener-workload-observer-unavailable" \
    "cell_failed=1 detached_samples=0 idle_samples=0 overhead_ns=0 divert_listeners_fw0=$T12_DIVERT_LISTENERS_FW0 divert_listeners_fw1=$T12_DIVERT_LISTENERS_FW1"
if run_fixture_measure v4_native 8 g2-capture; then
    emit_cell g2_9506_capture_8t 'r6 §5.1' '8-tunnel routed-inet capture cost and provenance validation' \
        "fixture_ready=$MEASURE_READY queues_fw0=$MEASURE_QUEUE_TOTAL queues_fw1=$MEASURE_QUEUE_TOTAL_NODE1 packets=$MEASURE_PACKETS offered_fw0=$MEASURE_OFFERED_FW0 offered_fw1=$MEASURE_OFFERED_FW1 xfrm_tunnel0_packets=$MEASURE_XFRM_TUNNEL0_PACKETS loss_pct=$MEASURE_LOSS teardown=$MEASURE_TEARDOWN consumed_fw0=$MEASURE_CONSUMED_FW0 consumed_fw1=$MEASURE_CONSUMED_FW1 adjudicated_fw0=$MEASURE_ADJUDICATED_FW0 adjudicated_fw1=$MEASURE_ADJUDICATED_FW1 reinjected_fw0=$MEASURE_REINJECTED_FW0 reinjected_fw1=$MEASURE_REINJECTED_FW1 written_fw0=$MEASURE_WRITTEN_FW0 written_fw1=$MEASURE_WRITTEN_FW1 uncertain_fw0=$MEASURE_UNCERTAIN_FW0 uncertain_fw1=$MEASURE_UNCERTAIN_FW1 late_completions_fw0=$MEASURE_LATE_COMPLETIONS_FW0 late_completions_fw1=$MEASURE_LATE_COMPLETIONS_FW1 timeouts_fw0=$MEASURE_TIMEOUTS_FW0 timeouts_fw1=$MEASURE_TIMEOUTS_FW1 stale_fw0=$MEASURE_STALE_FW0 stale_fw1=$MEASURE_STALE_FW1 cancelled_fw0=$MEASURE_CANCELLED_FW0 cancelled_fw1=$MEASURE_CANCELLED_FW1 refused_fw0=$MEASURE_REFUSED_FW0 refused_fw1=$MEASURE_REFUSED_FW1 delivered_available_fw0=$MEASURE_DELIVERED_AVAILABLE_FW0 delivered_available_fw1=$MEASURE_DELIVERED_AVAILABLE_FW1 provenance_fw0=$MEASURE_PROVENANCE_FW0 provenance_fw1=$MEASURE_PROVENANCE_FW1 queue_economics_fw0=$MEASURE_QUEUE_ECON_FW0 queue_economics_fw1=$MEASURE_QUEUE_ECON_FW1" VOID \
        "measurement-incomplete:verdict-flip-unimplemented;fw0=${MEASURE_REASON_FW0};fw1=${MEASURE_REASON_FW1}" \
        "cell_failed=1 tunnels=8 offered_expected=16 offered_fw0=$MEASURE_OFFERED_FW0 offered_fw1=$MEASURE_OFFERED_FW1 packets=$MEASURE_PACKETS xfrm_tunnel0_packets=$MEASURE_XFRM_TUNNEL0_PACKETS provenance_samples_fw0=$(observer_field "$MEASURE_PROVENANCE_FW0" packet_samples) provenance_samples_fw1=$(observer_field "$MEASURE_PROVENANCE_FW1" packet_samples) provenance_mismatch_fw0=$(observer_field "$MEASURE_PROVENANCE_FW0" mismatch) provenance_mismatch_fw1=$(observer_field "$MEASURE_PROVENANCE_FW1" mismatch) queue_instances=$(observer_field "$MEASURE_QUEUE_ECON_FW0" queue_instances) queue_instances_fw1=$(observer_field "$MEASURE_QUEUE_ECON_FW1" queue_instances) consumed_fw0=$MEASURE_CONSUMED_FW0 consumed_fw1=$MEASURE_CONSUMED_FW1 adjudicated_fw0=$MEASURE_ADJUDICATED_FW0 adjudicated_fw1=$MEASURE_ADJUDICATED_FW1 reinjected_fw0=$MEASURE_REINJECTED_FW0 reinjected_fw1=$MEASURE_REINJECTED_FW1 written_fw0=$MEASURE_WRITTEN_FW0 written_fw1=$MEASURE_WRITTEN_FW1 uncertain_fw0=$MEASURE_UNCERTAIN_FW0 uncertain_fw1=$MEASURE_UNCERTAIN_FW1 late_completions_fw0=$MEASURE_LATE_COMPLETIONS_FW0 late_completions_fw1=$MEASURE_LATE_COMPLETIONS_FW1 timeouts_fw0=$MEASURE_TIMEOUTS_FW0 timeouts_fw1=$MEASURE_TIMEOUTS_FW1 stale_fw0=$MEASURE_STALE_FW0 stale_fw1=$MEASURE_STALE_FW1 cancelled_fw0=$MEASURE_CANCELLED_FW0 cancelled_fw1=$MEASURE_CANCELLED_FW1 refused_fw0=$MEASURE_REFUSED_FW0 refused_fw1=$MEASURE_REFUSED_FW1 delivered_available_fw0=$MEASURE_DELIVERED_AVAILABLE_FW0 delivered_available_fw1=$MEASURE_DELIVERED_AVAILABLE_FW1 delivered_fw0=$MEASURE_DELIVERED_FW0 delivered_fw1=$MEASURE_DELIVERED_FW1 loss_pct=$MEASURE_LOSS restore_clean=$MEASURE_TEARDOWN"
else
    emit_cell g2_9506_capture_8t 'r6 §5.1' '8-tunnel routed-inet capture cost and provenance validation' \
        "fixture_ready=$MEASURE_READY queues_fw0=$MEASURE_QUEUE_TOTAL queues_fw1=$MEASURE_QUEUE_TOTAL_NODE1 packets=$MEASURE_PACKETS offered_fw0=$MEASURE_OFFERED_FW0 offered_fw1=$MEASURE_OFFERED_FW1 xfrm_tunnel0_packets=$MEASURE_XFRM_TUNNEL0_PACKETS loss_pct=$MEASURE_LOSS teardown=$MEASURE_TEARDOWN" VOID \
        "${MEASURE_REASON:-fixture-measurement-failed}" \
        "cell_failed=1 tunnels=8 offered_expected=16 offered_fw0=$MEASURE_OFFERED_FW0 offered_fw1=$MEASURE_OFFERED_FW1 packets=$MEASURE_PACKETS xfrm_tunnel0_packets=$MEASURE_XFRM_TUNNEL0_PACKETS provenance_mismatch=0 loss_pct=$MEASURE_LOSS restore_clean=$MEASURE_TEARDOWN"
fi
emit_cell g2_9506_vrf_overhead 'r6 §5.1' 'mandatory live VRF refusal overhead: pre-close status quo, ACKed host fence, post-close DROP' \
    "VRF scope census test_created=0 attached=0; transition workload/latency samples were not executed" VOID \
    "measurement-incomplete:test-vrf-not-created-by-fixture" \
    "cell_failed=1 preclose_samples=0 fence_ack_samples=0 postclose_samples=0 input_queue_hits=0 vrf_test_created=0 vrf_attached=0"
for shape in v4_native v4_nat_t v6_native v6_nat_t; do
    for tunnels in 8 16 32; do
        g2_emit_measured "$shape" "$tunnels"
    done
done
emit_cell g2_9506_queue_economics 'r6 §5.1' '32-tunnel admission prices 128 queue/socket instances, buffers, FDs, rotation and teardown' \
    "retained v4_native 32-tunnel observer ready=$QUEUE32_READY fw0=$QUEUE32_ECON_FW0 fw1=$QUEUE32_ECON_FW1; buffer reservations/rotation/teardown ownership are not exposed" VOID \
    "measurement-incomplete:queue-buffer-and-rotation-observer-unavailable" \
    "cell_failed=1 tunnels=32 observer_ready=$QUEUE32_READY queue_instances=$(observer_field "$QUEUE32_ECON_FW0" queue_instances) queue_instances_fw1=$(observer_field "$QUEUE32_ECON_FW1" queue_instances) fd_count=$(observer_field "$QUEUE32_ECON_FW0" fd_count) fd_count_fw1=$(observer_field "$QUEUE32_ECON_FW1" fd_count) queue_pending=$(observer_field "$QUEUE32_ECON_FW0" queue_pending) queue_pending_fw1=$(observer_field "$QUEUE32_ECON_FW1" queue_pending) queue_drops=$(observer_field "$QUEUE32_ECON_FW0" queue_drops) queue_drops_fw1=$(observer_field "$QUEUE32_ECON_FW1" queue_drops) recv_buffers_mib=0 recv_buffers_known=0 socket_buffers_mib=0 socket_buffers_known=0 rotation_overlap=0 rotation_known=0 teardown_known=0"

# Full restore/residue proof.  No temporary fixture is created by this
# conservative first live cell; deployment is intentionally outside config
# state.  The snapshots still prove that both nodes have no config residue.
snapshot_node "$NODE0" "$POST0" || true
snapshot_node "$NODE1" "$POST1" || true
normalize_config "$POST0" >"$POST0.norm" 2>/dev/null || :
normalize_config "$POST1" >"$POST1.norm" 2>/dev/null || :
restore0=0; restore1=0
if [[ -s "$BASE0.norm" && -s "$POST0.norm" ]] && cmp -s "$BASE0.norm" "$POST0.norm"; then restore0=1; fi
if [[ -s "$BASE1.norm" && -s "$POST1.norm" ]] && cmp -s "$BASE1.norm" "$POST1.norm"; then restore1=1; fi
residue0=0; residue1=0
residue_probe_error=0
check_residue() {
    local node="$1" out rc
    out="$(remote "$node" 'ip -o link show' 2>/dev/null)" || return 2
    if grep -qE 'xpf9506|st9506|vrf-9506|xpf-t12-g2' <<<"$out"; then
        return 1
    fi
    return 0
}
check_residue "$NODE0"; rc=$?
if [[ "$rc" == 0 ]]; then residue0=1; elif [[ "$rc" == 2 ]]; then residue_probe_error=1; fi
check_residue "$NODE1"; rc=$?
if [[ "$rc" == 0 ]]; then residue1=1; elif [[ "$rc" == 2 ]]; then residue_probe_error=1; fi
printf 'T12_G2_RESTORE fw0_config_cmp=%s fw1_config_cmp=%s fw0_residue_clear=%s fw1_residue_clear=%s residue_probe_error=%s archive=%s\n' \
    "$restore0" "$restore1" "$residue0" "$residue1" "$residue_probe_error" "$ARCHIVE_DIR"

restore_ok=1
if [[ "$restore0" != 1 || "$restore1" != 1 || "$residue0" != 1 || "$residue1" != 1 ||
      "$residue_probe_error" != 0 || "$T12_FIXTURE_RESTORE_OK" != 1 ||
      "$ACTIVE_FIXTURE_SETUP" != 0 ]]; then
    restore_ok=0
    echo "T12_G2_RESTORE FAIL (configuration/fixture/residue mismatch on one or both nodes)" >&2
fi

# Only now, after both node snapshots and residue checks, write the ledger
# rows.  A failed restore demotes every would-be result to an explicit VOID.
CELL_BUFFER_ONLY=0
CELL_COUNT=0
CELL_VOID=0
CELL_FAIL=0
CELL_PASS=0
while IFS=$'\t' read -r gate section predicate observed verdict reason metrics; do
    [[ -n "${gate:-}" ]] || continue
    if [[ "$restore_ok" != 1 ]]; then
        verdict=VOID
        reason=env-void
        observed="${observed};restore-failed"
        metrics="${metrics} restore_clean=0"
    fi
    emit_cell "$gate" "$section" "$predicate" "$observed" "$verdict" "$reason" "$metrics"
done <"$CELL_ROWS_FILE"
row_count_ok=1
if [[ "$CELL_COUNT" != 30 ]]; then
    row_count_ok=0
    echo "T12_G2_RESTORE FAIL (expected 30 ledger rows, got $CELL_COUNT)" >&2
fi
printf 'T12_G2_SUMMARY cells=%s pass=%s fail=%s void=%s exe_check=%s archive=%s\n' \
    "$CELL_COUNT" "$CELL_PASS" "$CELL_FAIL" "$CELL_VOID" "$EXE_CHECK" "$ARCHIVE_DIR"
if [[ "$restore_ok" != 1 || "$row_count_ok" != 1 ]]; then exit 1; fi
if ((CELL_FAIL > 0)); then exit 1; fi
if ((CELL_VOID > 0)); then exit 2; fi
exit 0
