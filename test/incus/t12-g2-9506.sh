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
    parser_dir="$(mktemp -d)"
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
    rm -rf "$parser_dir"
    if [[ "$fail" == 0 && "$pass" == 18 ]]; then
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
    # directions with the real peer/inner addresses and retain raw output.
    # The current workload is an inner-index-0 smoke probe.  Keep its XFRM
    # state delta explicitly tunnel-scoped; it must not stand in for a
    # per-tunnel G2 workload.
    local shape="$1" count="$2" dir="$3" family inner peer_out lan_out lan6
    local fw0_before="$dir/xfrm-fw0-before.txt" fw1_before="$dir/xfrm-fw1-before.txt"
    local fw0_after="$dir/xfrm-fw0-after.txt" fw1_after="$dir/xfrm-fw1-after.txt"
    local before_packets after_packets
    family="$(fix9506_shape_family "$shape")"
    inner="$(fix9506_inner4_ip 0)"
    lan_out="$dir/lan-to-peer.txt"
    peer_out="$dir/peer-to-lan.txt"
    fix9506_remote "$FIX9506_NODE0" 'ip -s xfrm state' >"$fw0_before" 2>&1 || :
    fix9506_remote "$FIX9506_NODE1" 'ip -s xfrm state' >"$fw1_before" 2>&1 || :
    if [[ "$family" == v4 ]]; then
        fix9506_remote "$FIX9506_LAN_REF" "ip -4 route get $inner; ping -c 4 -W 2 $inner" >"$lan_out" 2>&1 || :
        fix9506_remote "$FIX9506_PEER_REF" "ping -c 4 -W 2 -I $inner $LAN_HOST_IP" >"$peer_out" 2>&1 || :
    else
        inner="$(fix9506_inner6_ip 0)"
        lan6="$(fix9506_remote "$FIX9506_LAN_REF" 'ip -6 -o addr show scope global | sed -n "1{s/.*inet6 \([^/ ]*\)\/.*/\1/p;}"' 2>/dev/null || true)"
        fix9506_remote "$FIX9506_LAN_REF" "ip -6 route get $inner; ping -6 -c 4 -W 2 $inner" >"$lan_out" 2>&1 || :
        fix9506_remote "$FIX9506_PEER_REF" "ping -6 -c 4 -W 2 -I $inner ${lan6:-$LAN_VIP6}" >"$peer_out" 2>&1 || :
    fi
    fix9506_remote "$FIX9506_NODE0" 'ip -s xfrm state' >"$fw0_after" 2>&1 || :
    fix9506_remote "$FIX9506_NODE1" 'ip -s xfrm state' >"$fw1_after" 2>&1 || :
    before_packets=$(( $(fix9506_count_xfrm_packets "$fw0_before") + $(fix9506_count_xfrm_packets "$fw1_before") ))
    after_packets=$(( $(fix9506_count_xfrm_packets "$fw0_after") + $(fix9506_count_xfrm_packets "$fw1_after") ))
    MEASURE_XFRM_TUNNEL0_PACKETS=$((after_packets - before_packets))
    ((MEASURE_XFRM_TUNNEL0_PACKETS < 0)) && MEASURE_XFRM_TUNNEL0_PACKETS=0
    local lan_ok=0 peer_ok=0
    grep -Eq '(^|[[:space:],])0% packet loss' "$lan_out" 2>/dev/null && lan_ok=1 || :
    grep -Eq '(^|[[:space:],])0% packet loss' "$peer_out" 2>/dev/null && peer_ok=1 || :
    MEASURE_LAN_OK="$lan_ok"
    MEASURE_PEER_OK="$peer_ok"
    MEASURE_PACKETS=$((lan_ok * 4 + peer_ok * 4))
    MEASURE_LOSS=0
    ((lan_ok == 1 && peer_ok == 1)) || MEASURE_LOSS=100
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
    MEASURE_LOSS=100
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
    MEASURE_QUEUE_CLASSES="$(fix9506_divert_queues "$dir/measure-fw0-ruleset.json")"
    MEASURE_QUEUE_CLASSES_NODE1="$(fix9506_divert_queues "$dir/measure-fw1-ruleset.json")"
    read -r _ _ _ _ MEASURE_QUEUE_TOTAL <<<"$MEASURE_QUEUE_CLASSES"
    read -r _ _ _ _ MEASURE_QUEUE_TOTAL_NODE1 <<<"$MEASURE_QUEUE_CLASSES_NODE1"
    if [[ "$MEASURE_QUEUE_TOTAL" == "$MEASURE_QUEUE_EXPECT" &&
          "$MEASURE_QUEUE_TOTAL_NODE1" == "$MEASURE_QUEUE_EXPECT" ]]; then
        MEASURE_QUEUE_BOTH=1
    fi
    fixture_measure_traffic "$shape" "$count" "$dir"
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
        sed -E '/^set security (ike|ipsec)$/d; /^set security address-book global$/d'
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
fixture=0
if [[ "$T12_FIXTURE_SETUP" == 1 && "$has_st" == 1 && "$has_sa" == 1 && "$has_divert" == 1 ]]; then fixture=1; fi
printf 'T12_G2_PRECONDITIONS stn=%s stn_fw0=%s stn_fw1=%s xfrm_sa=%s xfrm_sa_fw0=%s xfrm_sa_fw1=%s divert_table=%s fence_table=%s q0_mark_surface=%s ruleset_fw0_readable=%s ruleset_fw1_readable=%s complete_fixture=%s\n' \
    "$has_st" "$has_st_fw0" "$has_st_fw1" "$has_sa" "$has_sa_fw0" "$has_sa_fw1" "$has_divert" "$has_fence" "$has_q0" "$F0_READ" "$F1_READ" "$fixture"
T12_TRAFFIC_PACKETS=0
T12_TRAFFIC_LOSS=100
T12_TRAFFIC_XFRM_TUNNEL0_PACKETS=0
T12_TRAFFIC_LAN_OK=0
T12_TRAFFIC_PEER_OK=0
if [[ "$T12_FIXTURE_SETUP" == 1 ]]; then
    T12_TRAFFIC_DIR="$T12_FIXTURE_DIR/traffic"
    mkdir -p "$T12_TRAFFIC_DIR"
    fixture_measure_traffic "$T12_FIXTURE_SHAPE" "$T12_FIXTURE_COUNT" "$T12_TRAFFIC_DIR"
    T12_TRAFFIC_XFRM_TUNNEL0_PACKETS="$MEASURE_XFRM_TUNNEL0_PACKETS"
    T12_TRAFFIC_PACKETS="$MEASURE_PACKETS"
    T12_TRAFFIC_LOSS="$MEASURE_LOSS"
    T12_TRAFFIC_LAN_OK="$MEASURE_LAN_OK"
    T12_TRAFFIC_PEER_OK="$MEASURE_PEER_OK"
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
        'both nodes readable; base chain shape observed but dynamic armed pinholes were not parsed' VOID \
        "measurement-incomplete:exact-armed-pinhole-set" \
        "cell_failed=1 fence_chain_exact=1 fence_both_nodes=1 pinholes_validated=0"
else
    emit_cell t12_9506_fence_shape 'r6 §5.2.1' 'inet+bridge fence exact shape/policy DROP' \
        'xpf_transit_barrier absent from observed ruleset or observer unavailable' VOID "$LIVE_REASON" \
        "cell_failed=1 fence_chain_exact=0 fence_both_nodes=0 pinholes_validated=0"
fi
if [[ "$has_divert" == 1 ]]; then
    emit_cell t12_9506_divert_order 'r6 §5.2.2-§5.2.3' 'divert chains at P_divert before filter fence; four provenance classes' \
        "queue classes counted ($F0_IF/$F0_II/$F0_BF/$F0_BI) but per-rule provenance and same-priority-chain absence were not parsed" VOID \
        "measurement-incomplete:exact-provenance-rule-set" \
        "cell_failed=1 divert_table=1 provenance_classes=0 priority_divert=-175 priority_fence=0"
else
    emit_cell t12_9506_divert_order 'r6 §5.2.2-§5.2.3' 'divert chains at P_divert before filter fence; four provenance classes' \
        'xpf_ipsec_divert absent from observed ruleset or observer unavailable' VOID "$LIVE_REASON" \
        "cell_failed=1 divert_table=0 provenance_classes=0 priority_divert=0 priority_fence=0"
fi
if [[ "$has_q0" == 1 && "$T12_TRAFFIC_PACKETS" -gt 0 ]]; then
    emit_cell t12_9506_no_bypass 'r6 §5.2.4-§5.2.5' 'q0 exact mark admits; q1/wrong mark and resumed xfrmi ACCEPT remain DROP' \
        "bidirectional decrypted delivery observed packets=$T12_TRAFFIC_PACKETS; xfrm_tunnel0_state_delta=$T12_TRAFFIC_XFRM_TUNNEL0_PACKETS; q0/wrong-mark/resumption matrix not injected" VOID \
        "measurement-incomplete:no-bypass-matrix" \
        "cell_failed=1 q0_mark_surface=1 packet_rows=$T12_TRAFFIC_PACKETS xfrm_tunnel0_packets=$T12_TRAFFIC_XFRM_TUNNEL0_PACKETS lan_to_peer=$T12_TRAFFIC_LAN_OK peer_to_lan=$T12_TRAFFIC_PEER_OK"
else
    emit_cell t12_9506_no_bypass 'r6 §5.2.4-§5.2.5' 'q0 exact mark admits; q1/wrong mark and resumed xfrmi ACCEPT remain DROP' \
        "${PREASON:-q0 mark surface or bidirectional traffic absent}" VOID "$LIVE_REASON" \
        "cell_failed=1 q0_mark_surface=$has_q0 packet_rows=$T12_TRAFFIC_PACKETS xfrm_tunnel0_packets=$T12_TRAFFIC_XFRM_TUNNEL0_PACKETS"
fi
emit_cell t12_9506_vrf_refusal 'r6 §5.2.5a' 'VRF/l3mdev enslaving revokes permit and publishes ACKed host fence' "${PREASON:-requires test VRF + owned stN fixture}" VOID "$LIVE_REASON" \
    "cell_failed=1 vrf_attach=0 fence_ack=0 conntrack_ack=0"
emit_cell t12_9506_coexistence_order 'r6 §5.2.3' 'both-family divert priority precedes filter; no same-priority base chain; mixed OPEN generation forbidden' "$LIVE_REASON" VOID "$LIVE_REASON" \
    "cell_failed=1 inet_order=0 bridge_order=0 mixed_open=0 rotation_budget_ms=0"
emit_cell t12_9506_provenance_metadata 'r6 §5.2.3-§5.2.4' 'queue-id, nfgen_family, hook, ifindex, owner and stN agree for every packet' "$LIVE_REASON" VOID "$LIVE_REASON" \
    "cell_failed=1 packets=0 provenance_mismatch=0"
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
g2_emit_measured() {
    local shape="$1" tunnels="$2" gate="g2_9506_${shape}_${tunnels}"
    local observed
    if run_fixture_measure "$shape" "$tunnels" g2; then
        local qif qii qbf qbi qt
        read -r qif qii qbf qbi qt <<<"$MEASURE_QUEUE_CLASSES"
        observed="fixture_ready=$MEASURE_READY queues_fw0=$MEASURE_QUEUE_TOTAL queues_fw1=$MEASURE_QUEUE_TOTAL_NODE1 queue_classes_fw0=${qif}/${qii}/${qbf}/${qbi} packets=$MEASURE_PACKETS xfrm_tunnel0_packets=$MEASURE_XFRM_TUNNEL0_PACKETS loss_pct=$MEASURE_LOSS teardown=$MEASURE_TEARDOWN"
        emit_cell "$gate" 'r6 §5.1' \
            "${shape} routed-inet real-SA workload at ${tunnels} tunnels with provenance and non-tunnel overhead" \
            "$observed" VOID "measurement-incomplete:provenance-and-overhead-observer-unavailable" \
            "cell_failed=1 tunnels=$tunnels offered=8 observed=$MEASURE_PACKETS xfrm_tunnel0_packets=$MEASURE_XFRM_TUNNEL0_PACKETS provenance_mismatch=0 overhead_ns=0 queue_instances=$MEASURE_QUEUE_TOTAL queue_instances_fw1=$MEASURE_QUEUE_TOTAL_NODE1 loss_pct=$MEASURE_LOSS restore_clean=$MEASURE_TEARDOWN"
    else
        observed="fixture_ready=$MEASURE_READY queues_fw0=$MEASURE_QUEUE_TOTAL queues_fw1=$MEASURE_QUEUE_TOTAL_NODE1 packets=$MEASURE_PACKETS xfrm_tunnel0_packets=$MEASURE_XFRM_TUNNEL0_PACKETS loss_pct=$MEASURE_LOSS teardown=$MEASURE_TEARDOWN"
        emit_cell "$gate" 'r6 §5.1' \
            "${shape} routed-inet real-SA workload at ${tunnels} tunnels with provenance and non-tunnel overhead" \
            "$observed" VOID "${MEASURE_REASON:-fixture-measurement-failed}" \
            "cell_failed=1 tunnels=$tunnels offered=8 observed=$MEASURE_PACKETS xfrm_tunnel0_packets=$MEASURE_XFRM_TUNNEL0_PACKETS provenance_mismatch=0 overhead_ns=0 queue_instances=$MEASURE_QUEUE_TOTAL queue_instances_fw1=$MEASURE_QUEUE_TOTAL_NODE1 loss_pct=$MEASURE_LOSS restore_clean=$MEASURE_TEARDOWN"
    fi
}
emit_cell g2_9506_fence_baseline 'r6 §5.1' 'fence-alone baseline with concurrent routed+bridged non-tunnel traffic' \
    'same-day baseline workload/latency observer not implemented' VOID \
    "measurement-incomplete:fence-baseline-observer-unavailable" \
    "cell_failed=1 baseline_samples=0 offered=0 observed=0"
emit_cell g2_9506_divert_detached 'r6 §5.1' 'fence+divert detached-listener overhead delta' \
    'detached-listener workload/latency observer not implemented' VOID \
    "measurement-incomplete:detached-listener-observer-unavailable" \
    "cell_failed=1 baseline_samples=0 detached_samples=0 overhead_ns=0"
emit_cell g2_9506_divert_idle 'r6 §5.1' 'fence+divert attached-idle listener overhead delta' \
    'attached-idle listener workload/latency observer not implemented' VOID \
    "measurement-incomplete:idle-listener-observer-unavailable" \
    "cell_failed=1 detached_samples=0 idle_samples=0 overhead_ns=0"
if run_fixture_measure v4_native 8 g2-capture; then
    emit_cell g2_9506_capture_8t 'r6 §5.1' '8-tunnel routed-inet capture cost and provenance validation' \
        "fixture_ready=$MEASURE_READY queues_fw0=$MEASURE_QUEUE_TOTAL queues_fw1=$MEASURE_QUEUE_TOTAL_NODE1 packets=$MEASURE_PACKETS xfrm_tunnel0_packets=$MEASURE_XFRM_TUNNEL0_PACKETS loss_pct=$MEASURE_LOSS teardown=$MEASURE_TEARDOWN" VOID \
        "measurement-incomplete:provenance-observer-unavailable" \
        "cell_failed=1 tunnels=8 packets=$MEASURE_PACKETS xfrm_tunnel0_packets=$MEASURE_XFRM_TUNNEL0_PACKETS provenance_mismatch=0"
else
    emit_cell g2_9506_capture_8t 'r6 §5.1' '8-tunnel routed-inet capture cost and provenance validation' \
        "fixture_ready=$MEASURE_READY queues_fw0=$MEASURE_QUEUE_TOTAL queues_fw1=$MEASURE_QUEUE_TOTAL_NODE1 packets=$MEASURE_PACKETS xfrm_tunnel0_packets=$MEASURE_XFRM_TUNNEL0_PACKETS loss_pct=$MEASURE_LOSS teardown=$MEASURE_TEARDOWN" VOID \
        "${MEASURE_REASON:-fixture-measurement-failed}" \
        "cell_failed=1 tunnels=8 xfrm_tunnel0_packets=$MEASURE_XFRM_TUNNEL0_PACKETS packets=$MEASURE_PACKETS provenance_mismatch=0"
fi
emit_cell g2_9506_vrf_overhead 'r6 §5.1' 'mandatory live VRF refusal overhead: pre-close status quo, ACKed host fence, post-close DROP' \
    'live VRF/l3mdev refusal transition observer not implemented' VOID \
    "measurement-incomplete:vrf-refusal-observer-unavailable" \
    "cell_failed=1 preclose_samples=0 fence_ack_samples=0 postclose_samples=0 input_queue_hits=0"
emit_cell g2_9506_queue_economics 'r6 §5.1' '32-tunnel admission prices 128 queue/socket instances, buffers, FDs, rotation and teardown' \
    'queue count is collected per fixture shape; FD/buffer/rotation observer not implemented' VOID \
    "measurement-incomplete:queue-economics-observer-unavailable" \
    "cell_failed=1 tunnels=32 queue_instances=0 recv_buffers_mib=0 fd_peak=0 rotation_overlap=0"
for shape in v4_native v4_nat_t v6_native v6_nat_t; do
    for tunnels in 8 16 32; do
        g2_emit_measured "$shape" "$tunnels"
    done
done

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
