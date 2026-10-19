#!/usr/bin/env bash
# #10136/#11416 — wire_routing_separation: live VRF-miss deny gate plus a
# populated-RI positive leg on the same IPv4/UDP shape.
#
# The product-owned LAN ingress (reth1 / ge-0-0-1, XDP-owned, transit-fence
# admitted) is the only offer path. The gate first sends an exact-tuple control
# from the LAN host through its existing main-table VLAN-80 path, then creates
# an EMPTY RI and commits an exact-match input FBF term for the probe tuple.
#
# After that commit, one sender interleaves an unsteered near-miss control
# with the probe: same addresses, protocol, direction, and capture filter,
# differing only in destination port, so only the probe selects the RI. The
# probe reaches the userspace route miss and is denied. `WIRE_BROKEN_FIXTURE=1`
# inserts a temporary exact explicit `accept` term ahead of the FBF steer,
# sending the probe through the already-proven main-table route to the peer.
# This does not exercise fallthrough after an empty selected-VRF lookup.
# Both controls and the interleaved near-miss/probe run under one peer-side
# tcpdump window; the near-miss supplies liveness during the probe and for the
# first 100 controls immediately after it.
#
# #11416 populated-RI positive leg (v6 twin, TCP, and return-path legs remain
# blocked on the maintainer ruling recorded in the issue): the gate adds a
# test-owned GRE member to the RI (underlay WAN-source -> DEST_IP; outer
# transport deliberately left in main) plus an exact /32 static route for the
# probe destination, then re-offers the steered tuple with a FRESH source port
# interleaved with a fresh near-miss control (tags R/B). The probe MUST reach
# the peer encapsulated in the RI member's GRE: this window's capture filter
# admits the probe only in proto-47 form, so a main-table fallback cannot
# score as a pass. Deleting only the static route and re-offering another
# fresh tuple (tags D/E) MUST stop delivery in any form — the populated leg
# FAILs when the RI route is removed. Every config write uses the gate's
# existing per-statement commit/delete pattern; cleanup deletes only owned
# leaves, and an authenticated FAIL survives a failed restore.
#
# The GRE member lives in its OWN test-owned zone (wire-vrf), never in the
# existing `wan` zone: `wan` also carries the MAIN-context reth0.50/.80, so
# adding an RI member there makes the zone span two routing contexts and the
# #11061 strict validator (validateFabricZoneRoutingInstanceAmbiguityStrict)
# rejects the commit — the exact failure the 2026-10-16 live attempt hit.
# The dedicated zone carries its own lan->wire-vrf permit and lan->wire-vrf
# interface-SNAT rule-set, mirroring the existing lan->sfmix pair for the
# product GRE fixture, so policy/NAT selection for the new egress is
# explicit instead of borrowed from a zone the packet does not egress into.
#
# Successful sender sendto calls are the offered-frame count. Sender and
# capture mirror wire-conntrack-lifecycle: LAN host offers, target captures on
# eth0. The target is the managed peer, not the host-side fence.
#
# Usage:
#   ./test/incus/wire-routing-separation.sh
#   ./test/incus/wire-routing-separation.sh --fixture transcript.tsv
#   ./test/incus/wire-routing-separation.sh --selftest
#
# Fixture format: one `probe_offered=N probe_leaked=N
# precommit_control_offered=N precommit_control_observed=N
# near_miss_offered=N near_miss_observed=N near_miss_tail_observed=N
# populated_offered=N populated_observed=N populated_control_offered=N
# populated_control_observed=N removed_offered=N removed_observed=N
# removed_control_offered=N removed_control_observed=N cksum_bad=N` line.
# Exit: 0 PASS, 1 FAIL, 2 VOID. The tail covers the first 100 controls after probes.
set -uo pipefail

MODE=live
FIXTURE=""
while (($#)); do
    case "$1" in
    --selftest) MODE=selftest ;;
    --fixture) MODE=fixture; shift; FIXTURE="${1:-}" ;;
    -h|--help) sed -n '1,/^# Exit: 0 PASS/{p}' "$0"; exit 0 ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *) echo "unexpected argument: $1" >&2; exit 2 ;;
    esac
    shift
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/incus/wire-gate-lib.sh
source "${SCRIPT_DIR}/wire-gate-lib.sh"
cli_commit_succeeded() {
    local out="$1"
    grep -qE '^[[:space:]]*configuration check succeeds[[:space:]]*$' <<<"$out" &&
        grep -qE '^[[:space:]]*commit complete([: ].*)?$' <<<"$out"
}
canonical_set_snapshot() {
    # Only these two sibling flow statements are known to be semantically
    # commutative on the managed peers. Preserve every other statement and its
    # position; a global sort would hide order-sensitive restore drift.
    awk '
        {
            if ($0 !~ /^set /) next
            lines[++n] = $0
            if ($0 == "set security flow allow-dns-reply") dns++
            if ($0 == "set security flow allow-embedded-icmp") embedded++
        }
        END {
            placed = 0
            for (i = 1; i <= n; i++) {
                if (lines[i] == "set security flow allow-dns-reply" ||
                    lines[i] == "set security flow allow-embedded-icmp") {
                    if (!placed) {
                        for (j = 0; j < dns; j++) print "set security flow allow-dns-reply"
                        for (j = 0; j < embedded; j++) print "set security flow allow-embedded-icmp"
                        placed = 1
                    }
                } else {
                    print lines[i]
                }
            }
        }
    ' "$1"
}



if [[ "$MODE" == selftest ]]; then
    pass=0
    fail=0
    window_cell() {
        local label="$1" want_v="$2" want_rc="$3"
        shift 3
        local out rc v
        out=$(wire_routing_separation_window_verdict "$@")
        rc=$?
        v=$(awk '{print $3}' <<<"$out")
        if [[ "$v" == "$want_v" && "$rc" == "$want_rc" &&
            "$out" == WIRE_GATE\ wire_routing_separation\ * ]]; then
            echo "  PASS  $label"
            pass=$((pass + 1))
        else
            echo "  FAIL  $label (got '$out' rc=$rc)"
            fail=$((fail + 1))
        fi
    }
    reason_cell() {
        local label="$1" want_reason="$2"
        shift 2
        local out rc v
        out=$(wire_routing_separation_window_verdict "$@")
        rc=$?
        v=$(awk '{print $3}' <<<"$out")
        if [[ "$v" == VOID && "$rc" == 2 &&
            "$out" == *"reason=$want_reason"* &&
            "$out" == WIRE_GATE\ wire_routing_separation\ * ]]; then
            echo "  PASS  $label"
            pass=$((pass + 1))
        else
            echo "  FAIL  $label (got '$out' rc=$rc)"
            fail=$((fail + 1))
        fi
    }
    marker_cell() {
        local label="$1" want="$2" text="$3" got
        if cli_commit_succeeded "$text"; then got=0; else got=1; fi
        if [[ "$got" == "$want" ]]; then
            echo "  PASS  $label"
            pass=$((pass + 1))
        else
            echo "  FAIL  $label (got rc=$got)"
            fail=$((fail + 1))
        fi
    }
    marker_cell "bare commit marker" 0 $'configuration check succeeds\ncommit complete'
    set_a=$(mktemp "${TMPDIR:-/var/worktrees/.cache/tmpdir}/xpf-10136-set-a.XXXXXX")
    set_b=$(mktemp "${TMPDIR:-/var/worktrees/.cache/tmpdir}/xpf-10136-set-b.XXXXXX")
    set_c=$(mktemp "${TMPDIR:-/var/worktrees/.cache/tmpdir}/xpf-10136-set-c.XXXXXX")
    set_d=$(mktemp "${TMPDIR:-/var/worktrees/.cache/tmpdir}/xpf-10136-set-d.XXXXXX")
    printf '%s\n' \
        'set security flow allow-dns-reply' \
        'set security flow allow-embedded-icmp' >"$set_a"
    printf '%s\n' \
        'set security flow allow-embedded-icmp' \
        'set security flow allow-dns-reply' >"$set_b"
    printf '%s\n' 'set security flow allow-embedded-icmp' >"$set_c"
    printf '%s\n' \
        'cli — connected to xpfd (uptime: 1h)' \
        'Type '\''?'\'' for help' \
        'set security flow allow-dns-reply' \
        'set security flow allow-embedded-icmp' >"$set_d"
    if [[ "$(canonical_set_snapshot "$set_a")" == "$(canonical_set_snapshot "$set_b")" &&
        "$(canonical_set_snapshot "$set_a")" != "$(canonical_set_snapshot "$set_c")" &&
        "$(canonical_set_snapshot "$set_a")" == "$(canonical_set_snapshot "$set_d")" ]]; then
        echo "  PASS  semantic set reorder and CLI banner are restore-equivalent"
        pass=$((pass + 1))
    else
        echo "  FAIL  semantic set reorder and CLI banner are restore-equivalent"
        fail=$((fail + 1))
    fi
    rm -f "$set_a" "$set_b" "$set_c" "$set_d"

    # #11416 fixture-shape guards (source-text, no cluster): the populated
    # GRE member must land in the dedicated wire-vrf zone with its own
    # lan->wire-vrf permit + SNAT, never in the cross-context wan zone.
    # Reverting the zone to wan (or dropping the policy/NAT pair) makes the
    # populated commit collide with the #11061 validator again — these
    # cells are the unit-level proof that cannot happen by construction.
    script_text="$(cat "$0")"
    wan_zone_lines="$(grep 'security-zone wan interfaces' "$0" | grep -vc 'wan_zone_lines' || true)"
    if [[ "$script_text" == *'set security zones security-zone %s interfaces %s'* &&
        "$script_text" == *'from-zone lan to-zone %s policy wire-vrf-allow'* &&
        "$script_text" == *'rule-set lan-to-wire-vrf to zone %s'* &&
        "$wan_zone_lines" == 0 ]]; then
        echo "  PASS  populated GRE member uses dedicated wire-vrf zone, not wan"
        pass=$((pass + 1))
    else
        echo "  FAIL  populated GRE member uses dedicated wire-vrf zone, not wan"
        fail=$((fail + 1))
    fi
    if [[ "$script_text" == *'delete security policies from-zone lan to-zone %s'* &&
        "$script_text" == *'delete security nat source rule-set lan-to-wire-vrf'* &&
        "$script_text" == *'delete security zones security-zone %s'* ]]; then
        echo "  PASS  populated cleanup deletes owned zone policy and SNAT"
        pass=$((pass + 1))
    else
        echo "  FAIL  populated cleanup deletes owned zone policy and SNAT"
        fail=$((fail + 1))
    fi
    marker_cell "summary commit marker" 0 $'configuration check succeeds\ncommit complete: 1 statement(s) changed (1 added, 0 removed)'
    marker_cell "embedded commit marker rejected" 1 $'configuration check succeeds\nerror: commit failed before commit complete'

    if wire_gate_finalizer_selftest; then
        echo "  PASS  cleanup finalizer shields restore"
        pass=$((pass + 1))
    else
        echo "  FAIL  cleanup finalizer shields restore"
        fail=$((fail + 1))
    fi
    # Miss-phase cells carry sound populated/removed suffixes so they also
    # prove the positive legs cannot rescue a FAIL or upgrade a VOID.
    window_cell "clean VRF miss with sound positive legs passes" PASS 0 \
        1500 1000 0 1500 1500 0 1500 1500 1500 1500 1500 1500 1000 0 1500 1500
    window_cell "observed probe leak fails despite sound positive legs" FAIL 1 \
        1500 1000 1 1500 1500 0 1500 1500 1500 1500 1500 1500 1000 0 1500 1500
    reason_cell "precommit control cannot rescue suppressed post-commit near-miss" capture-blind \
        1500 1000 0 1500 1500 0 1500 0 1500 1500 1500 1500 1000 0 1500 1500
    reason_cell "precommit exact-tuple suppression is VOID despite live near-miss" env-void \
        1500 1000 0 1500 0 0 1500 1500 1500 1500 1500 1500 1000 0 1500 1500
    window_cell "short successful ingress burst is VOID" VOID 2 \
        1500 999 0 1500 1500 0 1500 1500 1500 1500 1500 1500 1000 0 1500 1500
    window_cell "leak survives an under-sampled probe offer" FAIL 1 \
        1500 999 1 1000 1000 0 1500 1500 1500 1500 1500 1500 1000 0 1500 1500
    window_cell "checksum corruption fails" FAIL 1 \
        1500 1000 0 1500 1500 1 1500 1500 1500 1500 1500 1500 1000 0 1500 1500
    window_cell "malformed count is VOID" VOID 2 \
        1500 x 0 1500 1500 0 1500 1500 1500 1500 1500 1500 1000 0 1500 1500
    window_cell "1000 early controls cannot replace post-probe tail liveness" VOID 2 \
        0 1000 0 1500 1500 0 1500 1000 1500 1500 1500 1500 1000 0 1500 1500
    window_cell "one observed control in tail proves window liveness" PASS 0 \
        1 1000 0 1500 1500 0 1500 1000 1500 1500 1500 1500 1000 0 1500 1500
    window_cell "probe leak fails without post-probe tail" FAIL 1 \
        0 1000 1 1500 1500 0 1500 1000 1500 1500 1500 1500 1000 0 1500 1500
    # #11416 populated-RI positive cells.
    window_cell "populated probe missing with live control fails (over-deny)" FAIL 1 \
        1500 1000 0 1500 1500 0 1500 1500 1500 0 1500 1500 1000 0 1500 1500
    window_cell "populated probe partial delivery below floor fails" FAIL 1 \
        1500 1000 0 1500 1500 0 1500 1500 1500 999 1500 1500 1000 0 1500 1500
    reason_cell "populated control blind is VOID despite probe delivery" capture-blind \
        1500 1000 0 1500 1500 0 1500 1500 1500 1500 1500 0 1000 0 1500 1500
    reason_cell "populated under-offer is VOID" under-sampled \
        1500 1000 0 1500 1500 0 1500 1500 999 1500 1500 1500 1000 0 1500 1500
    window_cell "steered tuple still delivered after route removal fails" FAIL 1 \
        1500 1000 0 1500 1500 0 1500 1500 1500 1500 1500 1500 1000 7 1500 1500
    reason_cell "removed control blind is VOID" capture-blind \
        1500 1000 0 1500 1500 0 1500 1500 1500 1500 1500 1500 1000 0 1500 0
    window_cell "populated violation survives a miss-phase VOID" FAIL 1 \
        1500 1000 0 1500 0 0 1500 1500 1500 0 1500 1500 1000 0 1500 1500
    window_cell "removed violation survives a blind populated control" FAIL 1 \
        1500 1000 0 1500 1500 0 1500 1500 1500 1500 1500 0 1000 3 1500 1500
    window_cell "missing populated metric argument is VOID" VOID 2 \
        1 1000 0 1500 1500 0 1500 1000

    if python3 "${SCRIPT_DIR}/wire-routing-separation-temporal-selftest.py"; then
        echo "  PASS  post-near-miss outage cannot score PASS"
        pass=$((pass + 1))
    else
        echo "  FAIL  post-near-miss outage regression"
        fail=$((fail + 1))
    fi

    # RED→GREEN proof through the fixture parser/emitter, not just a direct
    # reducer call: stale precommit liveness must not rescue the post-commit
    # near-miss absence; the leak transcript must fail and the clean fixture pass.
    good=$(mktemp "${TMPDIR:-/var/worktrees/.cache/tmpdir}/xpf-10136-good.XXXXXX")
    bad=$(mktemp "${TMPDIR:-/var/worktrees/.cache/tmpdir}/xpf-10136-bad.XXXXXX")
    blind=$(mktemp "${TMPDIR:-/var/worktrees/.cache/tmpdir}/xpf-10136-blind.XXXXXX")
    late=$(mktemp "${TMPDIR:-/var/worktrees/.cache/tmpdir}/xpf-10136-late.XXXXXX")
    missing_tail=$(mktemp "${TMPDIR:-/var/worktrees/.cache/tmpdir}/xpf-10136-missing-tail.XXXXXX")
    missing_positive=$(mktemp "${TMPDIR:-/var/worktrees/.cache/tmpdir}/xpf-10136-missing-positive.XXXXXX")
    printf '%s\n' 'probe_offered=1000 probe_leaked=0 precommit_control_offered=1500 precommit_control_observed=1500 near_miss_offered=1500 near_miss_observed=1500 near_miss_tail_observed=99 populated_offered=1500 populated_observed=1500 populated_control_offered=1500 populated_control_observed=1500 removed_offered=1000 removed_observed=0 removed_control_offered=1500 removed_control_observed=1500 cksum_bad=0' >"$good"
    printf '%s\n' 'probe_offered=1000 probe_leaked=1 precommit_control_offered=1500 precommit_control_observed=1500 near_miss_offered=1500 near_miss_observed=1500 near_miss_tail_observed=99 populated_offered=1500 populated_observed=1500 populated_control_offered=1500 populated_control_observed=1500 removed_offered=1000 removed_observed=0 removed_control_offered=1500 removed_control_observed=1500 cksum_bad=0' >"$bad"
    printf '%s\n' 'probe_offered=1000 probe_leaked=0 precommit_control_offered=1500 precommit_control_observed=1500 near_miss_offered=1500 near_miss_observed=0 near_miss_tail_observed=0 populated_offered=1500 populated_observed=1500 populated_control_offered=1500 populated_control_observed=1500 removed_offered=1000 removed_observed=0 removed_control_offered=1500 removed_control_observed=1500 cksum_bad=0' >"$blind"
    printf '%s\n' 'probe_offered=1000 probe_leaked=0 precommit_control_offered=1500 precommit_control_observed=1500 near_miss_offered=1500 near_miss_observed=1000 near_miss_tail_observed=0 populated_offered=1500 populated_observed=1500 populated_control_offered=1500 populated_control_observed=1500 removed_offered=1000 removed_observed=0 removed_control_offered=1500 removed_control_observed=1500 cksum_bad=0' >"$late"
    sed 's/ near_miss_tail_observed=99//' "$good" >"$missing_tail"
    # Pre-#11416 transcript shape: sound miss metrics, no positive legs. It
    # must VOID, never PASS, so an old fixture cannot certify the extended row.
    sed 's/ populated_offered=1500.*removed_control_observed=1500//' "$good" >"$missing_positive"
    out=$("$0" --fixture "$bad"); rc=$?
    if [[ "$rc" == 1 && "$out" == *'WIRE_GATE wire_routing_separation FAIL reason=--'* ]]; then
        echo "  PASS  leaked-probe transcript fails"
        pass=$((pass + 1))
    else
        echo "  FAIL  leaked-probe transcript did not fail (rc=$rc out=$out)"
        fail=$((fail + 1))
    fi
    out=$("$0" --fixture "$blind"); rc=$?
    if [[ "$rc" == 2 && "$out" == *'WIRE_GATE wire_routing_separation VOID reason=capture-blind'* &&
        "$out" == *'control_observed=0'* && "$out" == *'precommit_control_observed=1500'* ]]; then
        echo "  PASS  suppressed post-commit near-miss is VOID despite precommit control"
        pass=$((pass + 1))
    else
        echo "  FAIL  suppressed near-miss fixture did not VOID (rc=$rc out=$out)"
        fail=$((fail + 1))
    fi
    out=$("$0" --fixture "$good"); rc=$?
    missing_out=$("$0" --fixture "$missing_tail"); missing_rc=$?
    positive_out=$("$0" --fixture "$missing_positive"); positive_rc=$?
    if [[ "$rc" == 0 && "$out" == *'WIRE_GATE wire_routing_separation PASS reason=--'* &&
        "$out" == *'populated_observed=1500'* && "$out" == *'removed_observed=0'* &&
        "$missing_rc" == 2 &&
        "$missing_out" == *'WIRE_GATE wire_routing_separation VOID reason=harness-void'* ]]; then
        echo "  PASS  clean fixture passes; missing tail field is VOID"
        pass=$((pass + 1))
    else
        echo "  FAIL  fixture tail-field behavior mismatch (good rc=$rc out=$out; missing rc=$missing_rc out=$missing_out)"
        fail=$((fail + 1))
    fi
    if [[ "$positive_rc" == 2 &&
        "$positive_out" == *'WIRE_GATE wire_routing_separation VOID reason=harness-void'* ]]; then
        echo "  PASS  pre-#11416 transcript without positive legs is VOID, never PASS"
        pass=$((pass + 1))
    else
        echo "  FAIL  old-shape fixture did not VOID (rc=$positive_rc out=$positive_out)"
        fail=$((fail + 1))
    fi
    out=$("$0" --fixture "$late"); rc=$?
    if [[ "$rc" == 2 && "$out" == *'WIRE_GATE wire_routing_separation VOID reason=capture-blind'* &&
        "$out" == *'control_observed=1000'* ]]; then
        echo "  PASS  late outage cannot use 1000 earlier controls"
        pass=$((pass + 1))
    else
        echo "  FAIL  late outage fixture did not VOID (rc=$rc out=$out)"
        fail=$((fail + 1))
    fi
    rm -f "$good" "$bad" "$blind" "$late" "$missing_tail" "$missing_positive"
    echo "  wire-routing-separation selftest: $pass passed, $fail failed"
    [[ "$fail" -eq 0 && "$pass" -gt 0 ]] || exit 1
    exit 0
fi

if [[ "$MODE" == fixture ]]; then
    if [[ -z "$FIXTURE" || ! -f "$FIXTURE" ]]; then
        echo "usage: $0 --fixture <transcript.tsv>" >&2
        exit 2
    fi
    parsed=$(wire_parse_transcript "$FIXTURE") || {
        printf 'WIRE_GATE wire_routing_separation VOID reason=harness-void probe_offered=0 probe_leaked=0 control_offered=0 control_observed=0 cksum_bad=0 precommit_control_offered=0 precommit_control_observed=0 populated_offered=0 populated_observed=0 populated_control_offered=0 populated_control_observed=0 removed_offered=0 removed_observed=0 removed_control_offered=0 removed_control_observed=0\n'
        exit 2
    }
    # shellcheck disable=SC2034
    eval "$parsed" || {
        printf 'WIRE_GATE wire_routing_separation VOID reason=harness-void probe_offered=0 probe_leaked=0 control_offered=0 control_observed=0 cksum_bad=0 precommit_control_offered=0 precommit_control_observed=0 populated_offered=0 populated_observed=0 populated_control_offered=0 populated_control_observed=0 removed_offered=0 removed_observed=0 removed_control_offered=0 removed_control_observed=0\n'
        exit 2
    }
    po=${probe_offered:-} pl=${probe_leaked:-}
    pco=${precommit_control_offered:-} pcb=${precommit_control_observed:-}
    nmo=${near_miss_offered:-} nmb=${near_miss_observed:-}
    nmt=${near_miss_tail_observed:-} ck=${cksum_bad:-0}
    ro=${populated_offered:-} rb=${populated_observed:-}
    rco=${populated_control_offered:-} rcb=${populated_control_observed:-}
    dof=${removed_offered:-} db=${removed_observed:-}
    eco=${removed_control_offered:-} ecb=${removed_control_observed:-}
    if [[ -z "$po" || -z "$pl" || -z "$pco" || -z "$pcb" ||
        -z "$nmo" || -z "$nmb" || -z "$nmt" ||
        -z "$ro" || -z "$rb" || -z "$rco" || -z "$rcb" ||
        -z "$dof" || -z "$db" || -z "$eco" || -z "$ecb" ]]; then
        printf 'WIRE_GATE wire_routing_separation VOID reason=harness-void probe_offered=0 probe_leaked=0 control_offered=0 control_observed=0 cksum_bad=0 precommit_control_offered=0 precommit_control_observed=0 populated_offered=0 populated_observed=0 populated_control_offered=0 populated_control_observed=0 removed_offered=0 removed_observed=0 removed_control_offered=0 removed_control_observed=0\n'
        exit 2
    fi
    wire_routing_separation_window_verdict "$nmt" "$po" "$pl" "$pco" "$pcb" "$ck" "$nmo" "$nmb" \
        "$ro" "$rb" "$rco" "$rcb" "$dof" "$db" "$eco" "$ecb"
    exit $?
fi

# ── live gate (destructive lock cell) ────────────────────────────────
_CELL_DIR="$SCRIPT_DIR"
# shellcheck source=test/incus/cluster-cell.sh
source "${_CELL_DIR}/cluster-cell.sh"
xpf_enter_destructive_cluster_cell "wire-routing-separation $*" "$0" "$@"
# shellcheck source=test/incus/cluster-env.sh
source "${SCRIPT_DIR}/cluster-env.sh"

INCUS_REMOTE="${INCUS_REMOTE:-loss}"
NODE="${NODE:-${FW0:-${INCUS_REMOTE}:xpf-userspace-fw0}}"
NODE0="${FW0:-${INCUS_REMOTE}:xpf-userspace-fw0}"
NODE1="${FW1:-${INCUS_REMOTE}:xpf-userspace-fw1}"
TARGET="${TARGET:-${INCUS_REMOTE}:xpf-mouse-target}"
RI_NAME="${RI_NAME:-wire-10136}"
[[ "$RI_NAME" =~ ^[A-Za-z][A-Za-z0-9_-]{0,31}$ ]] || {
    printf 'WIRE_GATE wire_routing_separation VOID reason=harness-void probe_offered=0 probe_leaked=0 control_offered=0 control_observed=0 cksum_bad=0 precommit_control_offered=0 precommit_control_observed=0 populated_offered=0 populated_observed=0 populated_control_offered=0 populated_control_observed=0 removed_offered=0 removed_observed=0 removed_control_offered=0 removed_control_observed=0\n'
    exit 2
}
VRF_NAME="${VRF_NAME:-vrf-${RI_NAME}}"
VRF_TABLE=""
DEST_IP="${DEST_IP:-172.16.80.201}"
EGRESS_DEV="${EGRESS_DEV:-ge-0-0-2.80}"
# #11416 populated-RI positive leg. The GRE member is test-owned: its underlay
# source is the FW's own reth0.80 address (outer transport deliberately stays
# in main), its destination is the probe destination (the managed peer), and
# its unit address comes from the 198.18.0.0/15 benchmark range already
# reserved for this fixture family. Absence is checked against both node
# baselines before any write.
WAN_SRC="${WAN_SRC:-172.16.80.8}"
POPULATED_GRE_UNIT="${POPULATED_GRE_UNIT:-gr-0/0/1.0}"
POPULATED_GRE_DEV="${POPULATED_GRE_DEV:-gr-0/0/1}"
POPULATED_GRE_ADDR="${POPULATED_GRE_ADDR:-198.18.117.1}"
LAN_REF="${CLUSTER_LAN_HOST:-${INCUS_REMOTE}:cluster-userspace-host}"
LAN_ADDR="${LAN_ADDR:-${LAN_HOST_IP:-10.0.61.102}}"
LAN_ADDR="${LAN_ADDR%%/*}"
# The exact tuple is attached to the product-owned LAN ingress. The FBF term
# owns the fixed leg; the broken fixture inserts a temporary explicit accept
# term ahead of it, exercising the actual userspace enforcement point.
LAN_DEV="${LAN_DEV:-ge-0-0-1}"
PORT="${PORT:-$((40000 + RANDOM % 20000))}"
NEAR_MISS_PORT=""
PROBE_BURST="${PROBE_BURST:-1000}"
CONTROL_BURST="${CONTROL_BURST:-1500}"
NEAR_MISS_TAIL_SIZE=100
RATE="${RATE:-500}"
STEP_TIMEOUT="${STEP_TIMEOUT:-120}"
REMOTE_PROBE="/tmp/xpf-wire-routing-probe-10136-${BASHPID}"
SG="sg incus-admin -c"

CAP_PID=""
CAPLOG=""
CAPLOG2=""
CAPLOG3=""
RI_OWNED=0
FILTER_OWNED=0
ALLOW_OWNED=0
POP_GRE_OWNED=0
POP_ROUTE_OWNED=0
REMOTE_PROBE_OWNED=0
BASELINE_CAPTURED=0
KERNEL_BASELINE_CAPTURED=0
RESTORE_OK=1
WIRE_GATE_FINAL_OUT=""
WIRE_GATE_FINAL_RC=2
# #11416: an authenticated FAIL must survive a failed restore instead of
# being demoted to RESTORE_VOID (see wire_gate_finalize).
WIRE_GATE_FAIL_STICKY=1

remote() { $SG "incus exec ${NODE} -- bash -lc '$*'"; }
snapshot_node() {
    local n="$1" out="$2"
    printf 'show configuration | display set\nexit\n' |
        $SG "incus exec ${n} -- bash -lc 'cli'" >"$out" 2>&1
}
normalize_config() { canonical_set_snapshot "$1"; }
cli_commit_ri() {
    local action="$1" out
    if [[ "$action" == add ]]; then
        out="$(printf 'configure\nrollback 0\nset routing-instances %s instance-type vrf\ncommit check\ncommit\nexit\nquit\n' "$RI_NAME" |
            $SG "incus exec ${NODE} -- cli" 2>&1)" || {
            printf '%s\n' "$out" >&2
            return 1
        }
    else
        out="$(printf 'configure\nrollback 0\ndelete routing-instances %s\ncommit check\ncommit\nexit\nquit\n' "$RI_NAME" |
            $SG "incus exec ${NODE} -- cli" 2>&1)" || {
            printf '%s\n' "$out" >&2
            return 1
        }
    fi
    if ! cli_commit_succeeded "$out"; then
        printf '%s\n' "$out" >&2
        return 1
    fi
}
cli_commit_probe_filter() {
    local action="$1" out
    if [[ "$action" == add ]]; then
        out="$(printf 'configure\nrollback 0\nset firewall family inet filter sfmix-pbr term wire-10136 from source-address %s/32\nset firewall family inet filter sfmix-pbr term wire-10136 from destination-address %s/32\nset firewall family inet filter sfmix-pbr term wire-10136 from protocol udp\nset firewall family inet filter sfmix-pbr term wire-10136 from destination-port %s\nset firewall family inet filter sfmix-pbr term wire-10136 then routing-instance %s\ninsert firewall family inet filter sfmix-pbr term wire-10136 before term default\ncommit check\ncommit\nexit\nquit\n' "$LAN_ADDR" "$DEST_IP" "$PORT" "$RI_NAME" |
            $SG "incus exec ${NODE} -- cli" 2>&1)" || {
            printf '%s\n' "$out" >&2
            return 1
        }
    else
        out="$(printf 'configure\nrollback 0\ndelete firewall family inet filter sfmix-pbr term wire-10136\ncommit check\ncommit\nexit\nquit\n' |
            $SG "incus exec ${NODE} -- cli" 2>&1)" || {
            printf '%s\n' "$out" >&2
            return 1
        }
    fi
    if ! cli_commit_succeeded "$out"; then
        printf '%s\n' "$out" >&2
        return 1
    fi
}
cli_commit_probe_allow() {
    local action="$1" out
    if [[ "$action" == add ]]; then
        out="$(printf 'configure\nrollback 0\nset firewall family inet filter sfmix-pbr term wire-10136-allow from source-address %s/32\nset firewall family inet filter sfmix-pbr term wire-10136-allow from destination-address %s/32\nset firewall family inet filter sfmix-pbr term wire-10136-allow from protocol udp\nset firewall family inet filter sfmix-pbr term wire-10136-allow from destination-port %s\nset firewall family inet filter sfmix-pbr term wire-10136-allow then accept\ninsert firewall family inet filter sfmix-pbr term wire-10136-allow before term wire-10136\ncommit check\ncommit\nexit\nquit\n' "$LAN_ADDR" "$DEST_IP" "$PORT" |
            $SG "incus exec ${NODE} -- cli" 2>&1)" || {
            printf '%s\n' "$out" >&2
            return 1
        }
    else
        out="$(printf 'configure\nrollback 0\ndelete firewall family inet filter sfmix-pbr term wire-10136-allow\ncommit check\ncommit\nexit\nquit\n' |
            $SG "incus exec ${NODE} -- cli" 2>&1)" || {
            printf '%s\n' "$out" >&2
            return 1
        }
    fi
    if ! cli_commit_succeeded "$out"; then
        printf '%s\n' "$out" >&2
        return 1
    fi
}
# #11416: the populated-RI fixture. One transaction owns the GRE member —
# device-level tunnel source/destination plus a unit-0 address, the same
# statement shape as the fixture's own gr-0/0/0 — its RI list membership,
# and its placement in the test-owned wire-vrf zone together with that
# zone's lan->wire-vrf permit and interface-SNAT rule-set (mirroring the
# existing lan->sfmix pair); a second owns only the exact /32 static
# route, so the route-removed discrimination phase deletes exactly that
# leaf. The member must NOT join the existing wan zone: wan also carries
# MAIN-context reth0.50/.80, so the #11061 fabric-zone validator rejects a
# zone spanning MAIN and the RI (the 2026-10-16 live VOID).
POPULATED_ZONE="${POPULATED_ZONE:-wire-vrf}"
cli_commit_populated() {
    local action="$1" out
    if [[ "$action" == add ]]; then
        out="$(printf 'configure\nrollback 0\nset interfaces %s tunnel source %s\nset interfaces %s tunnel destination %s\nset interfaces %s unit 0 family inet address %s/32\nset routing-instances %s interface %s\nset security zones security-zone %s interfaces %s\nset security policies from-zone lan to-zone %s policy wire-vrf-allow match source-address any\nset security policies from-zone lan to-zone %s policy wire-vrf-allow match destination-address any\nset security policies from-zone lan to-zone %s policy wire-vrf-allow match application any\nset security policies from-zone lan to-zone %s policy wire-vrf-allow then permit\nset security nat source rule-set lan-to-wire-vrf from zone lan\nset security nat source rule-set lan-to-wire-vrf to zone %s\nset security nat source rule-set lan-to-wire-vrf rule snat match source-address 0.0.0.0/0\nset security nat source rule-set lan-to-wire-vrf rule snat then source-nat interface\ncommit check\ncommit\nexit\nquit\n' \
            "$POPULATED_GRE_DEV" "$WAN_SRC" "$POPULATED_GRE_DEV" "$DEST_IP" \
            "$POPULATED_GRE_DEV" "$POPULATED_GRE_ADDR" "$RI_NAME" "$POPULATED_GRE_UNIT" \
            "$POPULATED_ZONE" "$POPULATED_GRE_UNIT" \
            "$POPULATED_ZONE" "$POPULATED_ZONE" "$POPULATED_ZONE" "$POPULATED_ZONE" \
            "$POPULATED_ZONE" |
            $SG "incus exec ${NODE} -- cli" 2>&1)" || {
            printf '%s\n' "$out" >&2
            return 1
        }
    else
        out="$(printf 'configure\nrollback 0\ndelete security nat source rule-set lan-to-wire-vrf\ndelete security policies from-zone lan to-zone %s\ndelete security zones security-zone %s\ndelete routing-instances %s interface %s\ndelete interfaces %s\ncommit check\ncommit\nexit\nquit\n' \
            "$POPULATED_ZONE" "$POPULATED_ZONE" "$RI_NAME" "$POPULATED_GRE_UNIT" "$POPULATED_GRE_DEV" |
            $SG "incus exec ${NODE} -- cli" 2>&1)" || {
            printf '%s\n' "$out" >&2
            return 1
        }
    fi
    if ! cli_commit_succeeded "$out"; then
        printf '%s\n' "$out" >&2
        return 1
    fi
}
cli_commit_ri_route() {
    local action="$1" out
    if [[ "$action" == add ]]; then
        out="$(printf 'configure\nrollback 0\nset routing-instances %s routing-options static route %s/32 next-hop %s\ncommit check\ncommit\nexit\nquit\n' \
            "$RI_NAME" "$DEST_IP" "$POPULATED_GRE_UNIT" |
            $SG "incus exec ${NODE} -- cli" 2>&1)" || {
            printf '%s\n' "$out" >&2
            return 1
        }
    else
        out="$(printf 'configure\nrollback 0\ndelete routing-instances %s routing-options static route %s/32\ncommit check\ncommit\nexit\nquit\n' \
            "$RI_NAME" "$DEST_IP" |
            $SG "incus exec ${NODE} -- cli" 2>&1)" || {
            printf '%s\n' "$out" >&2
            return 1
        }
    fi
    if ! cli_commit_succeeded "$out"; then
        printf '%s\n' "$out" >&2
        return 1
    fi
}
wait_ri_route() {
    # Poll the kernel VRF-table mirror for the populated /32 (present) or its
    # removal (absent). The userspace FIB applies with the same commit; this
    # mirrors the PBR-rule poll below and refuses to score a phase whose
    # config never landed.
    local want="$1" i out
    for ((i=0; i<60; i++)); do
        out="$(remote "ip -4 route show table ${VRF_TABLE}" 2>/dev/null || true)"
        if [[ "$want" == present && "$out" == *"${DEST_IP}"* ]]; then
            return 0
        fi
        if [[ "$want" == absent && "$out" != *"${DEST_IP}"* ]]; then
            return 0
        fi
        sleep 1
    done
    return 1
}
clear_steered_sessions() {
    # Destination/port-scoped session clear on both cluster nodes, archived
    # per phase. The dataplane reuses an established 5-tuple without re-running
    # RI scope, so every steered phase starts from a cleared destination/port
    # scope; the fresh source ports below make the new tuples themselves new.
    local phase="$1" i=0 clear_out session_out clear_node
    for clear_node in "$NODE0" "$NODE1"; do
        clear_out="$(printf 'clear security flow session destination-prefix %s destination-port %s\nexit\nquit\n' \
            "$DEST_IP" "$PORT" |
            $SG "incus exec ${clear_node} -- cli" 2>&1 || true)"
        grep -qiE 'error|failed|unknown command' <<<"$clear_out" && return 1
        session_out="$(printf 'show security flow session destination-prefix %s destination-port %s limit 10000\nexit\nquit\n' \
            "$DEST_IP" "$PORT" |
            $SG "incus exec ${clear_node} -- cli" 2>&1 || true)"
        printf '%s\n' "$session_out" >"$ARCHIVE_DIR/session-${phase}-${i}.txt"
        grep -qE '^[[:space:]]*Total sessions:[[:space:]]*0[[:space:]]*$' <<<"$session_out" ||
            return 1
        grep -qE "In:.*${LAN_ADDR}/[0-9]+.*${DEST_IP}/${PORT}" <<<"$session_out" && return 1
        i=$((i + 1))
    done
    return 0
}
managed_vrf_table() {
    remote "ip -d link show ${VRF_NAME}" 2>/dev/null |
        sed -n 's/.*vrf table \([0-9][0-9]*\).*/\1/p' | sed -n '1p'
}
wait_managed_vrf() {
    local i
    for ((i=0; i<60; i++)); do
        VRF_TABLE="$(managed_vrf_table)"
        RULE_2000="$(remote 'ip -4 rule show pref 2000' 2>/dev/null || true)"
        if [[ -n "$VRF_TABLE" && "$RULE_2000" == *unreachable* ]]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

ARCHIVE_DIR="${XPF_WIRE_CONFIG_ARCHIVE_DIR:-${TMPDIR:-/var/worktrees/.cache/tmpdir}/xpf-wire-routing-separation-$(date +%s)}"
mkdir -p "$ARCHIVE_DIR" || true
BASE0_RAW="$ARCHIVE_DIR/fw0-pre.set"
BASE1_RAW="$ARCHIVE_DIR/fw1-pre.set"
POST0_RAW="$ARCHIVE_DIR/fw0-post.set"
POST1_RAW="$ARCHIVE_DIR/fw1-post.set"
BASE0_NORM="$ARCHIVE_DIR/fw0-pre.normalized.set"
BASE1_NORM="$ARCHIVE_DIR/fw1-pre.normalized.set"
POST0_NORM="$ARCHIVE_DIR/fw0-post.normalized.set"
POST1_NORM="$ARCHIVE_DIR/fw1-post.normalized.set"
RULE_SNAPSHOT=""
RULE_2000=""
TABLE_SNAPSHOT=""
LAN_MASTER_SNAPSHOT=""
WIRE_GATE_RESTORE_VOID='WIRE_GATE wire_routing_separation VOID reason=harness-void probe_offered=0 probe_leaked=0 control_offered=0 control_observed=0 cksum_bad=0 precommit_control_offered=0 precommit_control_observed=0 populated_offered=0 populated_observed=0 populated_control_offered=0 populated_control_observed=0 removed_offered=0 removed_observed=0 removed_control_offered=0 removed_control_observed=0'
void_now() {
    WIRE_GATE_FINAL_OUT="WIRE_GATE wire_routing_separation VOID reason=$1 probe_offered=0 probe_leaked=0 control_offered=0 control_observed=0 cksum_bad=0 precommit_control_offered=0 precommit_control_observed=0 populated_offered=0 populated_observed=0 populated_control_offered=0 populated_control_observed=0 removed_offered=0 removed_observed=0 removed_control_offered=0 removed_control_observed=0"
    WIRE_GATE_FINAL_RC=2
    exit 2
}

cleanup() {
    local saved_rc=$?
    trap '' EXIT INT TERM
    if [[ -n "$CAP_PID" ]]; then
        kill "$CAP_PID" >/dev/null 2>&1 || true
        wait "$CAP_PID" >/dev/null 2>&1 || true
        CAP_PID=""
    fi
    if ((ALLOW_OWNED)); then
        cli_commit_probe_allow delete || RESTORE_OK=0
        ALLOW_OWNED=0
    fi
    if ((FILTER_OWNED)); then
        cli_commit_probe_filter delete || RESTORE_OK=0
        FILTER_OWNED=0
    fi
    if ((POP_ROUTE_OWNED)); then
        cli_commit_ri_route delete || RESTORE_OK=0
        POP_ROUTE_OWNED=0
    fi
    if ((POP_GRE_OWNED)); then
        cli_commit_populated delete || RESTORE_OK=0
        POP_GRE_OWNED=0
    fi
    if ((REMOTE_PROBE_OWNED)); then
        $SG "incus exec ${LAN_REF} -- rm -f ${REMOTE_PROBE}" >/dev/null 2>&1 || RESTORE_OK=0
        REMOTE_PROBE_OWNED=0
    fi
    if ((RI_OWNED)); then
        cli_commit_ri delete || RESTORE_OK=0
        RI_OWNED=0
    fi
    if ((KERNEL_BASELINE_CAPTURED)); then
        local restore_i
        for ((restore_i=0; restore_i<60; restore_i++)); do
            if [[ -z "$(remote "ip link show ${VRF_NAME}" 2>/dev/null || true)" &&
                "$(remote "ip -o link show ${LAN_DEV}" 2>/dev/null | sed -n 's/.* master \([^ ]*\).*/\1/p')" == "$LAN_MASTER_SNAPSHOT" &&
                "$(remote 'ip -4 rule show' 2>/dev/null || true)" == "$RULE_SNAPSHOT" ]]; then
                break
            fi
            sleep 1
        done
        [[ -z "$(remote "ip link show ${VRF_NAME}" 2>/dev/null || true)" ]] || RESTORE_OK=0
        [[ "$(remote "ip -o link show ${LAN_DEV}" 2>/dev/null | sed -n 's/.* master \([^ ]*\).*/\1/p')" == "$LAN_MASTER_SNAPSHOT" ]] || RESTORE_OK=0
        [[ -z "${VRF_TABLE:-}" || "$(remote "ip -4 route show table ${VRF_TABLE}" 2>/dev/null || true)" == "$TABLE_SNAPSHOT" ]] || RESTORE_OK=0
        [[ "$(remote 'ip -4 rule show' 2>/dev/null || true)" == "$RULE_SNAPSHOT" ]] || RESTORE_OK=0
    fi

    if ((BASELINE_CAPTURED)); then
        if ! snapshot_node "$NODE0" "$POST0_RAW"; then
            RESTORE_OK=0
        else
            normalize_config "$POST0_RAW" >"$POST0_NORM"
            cmp -s "$BASE0_NORM" "$POST0_NORM" || RESTORE_OK=0
        fi
        if ! snapshot_node "$NODE1" "$POST1_RAW"; then
            RESTORE_OK=0
        else
            normalize_config "$POST1_RAW" >"$POST1_NORM"
            cmp -s "$BASE1_NORM" "$POST1_NORM" || RESTORE_OK=0
        fi
        printf 'config_archive=%s pre_fw0_sha=%s post_fw0_sha=%s\n' \
            "$ARCHIVE_DIR" "$(sha256sum "$BASE0_NORM" 2>/dev/null | awk '{print $1}')" \
            "$(sha256sum "$POST0_NORM" 2>/dev/null | awk '{print $1}')"
    fi
    trap - INT TERM
    return "$saved_rc"
}
WIRE_GATE_CLEANUP_FN=cleanup
WIRE_GATE_RESTORE_OK_REF=RESTORE_OK
trap wire_gate_finalize EXIT
trap 'trap "" INT TERM; void_now harness-void' INT TERM

# ── Phase 0: complete snapshots and foreign-state refusal ────────────
snapshot_node "$NODE0" "$BASE0_RAW" || void_now env-void
snapshot_node "$NODE1" "$BASE1_RAW" || void_now env-void
normalize_config "$BASE0_RAW" >"$BASE0_NORM"
normalize_config "$BASE1_RAW" >"$BASE1_NORM"
[[ -s "$BASE0_NORM" && -s "$BASE1_NORM" ]] || void_now env-void
BASELINE_CAPTURED=1
if grep -qE 'wire-10136|xpf10136|10\.201\.36' "$BASE0_NORM" ||
    grep -qE 'wire-10136|xpf10136|10\.201\.36' "$BASE1_NORM"; then
    void_now env-void
fi
if grep -qE "^set routing-instances ${RI_NAME}[[:space:]]" "$BASE0_NORM" ||
    grep -qE "^set routing-instances ${RI_NAME}[[:space:]]" "$BASE1_NORM"; then
    void_now env-void
fi
# #11416: the populated-RI fixture's GRE member, unit address, dedicated
# zone, policy pair, and SNAT rule-set must be absent on both nodes before
# anything is written.
if grep -qE "${POPULATED_GRE_DEV}|${POPULATED_GRE_ADDR%.*}|security-zone ${POPULATED_ZONE}[[:space:]]|to-zone ${POPULATED_ZONE}[[:space:]]|rule-set lan-to-wire-vrf[[:space:]]" "$BASE0_NORM" ||
    grep -qE "${POPULATED_GRE_DEV}|${POPULATED_GRE_ADDR%.*}|security-zone ${POPULATED_ZONE}[[:space:]]|to-zone ${POPULATED_ZONE}[[:space:]]|rule-set lan-to-wire-vrf[[:space:]]" "$BASE1_NORM"; then
    void_now env-void
fi
[[ "$POPULATED_ZONE" =~ ^[A-Za-z][A-Za-z0-9_-]{0,31}$ && "$POPULATED_ZONE" != wan && "$POPULATED_ZONE" != lan ]] ||
    void_now harness-void
# The ingress filter must already be attached to the product-owned LAN unit.
# This is the ownership proof that replaces the old temporary unowned veth.
grep -q 'set interfaces reth1 unit 0 family inet filter input sfmix-pbr' "$BASE0_NORM" ||
    void_now env-void
grep -q '^set firewall family inet filter sfmix-pbr term default ' "$BASE0_NORM" ||
    void_now env-void
[[ "$PORT" =~ ^[0-9]+$ && "$PORT" -ge 1 && "$PORT" -le 65535 &&
    "$PROBE_BURST" =~ ^[0-9]+$ && "$CONTROL_BURST" =~ ^[0-9]+$ ]] ||
    void_now harness-void
PORT=$((10#$PORT))
((10#$CONTROL_BURST >= 10#$PROBE_BURST + NEAR_MISS_TAIL_SIZE)) ||
    void_now harness-void
NEAR_MISS_TAIL_START_SEQ=$((10#$PROBE_BURST))
NEAR_MISS_TAIL_END_SEQ=$((10#$PROBE_BURST + NEAR_MISS_TAIL_SIZE - 1))
if ((PORT == 65535)); then
    NEAR_MISS_PORT=65534
else
    NEAR_MISS_PORT=$((PORT + 1))
fi
# #11416: fresh source ports per steered phase. The FBF term matches only the
# destination port, so a fresh source port is still steered while no
# established 5-tuple from an earlier phase can be reused.
fresh_sport() {
    local s
    while :; do
        s=$((20000 + RANDOM % 18000))
        [[ "$s" != "$PORT" && "$s" != "$NEAR_MISS_PORT" &&
            "$s" != "${POP_SPORT:-}" && "$s" != "${REM_SPORT:-}" ]] && break
    done
    printf '%s\n' "$s"
}
POP_SPORT="$(fresh_sport)"
REM_SPORT="$(fresh_sport)"
if remote "ip link show ${VRF_NAME}" >/dev/null 2>&1; then void_now env-void; fi
RULE_SNAPSHOT="$(remote 'ip -4 rule show' 2>/dev/null || true)"
RULE_2000="$(remote 'ip -4 rule show pref 2000' 2>/dev/null || true)"
LAN_MASTER_SNAPSHOT="$(remote "ip -o link show ${LAN_DEV}" 2>/dev/null |
    sed -n 's/.* master \([^ ]*\).*/\1/p')"
KERNEL_BASELINE_CAPTURED=1
remote "ip -d link show ${LAN_DEV} | grep -q 'prog/xdp'" || void_now env-void
[[ -n "$RULE_2000" ]] || void_now env-void
remote "command -v ip >/dev/null" >/dev/null 2>&1 || void_now no-prober
$SG "incus exec ${LAN_REF} -- sh -c 'command -v python3 >/dev/null'" >/dev/null 2>&1 ||
    void_now no-prober
$SG "incus exec ${TARGET} -- sh -c 'command -v tcpdump >/dev/null && command -v python3 >/dev/null'" ||
    void_now no-prober
if $SG "incus exec ${LAN_REF} -- test -e ${REMOTE_PROBE}" >/dev/null 2>&1; then
    void_now env-void
fi

RI_OWNED=1
cli_commit_ri add || void_now harness-void
wait_managed_vrf || void_now harness-void
[[ "$VRF_TABLE" =~ ^[0-9]+$ ]] || void_now harness-void
TABLE_SNAPSHOT="$(remote "ip -4 route show table ${VRF_TABLE}" 2>/dev/null || true)"
[[ -z "$TABLE_SNAPSHOT" ]] || void_now env-void

REMOTE_PROBE_OWNED=1
$SG "incus file push --mode 0755 ${SCRIPT_DIR}/wire_routing_probe.py ${LAN_REF}${REMOTE_PROBE}" ||
    void_now harness-void

# ── Phase 1: exact control, then post-commit near-miss and empty-RI probe ─
CAPLOG="$(mktemp "${TMPDIR:-/var/worktrees/.cache/tmpdir}/xpf-wire-routing-cap.XXXXXX")" || void_now harness-void
$SG "incus exec ${TARGET} -- timeout ${STEP_TIMEOUT} tcpdump -i eth0 -nn -vv -A -s 0 'udp and dst host ${DEST_IP} and (dst port ${PORT} or dst port ${NEAR_MISS_PORT})'" >"$CAPLOG" 2>&1 &
CAP_PID=$!
sleep 2
kill -0 "$CAP_PID" >/dev/null 2>&1 || void_now no-prober
MAIN_ROUTE_ARGS="ip -4 route get ${DEST_IP} from ${LAN_ADDR} iif ${LAN_DEV} ipproto udp sport ${PORT} dport ${PORT}"
MAIN_LOOKUP="$(remote "${MAIN_ROUTE_ARGS} 2>&1 || true")"
[[ "$MAIN_LOOKUP" == *"${EGRESS_DEV}"* ]] || void_now env-void
NEAR_MISS_ROUTE_ARGS="ip -4 route get ${DEST_IP} from ${LAN_ADDR} iif ${LAN_DEV} ipproto udp sport ${PORT} dport ${NEAR_MISS_PORT}"
NEAR_MISS_LOOKUP="$(remote "${NEAR_MISS_ROUTE_ARGS} 2>&1 || true")"
[[ "$NEAR_MISS_LOOKUP" == *"${EGRESS_DEV}"* ]] || void_now env-void
SENT_CONTROL="$($SG "incus exec ${LAN_REF} -- ${REMOTE_PROBE} --src ${LAN_ADDR} --source-port ${PORT} --dst ${DEST_IP} --port ${PORT} --count ${CONTROL_BURST} --tag C --rate ${RATE}" 2>&1 || true)"
sleep 1

# Evict the control's cached forwarding decision on both cluster nodes. The
# dataplane intentionally reuses an established 5-tuple without re-running RI
# scope, so this remains destination/port-scoped and proves exact absence.
clear_steered_sessions precommit || void_now harness-void

FILTER_OWNED=1
cli_commit_probe_filter add || void_now harness-void
PBR_RULES=""
PBR_MATCH=""
for ((pbr_i=0; pbr_i<60; pbr_i++)); do
    PBR_RULES="$(remote 'ip -4 rule show' 2>/dev/null | grep -E 'lookup [0-9]+$' || true)"
    PBR_MATCH="$(grep -E "iif ${LAN_DEV}.*lookup ${VRF_TABLE}([[:space:]]|$)" <<<"$PBR_RULES" || true)"
    [[ -n "$PBR_MATCH" ]] && break
    sleep 1
done
[[ -n "$PBR_MATCH" ]] || void_now harness-void
[[ -z "$(remote "ip -4 route show table ${VRF_TABLE}" 2>/dev/null || true)" ]] ||
    void_now env-void
printf '%s\n' "$PBR_MATCH" >"$ARCHIVE_DIR/pbr-rules.set"

if [[ -n "${WIRE_BROKEN_FIXTURE:-}" ]]; then
    # Fault injection is an exact, temporary explicit ALLOW at the real
    # userspace enforcement point. It precedes (but does not alter) the fixed
    # RI-steering term, so the broken packet follows the proven main route.
    ALLOW_OWNED=1
    cli_commit_probe_allow add || void_now harness-void
    ALLOW_CHECK_RAW="$ARCHIVE_DIR/allow-check.set"
    snapshot_node "$NODE0" "$ALLOW_CHECK_RAW" || void_now harness-void
    grep -q "set firewall family inet filter sfmix-pbr term wire-10136-allow then accept" \
        "$ALLOW_CHECK_RAW" || void_now harness-void
    MAIN_LOOKUP="$(remote "${MAIN_ROUTE_ARGS} 2>&1 || true")"
    [[ "$MAIN_LOOKUP" == *"${EGRESS_DEV}"* ]] || void_now env-void
fi
# The near miss differs from the steered probe only by destination port, so the
# committed exact-match FBF term leaves it on the verified main-table route.
SENT_INTERLEAVED="$($SG "incus exec ${LAN_REF} -- ${REMOTE_PROBE} \
    --src ${LAN_ADDR} --source-port ${PORT} --dst ${DEST_IP} \
    --port ${PORT} --count ${PROBE_BURST} --tag P --interleave \
    --interleave-control-port ${NEAR_MISS_PORT} \
    --interleave-control-count ${CONTROL_BURST} \
    --interleave-control-tag N --rate ${RATE}" 2>&1 || true)"
sleep 3
if ! kill -0 "$CAP_PID" >/dev/null 2>&1; then
    void_now no-prober
fi
kill "$CAP_PID" >/dev/null 2>&1 || true
wait "$CAP_PID" >/dev/null 2>&1 || true
CAP_PID=""
if ((ALLOW_OWNED)); then
    cli_commit_probe_allow delete || void_now harness-void
    ALLOW_OWNED=0
fi

# ── Phase 2: populated-RI positive leg, then route-removed discrimination ──
# Same IPv4/UDP shape as the miss phase: the FBF term still owns the exact
# tuple, but the RI now holds a test-owned GRE member and an exact /32 static
# route, so the steered lookup must FORWARD. The capture filter admits the
# steered probe only in GRE form: a main-table fallback cannot score as a
# positive pass. Removing only the route must stop delivery in any form.
clear_steered_sessions populated || void_now harness-void
POP_GRE_OWNED=1
cli_commit_populated add || void_now harness-void
POP_ROUTE_OWNED=1
cli_commit_ri_route add || void_now harness-void
wait_ri_route present || void_now harness-void
printf '%s\n' "$(remote "ip -4 route show table ${VRF_TABLE}" 2>/dev/null || true)" \
    >"$ARCHIVE_DIR/populated-route.set"
CAPLOG2="$(mktemp "${TMPDIR:-/var/worktrees/.cache/tmpdir}/xpf-wire-routing-cap2.XXXXXX")" || void_now harness-void
$SG "incus exec ${TARGET} -- timeout ${STEP_TIMEOUT} tcpdump -i eth0 -nn -vv -A -s 0 'dst host ${DEST_IP} and (proto 47 or (udp and dst port ${NEAR_MISS_PORT}))'" >"$CAPLOG2" 2>&1 &
CAP_PID=$!
sleep 2
kill -0 "$CAP_PID" >/dev/null 2>&1 || void_now no-prober
SENT_POPULATED="$($SG "incus exec ${LAN_REF} -- ${REMOTE_PROBE} \
    --src ${LAN_ADDR} --source-port ${POP_SPORT} --dst ${DEST_IP} \
    --port ${PORT} --count ${PROBE_BURST} --tag R --interleave \
    --interleave-control-port ${NEAR_MISS_PORT} \
    --interleave-control-count ${CONTROL_BURST} \
    --interleave-control-tag B --rate ${RATE}" 2>&1 || true)"
sleep 3
if ! kill -0 "$CAP_PID" >/dev/null 2>&1; then
    void_now no-prober
fi
kill "$CAP_PID" >/dev/null 2>&1 || true
wait "$CAP_PID" >/dev/null 2>&1 || true
CAP_PID=""

# Route-removed discrimination: delete ONLY the /32 so the GRE member stays
# owned and committed while the steered lookup must miss again.
cli_commit_ri_route delete || void_now harness-void
POP_ROUTE_OWNED=0
wait_ri_route absent || void_now harness-void
clear_steered_sessions removed || void_now harness-void
CAPLOG3="$(mktemp "${TMPDIR:-/var/worktrees/.cache/tmpdir}/xpf-wire-routing-cap3.XXXXXX")" || void_now harness-void
$SG "incus exec ${TARGET} -- timeout ${STEP_TIMEOUT} tcpdump -i eth0 -nn -vv -A -s 0 'dst host ${DEST_IP} and (proto 47 or (udp and (dst port ${PORT} or dst port ${NEAR_MISS_PORT})))'" >"$CAPLOG3" 2>&1 &
CAP_PID=$!
sleep 2
kill -0 "$CAP_PID" >/dev/null 2>&1 || void_now no-prober
SENT_REMOVED="$($SG "incus exec ${LAN_REF} -- ${REMOTE_PROBE} \
    --src ${LAN_ADDR} --source-port ${REM_SPORT} --dst ${DEST_IP} \
    --port ${PORT} --count ${PROBE_BURST} --tag D --interleave \
    --interleave-control-port ${NEAR_MISS_PORT} \
    --interleave-control-count ${CONTROL_BURST} \
    --interleave-control-tag E --rate ${RATE}" 2>&1 || true)"
sleep 3
if ! kill -0 "$CAP_PID" >/dev/null 2>&1; then
    void_now no-prober
fi
kill "$CAP_PID" >/dev/null 2>&1 || true
wait "$CAP_PID" >/dev/null 2>&1 || true
CAP_PID=""
extract_sent() {
    local tag="$1" text="$2" value
    value=$(sed -n "s/.*SENT tag=${tag} count=\([0-9][0-9]*\).*/\1/p" <<<"$text" | tail -1)
    [[ "$value" =~ ^[0-9]+$ ]] && printf '%s\n' "$value" || printf '0\n'
}
POFFERED="$(extract_sent P "$SENT_INTERLEAVED")"
COFFERED="$(extract_sent C "$SENT_CONTROL")"
NEAR_MISS_OFFERED="$(extract_sent N "$SENT_INTERLEAVED")"
POPULATED_OFFERED="$(extract_sent R "$SENT_POPULATED")"
POPULATED_CONTROL_OFFERED="$(extract_sent B "$SENT_POPULATED")"
REMOVED_OFFERED="$(extract_sent D "$SENT_REMOVED")"
REMOVED_CONTROL_OFFERED="$(extract_sent E "$SENT_REMOVED")"
PLEAKED="$(grep -cE 'P10136:[0-9]+:' "$CAPLOG" 2>/dev/null || true)"
COBSERVED="$(grep -cE 'C10136:[0-9]+:' "$CAPLOG" 2>/dev/null || true)"
NEAR_MISS_OBSERVED="$(grep -cE 'N10136:[0-9]+:' "$CAPLOG" 2>/dev/null || true)"
NEAR_MISS_TAIL_OBSERVED="$(grep -oE 'N10136:[0-9]+:' "$CAPLOG" 2>/dev/null |
    sed 's/^N10136:\([0-9][0-9]*\):$/\1/' |
    awk -v first="$NEAR_MISS_TAIL_START_SEQ" -v last="$NEAR_MISS_TAIL_END_SEQ" \
        '$1 >= first && $1 <= last { count++ } END { print count + 0 }')"
POPULATED_OBSERVED="$(grep -cE 'R10136:[0-9]+:' "$CAPLOG2" 2>/dev/null || true)"
POPULATED_CONTROL_OBSERVED="$(grep -cE 'B10136:[0-9]+:' "$CAPLOG2" 2>/dev/null || true)"
REMOVED_OBSERVED="$(grep -cE 'D10136:[0-9]+:' "$CAPLOG3" 2>/dev/null || true)"
REMOVED_CONTROL_OBSERVED="$(grep -cE 'E10136:[0-9]+:' "$CAPLOG3" 2>/dev/null || true)"
CKSUM="$(grep -ciE 'bad (udp|ip) (cksum|checksum)' "$CAPLOG" 2>/dev/null || true)"
CKSUM2="$(grep -ciE 'bad (udp|ip) (cksum|checksum)' "$CAPLOG2" 2>/dev/null || true)"
CKSUM3="$(grep -ciE 'bad (udp|ip) (cksum|checksum)' "$CAPLOG3" 2>/dev/null || true)"
rm -f "$CAPLOG" "$CAPLOG2" "$CAPLOG3"
for v in PLEAKED COBSERVED NEAR_MISS_OFFERED NEAR_MISS_OBSERVED NEAR_MISS_TAIL_OBSERVED \
    POPULATED_OFFERED POPULATED_OBSERVED POPULATED_CONTROL_OFFERED POPULATED_CONTROL_OBSERVED \
    REMOVED_OFFERED REMOVED_OBSERVED REMOVED_CONTROL_OFFERED REMOVED_CONTROL_OBSERVED \
    CKSUM CKSUM2 CKSUM3; do
    [[ "${!v}" =~ ^[0-9]+$ ]] || declare "$v=0"
done
CKALL=$((10#$CKSUM + 10#$CKSUM2 + 10#$CKSUM3))
printf 'offered: probe=%s precommit_control=%s near_miss=%s populated=%s populated_control=%s removed=%s removed_control=%s observed: probe=%s precommit_control=%s near_miss=%s near_miss_tail=%s populated=%s populated_control=%s removed=%s removed_control=%s cksum_bad=%s archive=%s\n' \
    "$POFFERED" "$COFFERED" "$NEAR_MISS_OFFERED" "$POPULATED_OFFERED" "$POPULATED_CONTROL_OFFERED" \
    "$REMOVED_OFFERED" "$REMOVED_CONTROL_OFFERED" \
    "$PLEAKED" "$COBSERVED" "$NEAR_MISS_OBSERVED" "$NEAR_MISS_TAIL_OBSERVED" \
    "$POPULATED_OBSERVED" "$POPULATED_CONTROL_OBSERVED" \
    "$REMOVED_OBSERVED" "$REMOVED_CONTROL_OBSERVED" "$CKALL" "$ARCHIVE_DIR"
WIRE_GATE_FINAL_OUT="$(wire_routing_separation_window_verdict \
    "$NEAR_MISS_TAIL_OBSERVED" "$POFFERED" "$PLEAKED" "$COFFERED" "$COBSERVED" "$CKALL" \
    "$NEAR_MISS_OFFERED" "$NEAR_MISS_OBSERVED" \
    "$POPULATED_OFFERED" "$POPULATED_OBSERVED" "$POPULATED_CONTROL_OFFERED" "$POPULATED_CONTROL_OBSERVED" \
    "$REMOVED_OFFERED" "$REMOVED_OBSERVED" "$REMOVED_CONTROL_OFFERED" "$REMOVED_CONTROL_OBSERVED")"
WIRE_GATE_FINAL_RC=$?
exit "$WIRE_GATE_FINAL_RC"
