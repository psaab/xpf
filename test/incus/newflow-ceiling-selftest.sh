#!/usr/bin/env bash
# Hermetic self-test for test/incus/newflow-ceiling-lib.sh (#6962).
#
# No cluster, no incus, no network. Runs in `make test-newflow-ceiling-lib`.
#
# THE ROW THAT MATTERS is WRONG_NODE_PEER_IS_PRIMARY: node0's own status, in
# which node0 is SECONDARY and node1 is PRIMARY. The shipped `grep -qi
# "primary"` matches node1's row in that text and selects node0 — and prints a
# node name, so nothing downstream in the harness looks like an error. A
# fixture where both nodes carry the SAME state cannot distinguish the anchored
# form from the unanchored one and would pass either way; UNANCHORED_CONTROL
# below runs the old pattern against the same bytes to keep that difference
# measured rather than asserted.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./newflow-ceiling-lib.sh
. "${SCRIPT_DIR}/newflow-ceiling-lib.sh"

pass=0
fail=0

check() {
	local name="$1" want="$2" status="$3" got verdict
	got="$(newflow_cluster_primary_verdict "$status")"
	verdict="${got%% *}"
	if [[ "$verdict" == "$want" ]]; then
		pass=$((pass + 1))
		printf 'ok   %-32s -> %s\n' "$name" "$verdict"
	else
		fail=$((fail + 1))
		printf 'FAIL %-32s -> want %s got %s (%s)\n' "$name" "$want" "$verdict" "$got"
	fi
	# TOTALITY: exactly one verdict line, and it is one of the three words.
	if [[ "$(grep -c . <<<"$got")" -ne 1 ]]; then
		fail=$((fail + 1))
		printf 'FAIL %-32s -> verdict was not exactly one line: %q\n' "$name" "$got"
	fi
	case "$verdict" in
	PRIMARY | NOT-PRIMARY | UNKNOWN) ;;
	*)
		fail=$((fail + 1))
		printf 'FAIL %-32s -> verdict word %q is not one of PRIMARY/NOT-PRIMARY/UNKNOWN\n' "$name" "$verdict"
		;;
	esac
}

# --- ground truth: node1 is primary, node0 is secondary -------------------
# Both nodes' own renderings of the SAME cluster state. FormatStatus grammar
# (pkg/cluster/status.go): the local "Node name:" header, then per-RG blocks
# with the local row, its two readiness lines, then the peer row.
FW0_STATUS='Monitor Failure codes:
    CS  Cold Sync monitoring        FL  Fabric Connection monitoring
    IF  Interface monitoring        IP  IP monitoring
    CF  Config Sync monitoring

Cluster ID: 1
Node name: node0

Software version: 0.0.0-dev
HA protocol version: 3

Redundancy group: 0 , Failover count: 1
node0   100      secondary      yes      no       None
  Takeover ready: yes
  Transfer ready: yes
node1   200      primary        yes      no       None

Redundancy group: 1 , Failover count: 1
node0   100      secondary      yes      no       None
  Takeover ready: yes
  Transfer ready: yes
node1   200      primary        yes      no       None

Redundancy group: 2 , Failover count: 1
node0   100      secondary      yes      no       None
  Takeover ready: yes
  Transfer ready: yes
node1   200      primary        yes      no       None
'
FW1_STATUS='Monitor Failure codes:
    CS  Cold Sync monitoring        FL  Fabric Connection monitoring

Cluster ID: 1
Node name: node1

Redundancy group: 0 , Failover count: 1
node1   200      primary        yes      no       None
  Takeover ready: yes
  Transfer ready: yes
node0   100      secondary      yes      no       None

Redundancy group: 1 , Failover count: 1
node1   200      primary        yes      no       None
  Takeover ready: yes
  Transfer ready: yes
node0   100      secondary      yes      no       None

Redundancy group: 2 , Failover count: 1
node1   200      primary        yes      no       None
  Takeover ready: yes
  Transfer ready: yes
node0   100      secondary      yes      no       None
'

check WRONG_NODE_PEER_IS_PRIMARY NOT-PRIMARY "$FW0_STATUS"
check RIGHT_NODE_OWNS_EVERY_RG   PRIMARY     "$FW1_STATUS"

# --- the negative control: the pattern that shipped, on the same bytes -----
# This is what makes the two rows above mean something. If node0's own status
# did NOT match the old pattern, the anchor would be unbound and both cells
# would pass with or without it.
if grep -qi "primary" <<<"$FW0_STATUS"; then
	pass=$((pass + 1))
	printf 'ok   %-32s -> the shipped `grep -qi "primary"` DOES match the SECONDARY node'"'"'s own status (it is matching the peer row), which is the defect\n' UNANCHORED_CONTROL
else
	fail=$((fail + 1))
	printf 'FAIL %-32s -> the fixture no longer reproduces the defect: `grep -qi "primary"` did not match node0'"'"'s status, so these cells would pass unanchored too and prove nothing\n' UNANCHORED_CONTROL
fi
# ... and the anchored verdict must DISAGREE with it on that same input.
if [[ "$(newflow_cluster_primary_verdict "$FW0_STATUS")" == PRIMARY* ]]; then
	fail=$((fail + 1))
	printf 'FAIL %-32s -> anchored verdict agreed with the unanchored grep on node0'"'"'s status; the anchor is not load-bearing\n' ANCHOR_DISAGREES
else
	pass=$((pass + 1))
	printf 'ok   %-32s -> anchored verdict rejects the node the unanchored grep selected\n' ANCHOR_DISAGREES
fi

# --- partial ownership: the wrong-node error one level in -----------------
# node0 owns RG0 but not the RGs carrying the measured path (reth0 -> rg1,
# reth1 -> rg2). Selecting it would measure a node that installs part of the
# flows, and the run would still produce numbers.
SPLIT_STATUS='Cluster ID: 1
Node name: node0

Redundancy group: 0 , Failover count: 0
node0   200      primary        yes      no       None
node1   100      secondary      yes      no       None

Redundancy group: 1 , Failover count: 1
node0   100      secondary      yes      no       None
node1   200      primary        yes      no       None

Redundancy group: 2 , Failover count: 1
node0   100      secondary      yes      no       None
node1   200      primary        yes      no       None
'
check SPLIT_OWNS_ONLY_RG0 NOT-PRIMARY "$SPLIT_STATUS"

SPLIT_STATUS_FW1='Cluster ID: 1
Node name: node1

Redundancy group: 0 , Failover count: 0
node1   100      secondary      yes      no       None
node0   200      primary        yes      no       None

Redundancy group: 1 , Failover count: 1
node1   200      primary        yes      no       None
node0   100      secondary      yes      no       None

Redundancy group: 2 , Failover count: 1
node1   200      primary        yes      no       None
node0   100      secondary      yes      no       None
'
check SPLIT_OWNS_ONLY_DATA_RGS NOT-PRIMARY "$SPLIT_STATUS_FW1"

# --- single-RG cluster: the ordinary healthy shape ------------------------
check SINGLE_RG_LOCAL_PRIMARY PRIMARY 'Node name: node0

Redundancy group: 0 , Failover count: 0
node0   200      primary        yes      no       None
node1   100      secondary      yes      no       None
'
check SINGLE_RG_LOCAL_SECONDARY NOT-PRIMARY 'Node name: node0

Redundancy group: 0 , Failover count: 0
node0   100      secondary      yes      no       None
node1   200      primary        yes      no       None
'

# --- the instrument could not be read: UNKNOWN, never a selection ---------
check PROBE_BLIND_EMPTY   UNKNOWN ""
check PROBE_BLIND_WS      UNKNOWN "   "
check PROBE_BLIND_NEWLINE UNKNOWN "
"
# A node that answered, but not with a cluster status (cli error text, a
# standalone node, a truncated read).
check NO_NODE_NAME_HEADER UNKNOWN 'Redundancy group: 0 , Failover count: 0
node0   200      primary        yes      no       None
'
check NO_RG_BLOCKS UNKNOWN 'Cluster ID: 1
Node name: node0

Software version: 0.0.0-dev
'
check ERROR_TEXT_MENTIONING_PRIMARY UNKNOWN 'error: could not read primary state from the cluster manager'
# RG blocks present, but the node has no row of its own in any of them.
check NO_LOCAL_ROW_IN_ANY_RG UNKNOWN 'Node name: node0

Redundancy group: 0 , Failover count: 0
node1   200      primary        yes      no       None
'
# A local row in RG0 but none in RG1: ownership of the whole path is
# unconfirmable, so it is not selectable — but the status WAS readable, so this
# is a NOT-PRIMARY answer rather than a blind instrument.
check LOCAL_ROW_MISSING_IN_ONE_RG NOT-PRIMARY 'Node name: node0

Redundancy group: 0 , Failover count: 0
node0   200      primary        yes      no       None
node1   100      secondary      yes      no       None

Redundancy group: 1 , Failover count: 0
node1   200      primary        yes      no       None
'

# --- lines that are NOT node rows must not answer for the node ------------
# #6495 renders "Held secondary: <reason>" above every RG header, and the
# readiness lines carry free text. Neither may be read as a row. The reason
# strings here deliberately contain the words the verdict keys on.
check HELD_AND_READINESS_TEXT_IGNORED PRIMARY 'Node name: node0
Held secondary: kernel upgrade candidate armed; primary promotion held

Redundancy group: 0 , Failover count: 0
node0   200      primary        yes      no       None
  Takeover ready: no (takeover hold: 4s of 10s remaining)
  Transfer ready: no (peer secondary not ready to become primary)
node1   100      secondary      yes      no       None
'
# A node row before any RG header has no group to belong to and is ignored —
# the same reset the Go parser does, so a malformed header cannot make the
# rows after it answer for the previous group.
check ROW_BEFORE_ANY_RG_HEADER UNKNOWN 'Node name: node0
node0   200      primary        yes      no       None
'
# ... and the same guard with REAL groups present, so the verdict cannot be
# reached by the no-groups path instead. Without the in-scope test the stray row
# is attributed to a group and this reads as an ownership claim.
check STRAY_ROW_ALONGSIDE_REAL_GROUPS UNKNOWN 'Node name: node0
node0   200      primary        yes      no       None

Redundancy group: 0 , Failover count: 0
node0   100      secondary      yes      no       None
node1   200      primary        yes      no       None
'
# A group whose id cannot be read is a group whose ownership is unknown, so the
# verdict is fail-closed even though every group that DID parse reads primary.
check MALFORMED_RG_HEADER_FAILS_CLOSED UNKNOWN 'Node name: node0

Redundancy group: 0 , Failover count: 0
node0   200      primary        yes      no       None

Redundancy group: <corrupt> , Failover count: 0
node0   200      primary        yes      no       None
'

# A malformed header with NO rows after it: the stray-row path cannot see this
# one (there is no stray row), so it isolates the unparseable-header check.
# Without it, a group that exists but could not be read would be silently
# excluded from "every redundancy group" and the node would read as owning all
# of them.
check MALFORMED_RG_HEADER_NO_ROWS_AFTER UNKNOWN 'Node name: node0

Redundancy group: 0 , Failover count: 0
node0   200      primary        yes      no       None
node1   100      secondary      yes      no       None

Redundancy group: <corrupt> , Failover count: 0
'

# --- node-token anchoring must be exact ----------------------------------
# node1 must not answer for node10, or the anchor is a prefix match.
# ORDER IS LOAD-BEARING: the local row comes FIRST and the prefix-colliding row
# LAST. With node10 first, a prefix match would be overwritten by node1's own
# later row and the cell would pass against a broken anchor — which is exactly
# what the first version of this fixture did, and the mutation matrix caught.
check NODE10_IS_NOT_NODE1 NOT-PRIMARY 'Node name: node1

Redundancy group: 0 , Failover count: 0
node1   100      secondary      yes      no       None
node10  200      primary        yes      no       None
'
check NODE10_LOCAL_PRIMARY PRIMARY 'Node name: node10

Redundancy group: 0 , Failover count: 0
node10  200      primary        yes      no       None
node1   100      secondary      yes      no       None
'

# --- the selection policy: both nodes evaluated, then decided -------------
checks() {
	local name="$1" want="$2" n0="$3" v0="$4" n1="$5" v1="$6" got
	got="$(newflow_select_active_node "$n0" "$v0" "$n1" "$v1")"
	if [[ "$got" == "$want"* ]]; then
		pass=$((pass + 1))
		printf 'ok   %-32s -> %s\n' "$name" "${got%% *}"
	else
		fail=$((fail + 1))
		printf 'FAIL %-32s -> want %s got %s\n' "$name" "$want" "$got"
	fi
	if [[ "$(grep -c . <<<"$got")" -ne 1 ]]; then
		fail=$((fail + 1))
		printf 'FAIL %-32s -> selection was not exactly one line: %q\n' "$name" "$got"
	fi
}

# The ground truth from the fixtures above: fw0 secondary, fw1 primary. The
# shipped loop selected fw0; the selector must reach fw1.
V0="$(newflow_cluster_primary_verdict "$FW0_STATUS")"
V1="$(newflow_cluster_primary_verdict "$FW1_STATUS")"
checks SELECT_THE_ACTUAL_PRIMARY "SELECT fw1" fw0 "$V0" fw1 "$V1"
checks SELECT_WHEN_NODE0_PRIMARY "SELECT fw0" \
	fw0 "PRIMARY node0 is primary for every redundancy group (rg0=primary)" \
	fw1 "NOT-PRIMARY node1 is not primary for redundancy group(s) rg0 (rg0=secondary)"
# A split cluster: neither node owns the whole path. The old loop reported
# "no node reports primary" with no evidence; refusing must name both.
checks REFUSE_SPLIT_CLUSTER "REFUSE" \
	fw0 "$(newflow_cluster_primary_verdict "$SPLIT_STATUS")" \
	fw1 "$(newflow_cluster_primary_verdict "$SPLIT_STATUS_FW1")"
# Split-brain: BOTH claim every RG. The old loop silently measured fw0.
checks REFUSE_SPLIT_BRAIN "REFUSE" \
	fw0 "PRIMARY node0 is primary for every redundancy group (rg0=primary)" \
	fw1 "PRIMARY node1 is primary for every redundancy group (rg0=primary)"
# Neither answered at all.
checks REFUSE_BOTH_UNKNOWN "REFUSE" \
	fw0 "$(newflow_cluster_primary_verdict "")" \
	fw1 "$(newflow_cluster_primary_verdict "")"
# One node down, the other primary: still selectable — a standby that cannot be
# reached does not stop the owner being measured.
checks SELECT_WITH_PEER_UNREACHABLE "SELECT fw1" \
	fw0 "$(newflow_cluster_primary_verdict "")" fw1 "$V1"
# The REFUSE text must carry both verdicts, or the operator cannot tell a
# split cluster from an unreachable pair without re-running under the lock.
refuse_msg="$(newflow_select_active_node fw0 "$V0" fw1 "$V0")"
if [[ "$refuse_msg" == *"fw0:"* && "$refuse_msg" == *"fw1:"* ]]; then
	pass=$((pass + 1)); printf 'ok   %-32s -> names both nodes\n' REFUSE_NAMES_BOTH_NODES
else
	fail=$((fail + 1)); printf 'FAIL %-32s -> refusal did not name both nodes: %q\n' REFUSE_NAMES_BOTH_NODES "$refuse_msg"
fi

# --- the lib must stay parseable: no apostrophes inside the awk program ---
# The verdict is one awk program delimited by SINGLE QUOTES. An apostrophe
# anywhere inside it — including in a comment — ends the program early and the
# whole lib stops parsing. That happened twice while this was written, both
# times in prose ("group\x27s", "parseNodeToken\x27s"), and both times every cell
# below failed at once, which is loud but tells you nothing about where. This
# names it.
LIB_FILE="${SCRIPT_DIR}/newflow-ceiling-lib.sh"
awk_body="$(awk "/^\tawk '\$/{flag=1;next} /^\t' <<</{flag=0} flag" "$LIB_FILE")"
if [[ -z "${awk_body//[[:space:]]/}" ]]; then
	fail=$((fail + 1))
	printf 'FAIL %-32s -> could not extract the awk program from %s; this cell would pass vacuously\n' AWK_BODY_EXTRACTED "$LIB_FILE"
elif [[ "$awk_body" == *"'"* ]]; then
	fail=$((fail + 1))
	printf 'FAIL %-32s -> an apostrophe inside the single-quoted awk program ends it early and breaks the whole lib\n' NO_APOSTROPHE_IN_AWK
else
	pass=$((pass + 1))
	printf 'ok   %-32s -> awk program is apostrophe-free (%d lines)\n' NO_APOSTROPHE_IN_AWK "$(grep -c . <<<"$awk_body")"
fi

# --- WIRING: the harness must USE the lib, not re-inline the grep ---------
# Every cell above passes against a perfect lib that nothing calls. The defect
# lives in the harness, so bind the harness.
#
# Comments are stripped before matching, because this file and the lib both
# QUOTE the defective pattern in their own prose to explain it — a source scan
# that reads comments would be satisfied by the explanation of the bug.
HARNESS="${SCRIPT_DIR}/newflow-ceiling-harness.sh"
# Materialised ONCE rather than piped per check: under `set -o pipefail`,
# `sed ... | grep -q X` returns 141 when grep short-circuits and sed takes
# SIGPIPE, so a MATCH reads as a failed pipeline. This test hit that on its
# first run and reported the wiring missing while it was present.
HARNESS_CODE="$(sed -e 's/[[:space:]]#.*$//' -e '/^[[:space:]]*#/d' "$HARNESS")"
if [[ -z "${HARNESS_CODE//[[:space:]]/}" ]]; then
	fail=$((fail + 1))
	printf 'FAIL %-32s -> could not read %s; the wiring cells below would pass vacuously\n' HARNESS_READABLE "$HARNESS"
else
	pass=$((pass + 1))
	printf 'ok   %-32s -> read %s\n' HARNESS_READABLE "$HARNESS"
fi
for fn in newflow_cluster_primary_verdict newflow_select_active_node; do
	if grep -q "$fn" <<<"$HARNESS_CODE"; then
		pass=$((pass + 1))
		printf 'ok   %-32s -> harness calls %s\n' "WIRED_${fn}" "$fn"
	else
		fail=$((fail + 1))
		printf 'FAIL %-32s -> the harness does not call %s, so every cell above tests a lib nothing uses (#6962)\n' "WIRED_${fn}" "$fn"
	fi
done
if grep -qE 'grep +-q[a-z]* +"?(primary|secondary)"?' <<<"$HARNESS_CODE"; then
	fail=$((fail + 1))
	printf 'FAIL %-32s -> the harness matches primary/secondary with no node token again; that pattern matches the PEER row and selects the wrong node (#6962)\n' NO_UNANCHORED_GREP
else
	pass=$((pass + 1))
	printf 'ok   %-32s -> no unanchored primary/secondary match left in the harness\n' NO_UNANCHORED_GREP
fi
# --- WIRING: the harness must take the #1875 cluster lock ----------------
# The lib cells above cannot see whether the harness itself enters the
# destructive-cluster cell. Reverting the lock entry, or capturing the
# original args only after --pool/--rule shifted them away, must fail here.
wiring_line() { # <extended-regex> -> first matching line in $HARNESS_CODE
	grep -nE "$1" <<<"$HARNESS_CODE" | head -1 | cut -d: -f1
}
w_line_orig="$(wiring_line '^ORIGINAL_ARGS=\(')"
w_line_lock_src="$(wiring_line '^source .*cluster-cell\.sh')"
w_line_lock_call="$(wiring_line '^xpf_enter_destructive_cluster_cell ')"
w_line_parse="$(wiring_line '^while \[\[ \$# -gt 0 \]\]')"
w_line_first_exec="$(wiring_line 'incus_cmd exec|incus exec')"
wiring_ok=1
wiring_detail=""
if [[ -z "$w_line_orig" || -z "$w_line_parse" ]] || (( w_line_orig >= w_line_parse )); then
	wiring_ok=0
	wiring_detail="ORIGINAL_ARGS must be captured before the argument parser shifts \$@ (orig=${w_line_orig:-missing} parse=${w_line_parse:-missing})"
fi
if [[ "$wiring_ok" -eq 1 && ( -z "$w_line_lock_src" || -z "$w_line_lock_call" || -z "$w_line_first_exec" ) ]]; then
	wiring_ok=0
	wiring_detail="harness must source cluster-cell.sh and call xpf_enter_destructive_cluster_cell before its first incus exec (source=${w_line_lock_src:-missing} call=${w_line_lock_call:-missing} first-exec=${w_line_first_exec:-missing})"
fi
if [[ "$wiring_ok" -eq 1 ]] && ! (( w_line_lock_src < w_line_lock_call && w_line_lock_call < w_line_first_exec )); then
	wiring_ok=0
	wiring_detail="lock order must be source < call < first incus exec (source=$w_line_lock_src call=$w_line_lock_call first-exec=$w_line_first_exec)"
fi
if [[ "$wiring_ok" -eq 1 ]] && ! grep -q -- '--src-bind' <<<"$HARNESS_CODE"; then
	wiring_ok=0
	wiring_detail="harness must accept --src-bind (harness SRC_BIND override)"
fi
if [[ "$wiring_ok" -eq 1 ]] && ! grep -q -- '--target-ip' <<<"$HARNESS_CODE"; then
	wiring_ok=0
	wiring_detail="harness must accept --target-ip (harness TARGET_IP override)"
fi
if [[ "$wiring_ok" -eq 1 ]] && ! grep -qF '"${ORIGINAL_ARGS[@]}"' <<<"$HARNESS_CODE"; then
	wiring_ok=0
	wiring_detail="lock entry must expand the ORIGINAL_ARGS captured before parsing"
fi
w_line_dryrun="$(wiring_line '^if \[\[ "\$DRY_RUN" == "1" \]\]; then')"
w_line_dryexit="$(wiring_line '^    exit 0$')"
if [[ "$wiring_ok" -eq 1 && ( -z "$w_line_dryrun" || -z "$w_line_dryexit" ) ]]; then
	wiring_ok=0
	wiring_detail="dry-run must have an early exit before the lock preamble (dry-run=${w_line_dryrun:-missing} exit=${w_line_dryexit:-missing})"
fi
if [[ "$wiring_ok" -eq 1 ]] && ! (( w_line_dryrun < w_line_dryexit && w_line_dryexit < w_line_lock_src )); then
	wiring_ok=0
	wiring_detail="dry-run exit must precede cluster-cell.sh source (dry-run=$w_line_dryrun exit=$w_line_dryexit source=$w_line_lock_src)"
fi
if [[ "$wiring_ok" -eq 1 ]]; then
	pass=$((pass + 1))
	printf 'ok   %-32s -> harness captures ORIGINAL_ARGS before parsing, enters the cluster lock (source < call < first incus exec) with those args, and accepts --src-bind/--target-ip\n' LOCK_WIRING
else
	fail=$((fail + 1))
	printf 'FAIL %-32s -> %s\n' LOCK_WIRING "$wiring_detail"
fi


printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
